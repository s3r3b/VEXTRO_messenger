use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};

use crate::storage::{KeyPairBase64, OneTimePrekeyEntry};
use crate::{
    generate_prekey_bundle, ratchet_decrypt, ratchet_encrypt, x3dh_initiate, x3dh_respond, KeyPair,
    PrekeyBundle, RatchetHeader, RatchetKeyPair, SessionState, X3dhPrekeyMessage,
};

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PrekeySecrets {
    identity_keypair: KeyPairBase64,
    signed_prekeypair: KeyPairBase64,
    one_time_prekeys: Vec<OneTimePrekeyEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct InitialMessage {
    x3dh: X3dhPrekeyMessage,
    ratchet_public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagePayload {
    pub header: RatchetHeader,
    pub ciphertext: String,
}

fn to_json<T: Serialize>(value: &T) -> Result<String, String> {
    serde_json::to_string(value).map_err(|error| format!("JSON serialization failed: {error}"))
}

fn from_json<T: for<'de> Deserialize<'de>>(value: &str, name: &str) -> Result<T, String> {
    serde_json::from_str(value).map_err(|error| format!("invalid {name} JSON: {error}"))
}

fn identity_keypair_from_secret(secret: &str) -> Result<KeyPair, String> {
    let private_key = BASE64
        .decode(secret)
        .map_err(|_| "invalid identity secret Base64".to_string())?;
    if private_key.len() != 64 {
        return Err("invalid Ed25519 identity secret length".to_string());
    }

    Ok(KeyPair {
        public_key: private_key[32..].to_vec(),
        private_key,
    })
}

pub fn create_prekey_bundle(opk_count: u32) -> Result<(String, String), String> {
    let generated = generate_prekey_bundle(opk_count as usize);
    let secrets = PrekeySecrets {
        identity_keypair: generated.identity_keypair,
        signed_prekeypair: generated.signed_prekeypair,
        one_time_prekeys: generated.one_time_prekeys,
    };

    Ok((to_json(&generated.bundle)?, to_json(&secrets)?))
}

pub fn init_outbound_session(
    bob_bundle_json: &str,
    my_identity_secret: &str,
) -> Result<(String, String), String> {
    let bob_bundle: PrekeyBundle = from_json(bob_bundle_json, "prekey bundle")?;
    let my_identity = identity_keypair_from_secret(my_identity_secret)?;
    let opk_index = (!bob_bundle.one_time_prekeys.is_empty()).then_some(0);
    let (x3dh_message, root_key) = x3dh_initiate(&my_identity, &bob_bundle, opk_index)?;
    let bob_signed_prekey = BASE64
        .decode(&bob_bundle.signed_prekey)
        .map_err(|_| "invalid Bob signed prekey Base64".to_string())?;
    let state = SessionState::new_initiator(root_key, bob_signed_prekey);

    Ok((
        to_json(&state)?,
        to_json(&InitialMessage {
            x3dh: x3dh_message,
            ratchet_public_key: BASE64.encode(&state.dhs.public_key),
        })?,
    ))
}

pub fn init_inbound_session(
    initial_msg_json: &str,
    my_keys_json: &str,
) -> Result<(String, String), String> {
    let initial: InitialMessage = from_json(initial_msg_json, "initial message")?;
    let secrets: PrekeySecrets = from_json(my_keys_json, "prekey secrets")?;
    let signed_prekey_private = BASE64
        .decode(&secrets.signed_prekeypair.private_key)
        .map_err(|_| "invalid signed prekey private Base64".to_string())?;
    let identity_private = BASE64
        .decode(&secrets.identity_keypair.private_key)
        .map_err(|_| "invalid identity private Base64".to_string())?;
    let opk_private = initial
        .x3dh
        .one_time_prekey_id
        .and_then(|key_id| {
            secrets
                .one_time_prekeys
                .iter()
                .find(|entry| entry.key_id == key_id)
        })
        .map(|entry| {
            BASE64
                .decode(&entry.key_pair.private_key)
                .map_err(|_| "invalid one-time prekey private Base64".to_string())
        })
        .transpose()?;
    let root_key = x3dh_respond(
        &identity_private,
        &signed_prekey_private,
        &initial.x3dh,
        opk_private.as_deref(),
    )?;
    let signed_prekey_public = BASE64
        .decode(&secrets.signed_prekeypair.public_key)
        .map_err(|_| "invalid signed prekey public Base64".to_string())?;
    let ratchet_public_key = BASE64
        .decode(&initial.ratchet_public_key)
        .map_err(|_| "invalid initial ratchet public Base64".to_string())?;
    let state = SessionState::new_responder(
        root_key,
        RatchetKeyPair {
            public_key: signed_prekey_public,
            private_key: signed_prekey_private,
        },
        ratchet_public_key,
    );

    Ok((to_json(&state)?, String::new()))
}

pub fn encrypt_message(
    session_state_json: &str,
    plaintext: &str,
) -> Result<(String, String), String> {
    let state: SessionState = from_json(session_state_json, "session state")?;
    let (updated_state, header, ciphertext) = ratchet_encrypt(&state, plaintext.as_bytes())?;
    let payload = MessagePayload {
        header,
        ciphertext: BASE64.encode(ciphertext),
    };

    Ok((to_json(&updated_state)?, to_json(&payload)?))
}

pub fn decrypt_message(
    session_state_json: &str,
    message_payload_json: &str,
) -> Result<(String, String), String> {
    let state: SessionState = from_json(session_state_json, "session state")?;
    let payload: MessagePayload = from_json(message_payload_json, "message payload")?;
    let ciphertext = BASE64
        .decode(payload.ciphertext)
        .map_err(|_| "invalid message ciphertext Base64".to_string())?;
    let (updated_state, plaintext) = ratchet_decrypt(&state, &payload.header, &ciphertext)?;
    let plaintext = String::from_utf8(plaintext)
        .map_err(|_| "decrypted message is not valid UTF-8".to_string())?;

    Ok((to_json(&updated_state)?, plaintext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn facade_creates_session_and_round_trips_message() {
        let (bob_bundle_json, bob_keys_json) = create_prekey_bundle(1).unwrap();
        let alice_identity = crate::generate_identity_keypair();
        let alice_identity_secret = BASE64.encode(alice_identity.private_key);

        let (alice_state, initial_message) =
            init_outbound_session(&bob_bundle_json, &alice_identity_secret).unwrap();
        let (bob_state, initial_text) =
            init_inbound_session(&initial_message, &bob_keys_json).unwrap();
        assert!(initial_text.is_empty());

        let (alice_state, payload) = encrypt_message(&alice_state, "hello through facade").unwrap();
        let (bob_state, plaintext) = decrypt_message(&bob_state, &payload).unwrap();

        assert_eq!(plaintext, "hello through facade");
        assert_ne!(alice_state, bob_state);
    }
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    use wasm_bindgen::prelude::*;

    use super::*;

    #[wasm_bindgen]
    pub fn wasm_create_prekey_bundle(opk_count: u32) -> Result<String, JsValue> {
        let result = create_prekey_bundle(opk_count).map_err(|error| JsValue::from_str(&error))?;
        serde_json::to_string(&result).map_err(|error| JsValue::from_str(&error.to_string()))
    }

    #[wasm_bindgen]
    pub fn wasm_init_outbound_session(
        bundle_json: &str,
        identity_secret: &str,
    ) -> Result<String, JsValue> {
        let result = init_outbound_session(bundle_json, identity_secret)
            .map_err(|error| JsValue::from_str(&error))?;
        serde_json::to_string(&result).map_err(|error| JsValue::from_str(&error.to_string()))
    }

    #[wasm_bindgen]
    pub fn wasm_init_inbound_session(
        message_json: &str,
        keys_json: &str,
    ) -> Result<String, JsValue> {
        let result = init_inbound_session(message_json, keys_json)
            .map_err(|error| JsValue::from_str(&error))?;
        serde_json::to_string(&result).map_err(|error| JsValue::from_str(&error.to_string()))
    }

    #[wasm_bindgen]
    pub fn wasm_encrypt_message(state_json: &str, plaintext: &str) -> Result<String, JsValue> {
        let result =
            encrypt_message(state_json, plaintext).map_err(|error| JsValue::from_str(&error))?;
        serde_json::to_string(&result).map_err(|error| JsValue::from_str(&error.to_string()))
    }

    #[wasm_bindgen]
    pub fn wasm_decrypt_message(state_json: &str, payload_json: &str) -> Result<String, JsValue> {
        let result =
            decrypt_message(state_json, payload_json).map_err(|error| JsValue::from_str(&error))?;
        serde_json::to_string(&result).map_err(|error| JsValue::from_str(&error.to_string()))
    }
}
