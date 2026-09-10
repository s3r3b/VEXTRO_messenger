pub mod facade;
pub mod ffi;
pub mod storage;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use serde::{Deserialize, Serialize};
use sodiumoxide::crypto::{
    box_::{self, Nonce, PublicKey, SecretKey},
    generichash, secretbox,
    sign::{
        self, PublicKey as SignPublicKey, SecretKey as SignSecretKey, Signature as SignSignature,
    },
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyPair {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OneTimePrekeyPublic {
    pub key_id: u32,
    pub key: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrekeyBundle {
    pub identity_key: String,
    pub signed_prekey: String,
    pub signature: String,
    pub one_time_prekeys: Vec<OneTimePrekeyPublic>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratedPrekeyBundle {
    pub bundle: PrekeyBundle,
    pub identity_keypair: storage::KeyPairBase64,
    pub signed_prekeypair: storage::KeyPairBase64,
    pub one_time_prekeys: Vec<storage::OneTimePrekeyEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct X3dhPrekeyMessage {
    pub identity_key: String,
    pub ephemeral_key: String,
    pub one_time_prekey_id: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RatchetKeyPair {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RatchetHeader {
    pub dh_public_key: Vec<u8>,
    pub previous_chain_length: u32,
    pub message_number: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SkippedMessageKey {
    pub dh_public_key: Vec<u8>,
    pub message_number: u32,
    pub message_key: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionState {
    pub root_key: Vec<u8>,
    pub dhs: RatchetKeyPair,
    pub dhr: Option<Vec<u8>>,
    pub cks: Option<Vec<u8>>,
    pub ckr: Option<Vec<u8>>,
    pub ns: u32,
    pub nr: u32,
    pub pn: u32,
    pub skipped_message_keys: Vec<SkippedMessageKey>,
}

fn init_libsodium() {
    let _ = sodiumoxide::init();
}

pub fn generate_identity_keypair() -> KeyPair {
    init_libsodium();
    let (public_key, private_key) = sign::gen_keypair();

    KeyPair {
        public_key: public_key.as_ref().to_vec(),
        private_key: private_key.as_ref().to_vec(),
    }
}

pub fn generate_signed_prekey() -> KeyPair {
    init_libsodium();
    let (public_key, private_key) = box_::gen_keypair();

    KeyPair {
        public_key: public_key.as_ref().to_vec(),
        private_key: private_key.as_ref().to_vec(),
    }
}

pub fn generate_one_time_prekey() -> KeyPair {
    generate_signed_prekey()
}

pub fn generate_prekey_bundle(opk_count: usize) -> GeneratedPrekeyBundle {
    let identity = generate_identity_keypair();
    let signed_prekey = generate_signed_prekey();
    let signature = sign_message(&signed_prekey.public_key, &identity.private_key);

    let identity_keypair = storage::KeyPairBase64 {
        public_key: BASE64.encode(&identity.public_key),
        private_key: BASE64.encode(&identity.private_key),
    };
    let signed_prekeypair = storage::KeyPairBase64 {
        public_key: BASE64.encode(&signed_prekey.public_key),
        private_key: BASE64.encode(&signed_prekey.private_key),
    };

    let mut public_one_time_prekeys = Vec::with_capacity(opk_count);
    let mut one_time_prekeys = Vec::with_capacity(opk_count);

    for key_id in 1..=opk_count {
        let key_id = u32::try_from(key_id).expect("OPK count exceeds u32 key ID capacity");
        let key_pair = generate_one_time_prekey();
        let public_key = BASE64.encode(&key_pair.public_key);
        let private_key = BASE64.encode(&key_pair.private_key);

        public_one_time_prekeys.push(OneTimePrekeyPublic {
            key_id,
            key: public_key.clone(),
        });
        one_time_prekeys.push(storage::OneTimePrekeyEntry {
            key_id,
            key_pair: storage::KeyPairBase64 {
                public_key,
                private_key,
            },
        });
    }

    GeneratedPrekeyBundle {
        bundle: PrekeyBundle {
            identity_key: identity_keypair.public_key.clone(),
            signed_prekey: signed_prekeypair.public_key.clone(),
            signature: BASE64.encode(&signature),
            one_time_prekeys: public_one_time_prekeys,
        },
        identity_keypair,
        signed_prekeypair,
        one_time_prekeys,
    }
}

fn decode_key(value: &str, name: &str) -> Result<Vec<u8>, String> {
    BASE64
        .decode(value)
        .map_err(|_| format!("invalid Base64 {name}"))
}

fn dh(public_key: &[u8], private_key: &[u8]) -> Result<Vec<u8>, String> {
    let public_key =
        PublicKey::from_slice(public_key).ok_or_else(|| "invalid X25519 public key".to_string())?;
    let private_key = SecretKey::from_slice(private_key)
        .ok_or_else(|| "invalid X25519 private key".to_string())?;

    Ok(box_::precompute(&public_key, &private_key)
        .as_ref()
        .to_vec())
}

fn x3dh_kdf(dh_outputs: &[Vec<u8>]) -> Result<Vec<u8>, String> {
    let mut input = b"VEXTRO-X3DH-v1".to_vec();
    for output in dh_outputs {
        input.extend_from_slice(output);
    }

    sodiumoxide::crypto::generichash::hash(&input, Some(32), None)
        .map(|digest| digest.as_ref().to_vec())
        .map_err(|_| "X3DH KDF failed".to_string())
}

fn keyed_hash(key: &[u8], context: &[u8], output_length: usize) -> Result<Vec<u8>, String> {
    generichash::hash(context, Some(output_length), Some(key))
        .map(|digest| digest.as_ref().to_vec())
        .map_err(|_| "Double Ratchet KDF failed".to_string())
}

pub fn kdf_chain(chain_key: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let next_chain_key = keyed_hash(chain_key, b"VEXTRO-DR-chain-v1", 32)?;
    let message_key = keyed_hash(chain_key, b"VEXTRO-DR-message-v1", 32)?;
    Ok((next_chain_key, message_key))
}

fn kdf_root(root_key: &[u8], dh_output: &[u8]) -> Result<(Vec<u8>, Vec<u8>), String> {
    let mut context = b"VEXTRO-DR-root-v1".to_vec();
    context.extend_from_slice(dh_output);
    let output = keyed_hash(root_key, &context, 64)?;
    Ok((output[..32].to_vec(), output[32..].to_vec()))
}

fn ratchet_dh(public_key: &[u8], private_key: &[u8]) -> Result<Vec<u8>, String> {
    dh(public_key, private_key)
}

impl SessionState {
    pub fn new_initiator(root_key: Vec<u8>, recipient_ratchet_public_key: Vec<u8>) -> Self {
        let dhs = generate_signed_prekey();
        let cks = keyed_hash(&root_key, b"VEXTRO-DR-alice-to-bob-v1", 32)
            .expect("valid root key for initiator chain");

        Self {
            root_key,
            dhs: RatchetKeyPair {
                public_key: dhs.public_key,
                private_key: dhs.private_key,
            },
            dhr: Some(recipient_ratchet_public_key),
            cks: Some(cks),
            ckr: None,
            ns: 0,
            nr: 0,
            pn: 0,
            skipped_message_keys: Vec::new(),
        }
    }

    pub fn new_responder(
        root_key: Vec<u8>,
        own_ratchet_keypair: RatchetKeyPair,
        initiator_ratchet_public_key: Vec<u8>,
    ) -> Self {
        let ckr = keyed_hash(&root_key, b"VEXTRO-DR-alice-to-bob-v1", 32)
            .expect("valid root key for responder chain");

        Self {
            root_key,
            dhs: own_ratchet_keypair,
            dhr: Some(initiator_ratchet_public_key),
            cks: None,
            ckr: Some(ckr),
            ns: 0,
            nr: 0,
            pn: 0,
            skipped_message_keys: Vec::new(),
        }
    }
}

fn perform_send_ratchet(state: &mut SessionState) -> Result<(), String> {
    let remote_key = state
        .dhr
        .as_ref()
        .ok_or_else(|| "cannot send before receiving a ratchet public key".to_string())?;
    let dhs = generate_signed_prekey();
    let dh_output = ratchet_dh(remote_key, &dhs.private_key)?;
    let (root_key, sending_chain_key) = kdf_root(&state.root_key, &dh_output)?;

    state.pn = state.ns;
    state.ns = 0;
    state.root_key = root_key;
    state.dhs = RatchetKeyPair {
        public_key: dhs.public_key,
        private_key: dhs.private_key,
    };
    state.cks = Some(sending_chain_key);
    Ok(())
}

fn skip_message_keys(state: &mut SessionState, until: u32) -> Result<(), String> {
    let chain_key = state
        .ckr
        .as_mut()
        .ok_or_else(|| "receiving chain is not initialized".to_string())?;

    while state.nr < until {
        let (next_chain_key, message_key) = kdf_chain(chain_key)?;
        let remote_key = state
            .dhr
            .as_ref()
            .ok_or_else(|| "missing remote ratchet key".to_string())?;
        state.skipped_message_keys.push(SkippedMessageKey {
            dh_public_key: remote_key.clone(),
            message_number: state.nr,
            message_key,
        });
        *chain_key = next_chain_key;
        state.nr = state
            .nr
            .checked_add(1)
            .ok_or_else(|| "message counter overflow".to_string())?;
    }
    Ok(())
}

fn perform_receive_ratchet(
    state: &mut SessionState,
    remote_public_key: &[u8],
) -> Result<(), String> {
    let dh_output = ratchet_dh(remote_public_key, &state.dhs.private_key)?;
    let (root_key, receiving_chain_key) = kdf_root(&state.root_key, &dh_output)?;

    state.pn = state.ns;
    state.ns = 0;
    state.nr = 0;
    state.root_key = root_key;
    state.dhr = Some(remote_public_key.to_vec());
    state.ckr = Some(receiving_chain_key);
    state.cks = None;
    Ok(())
}

pub fn ratchet_encrypt(
    state: &SessionState,
    plaintext: &[u8],
) -> Result<(SessionState, RatchetHeader, Vec<u8>), String> {
    init_libsodium();
    let mut updated_state = state.clone();

    if updated_state.cks.is_none() {
        perform_send_ratchet(&mut updated_state)?;
    }

    let chain_key = updated_state
        .cks
        .take()
        .ok_or_else(|| "sending chain is not initialized".to_string())?;
    let (next_chain_key, message_key) = kdf_chain(&chain_key)?;
    let message_number = updated_state.ns;
    updated_state.ns = updated_state
        .ns
        .checked_add(1)
        .ok_or_else(|| "message counter overflow".to_string())?;
    updated_state.cks = Some(next_chain_key);

    let key = secretbox::Key::from_slice(&message_key)
        .ok_or_else(|| "invalid message key".to_string())?;
    let nonce = secretbox::gen_nonce();
    let encrypted = secretbox::seal(plaintext, &nonce, &key);
    let mut ciphertext = nonce.as_ref().to_vec();
    ciphertext.extend_from_slice(&encrypted);

    let header = RatchetHeader {
        dh_public_key: updated_state.dhs.public_key.clone(),
        previous_chain_length: updated_state.pn,
        message_number,
    };

    Ok((updated_state, header, ciphertext))
}

pub fn ratchet_decrypt(
    state: &SessionState,
    header: &RatchetHeader,
    ciphertext: &[u8],
) -> Result<(SessionState, Vec<u8>), String> {
    init_libsodium();
    let mut updated_state = state.clone();
    let skipped_key_index = updated_state.skipped_message_keys.iter().position(|key| {
        key.dh_public_key == header.dh_public_key && key.message_number == header.message_number
    });
    let message_key = if let Some(index) = skipped_key_index {
        updated_state.skipped_message_keys.remove(index).message_key
    } else {
        let is_new_ratchet = updated_state.dhr.as_deref() != Some(header.dh_public_key.as_slice());
        if is_new_ratchet {
            if updated_state.ckr.is_some() {
                skip_message_keys(&mut updated_state, header.previous_chain_length)?;
            }
            perform_receive_ratchet(&mut updated_state, &header.dh_public_key)?;
        }

        skip_message_keys(&mut updated_state, header.message_number)?;
        let chain_key = updated_state
            .ckr
            .take()
            .ok_or_else(|| "receiving chain is not initialized".to_string())?;
        let (next_chain_key, message_key) = kdf_chain(&chain_key)?;
        updated_state.ckr = Some(next_chain_key);
        updated_state.nr = updated_state
            .nr
            .checked_add(1)
            .ok_or_else(|| "message counter overflow".to_string())?;
        message_key
    };

    if ciphertext.len() < secretbox::NONCEBYTES {
        return Err("ciphertext is too short".to_string());
    }
    let nonce = secretbox::Nonce::from_slice(&ciphertext[..secretbox::NONCEBYTES])
        .ok_or_else(|| "invalid nonce".to_string())?;
    let key = secretbox::Key::from_slice(&message_key)
        .ok_or_else(|| "invalid message key".to_string())?;
    secretbox::open(&ciphertext[secretbox::NONCEBYTES..], &nonce, &key)
        .map(|plaintext| (updated_state, plaintext))
        .map_err(|_| "message authentication failed".to_string())
}

pub fn x3dh_initiate(
    initiator_identity_keypair: &KeyPair,
    recipient_bundle: &PrekeyBundle,
    one_time_prekey_index: Option<usize>,
) -> Result<(X3dhPrekeyMessage, Vec<u8>), String> {
    init_libsodium();

    let initiator_identity_secret =
        sign::SecretKey::from_slice(&initiator_identity_keypair.private_key)
            .ok_or_else(|| "invalid initiator Ed25519 private key".to_string())?;
    let recipient_identity_public = SignPublicKey::from_slice(&decode_key(
        &recipient_bundle.identity_key,
        "recipient identity key",
    )?)
    .ok_or_else(|| "invalid recipient Ed25519 public key".to_string())?;
    let recipient_signed_prekey = decode_key(&recipient_bundle.signed_prekey, "signed prekey")?;
    let signature = decode_key(&recipient_bundle.signature, "signed prekey signature")?;

    if !verify_signature(
        &recipient_signed_prekey,
        &signature,
        recipient_identity_public.as_ref(),
    ) {
        return Err("recipient signed prekey signature is invalid".to_string());
    }

    let initiator_identity_curve = sign::to_curve25519_sk(&initiator_identity_secret)
        .map_err(|_| "cannot convert initiator identity key".to_string())?;
    let recipient_identity_curve = sign::to_curve25519_pk(&recipient_identity_public)
        .map_err(|_| "cannot convert recipient identity key".to_string())?;
    let ephemeral = generate_signed_prekey();

    let selected_opk = one_time_prekey_index.map(|index| {
        recipient_bundle
            .one_time_prekeys
            .get(index)
            .ok_or_else(|| "one-time prekey index is out of range".to_string())
    });
    let selected_opk = match selected_opk {
        Some(result) => Some(result?),
        None => None,
    };

    let mut dh_outputs = vec![
        dh(&recipient_signed_prekey, initiator_identity_curve.as_ref())?,
        dh(recipient_identity_curve.as_ref(), &ephemeral.private_key)?,
        dh(&recipient_signed_prekey, &ephemeral.private_key)?,
    ];

    if let Some(opk) = selected_opk {
        dh_outputs.push(dh(
            &decode_key(&opk.key, "one-time prekey")?,
            &ephemeral.private_key,
        )?);
    }

    Ok((
        X3dhPrekeyMessage {
            identity_key: BASE64.encode(&initiator_identity_keypair.public_key),
            ephemeral_key: BASE64.encode(&ephemeral.public_key),
            one_time_prekey_id: selected_opk.map(|opk| opk.key_id),
        },
        x3dh_kdf(&dh_outputs)?,
    ))
}

pub fn x3dh_respond(
    recipient_identity_private_key: &[u8],
    recipient_signed_prekey_private_key: &[u8],
    message: &X3dhPrekeyMessage,
    recipient_one_time_prekey_private_key: Option<&[u8]>,
) -> Result<Vec<u8>, String> {
    init_libsodium();

    let recipient_identity_secret = sign::SecretKey::from_slice(recipient_identity_private_key)
        .ok_or_else(|| "invalid recipient Ed25519 private key".to_string())?;
    let initiator_identity_public = SignPublicKey::from_slice(&decode_key(
        &message.identity_key,
        "initiator identity key",
    )?)
    .ok_or_else(|| "invalid initiator Ed25519 public key".to_string())?;
    let initiator_ephemeral_public = decode_key(&message.ephemeral_key, "initiator ephemeral key")?;
    let recipient_identity_curve = sign::to_curve25519_sk(&recipient_identity_secret)
        .map_err(|_| "cannot convert recipient identity key".to_string())?;
    let initiator_identity_curve = sign::to_curve25519_pk(&initiator_identity_public)
        .map_err(|_| "cannot convert initiator identity key".to_string())?;

    let mut dh_outputs = vec![
        dh(
            initiator_identity_curve.as_ref(),
            recipient_signed_prekey_private_key,
        )?,
        dh(
            &initiator_ephemeral_public,
            recipient_identity_curve.as_ref(),
        )?,
        dh(
            &initiator_ephemeral_public,
            recipient_signed_prekey_private_key,
        )?,
    ];

    match (
        message.one_time_prekey_id,
        recipient_one_time_prekey_private_key,
    ) {
        (Some(_), Some(private_key)) => {
            dh_outputs.push(dh(&initiator_ephemeral_public, private_key)?);
        }
        (Some(_), None) => return Err("one-time prekey private key is missing".to_string()),
        (None, Some(_)) => return Err("unexpected one-time prekey private key".to_string()),
        (None, None) => {}
    }

    x3dh_kdf(&dh_outputs)
}

pub fn sign_message(message: &[u8], private_key: &[u8]) -> Vec<u8> {
    init_libsodium();
    let secret_key = SignSecretKey::from_slice(private_key).expect("invalid Ed25519 private key");
    sign::sign_detached(message, &secret_key).as_ref().to_vec()
}

pub fn verify_signature(message: &[u8], signature: &[u8], public_key: &[u8]) -> bool {
    init_libsodium();

    let public_key = match SignPublicKey::from_slice(public_key) {
        Some(key) => key,
        None => return false,
    };

    let signature = match SignSignature::from_bytes(signature) {
        Ok(sig) => sig,
        Err(_) => return false,
    };

    sign::verify_detached(&signature, message, &public_key)
}

pub fn encrypt_message(
    plaintext: &[u8],
    sender_private_key: &[u8],
    recipient_public_key: &[u8],
) -> Vec<u8> {
    init_libsodium();

    let sender_private_key =
        SecretKey::from_slice(sender_private_key).expect("invalid X25519 sender private key");
    let recipient_public_key =
        PublicKey::from_slice(recipient_public_key).expect("invalid X25519 recipient public key");

    let nonce = box_::gen_nonce();
    let ciphertext = box_::seal(
        plaintext,
        &nonce,
        &recipient_public_key,
        &sender_private_key,
    );

    let mut output = Vec::with_capacity(box_::NONCEBYTES + ciphertext.len());
    output.extend_from_slice(nonce.as_ref());
    output.extend_from_slice(&ciphertext);
    output
}

pub fn decrypt_message(
    ciphertext: &[u8],
    sender_public_key: &[u8],
    recipient_private_key: &[u8],
) -> Result<Vec<u8>, String> {
    init_libsodium();

    if ciphertext.len() < box_::NONCEBYTES {
        return Err("ciphertext is too short".to_string());
    }

    let sender_public_key = PublicKey::from_slice(sender_public_key)
        .ok_or_else(|| "invalid sender public key".to_string())?;
    let recipient_private_key = SecretKey::from_slice(recipient_private_key)
        .ok_or_else(|| "invalid recipient private key".to_string())?;
    let nonce = Nonce::from_slice(&ciphertext[..box_::NONCEBYTES])
        .ok_or_else(|| "invalid nonce".to_string())?;

    let encrypted = &ciphertext[box_::NONCEBYTES..];
    box_::open(
        encrypted,
        &nonce,
        &sender_public_key,
        &recipient_private_key,
    )
    .map_err(|_| "decryption failed".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_keypair_generates_nonempty_keys() {
        let kp = generate_identity_keypair();
        assert!(!kp.public_key.is_empty());
        assert!(!kp.private_key.is_empty());
    }

    #[test]
    fn prekey_bundle_contains_signed_prekey_and_requested_opks() {
        let generated = generate_prekey_bundle(50);
        let bundle = &generated.bundle;

        assert_eq!(bundle.one_time_prekeys.len(), 50);
        assert_eq!(generated.one_time_prekeys.len(), 50);
        assert_eq!(bundle.one_time_prekeys[0].key_id, 1);
        assert_eq!(bundle.one_time_prekeys[49].key_id, 50);
        assert!(bundle
            .one_time_prekeys
            .windows(2)
            .all(|keys| keys[0].key != keys[1].key));

        let signed_prekey = BASE64.decode(&bundle.signed_prekey).unwrap();
        let identity_public_key = BASE64.decode(&bundle.identity_key).unwrap();
        let signature = BASE64.decode(&bundle.signature).unwrap();

        assert!(verify_signature(
            &signed_prekey,
            &signature,
            &identity_public_key
        ));
        assert_eq!(generated.identity_keypair.public_key, bundle.identity_key);
        assert_eq!(generated.signed_prekeypair.public_key, bundle.signed_prekey);
        assert!(generated
            .one_time_prekeys
            .iter()
            .all(|entry| entry.key_pair.private_key != entry.key_pair.public_key));
    }

    #[test]
    fn x3dh_initiator_and_responder_derive_same_secret_with_opk() {
        let alice_identity = generate_identity_keypair();
        let bob = generate_prekey_bundle(5);
        let bob_opk = &bob.one_time_prekeys[2];

        let (message, alice_secret) = x3dh_initiate(&alice_identity, &bob.bundle, Some(2)).unwrap();
        let bob_secret = x3dh_respond(
            &BASE64.decode(&bob.identity_keypair.private_key).unwrap(),
            &BASE64.decode(&bob.signed_prekeypair.private_key).unwrap(),
            &message,
            Some(&BASE64.decode(&bob_opk.key_pair.private_key).unwrap()),
        )
        .unwrap();

        assert_eq!(message.one_time_prekey_id, Some(3));
        assert_eq!(alice_secret.len(), 32);
        assert_eq!(alice_secret, bob_secret);
    }

    #[test]
    fn x3dh_works_without_one_time_prekey() {
        let alice_identity = generate_identity_keypair();
        let bob = generate_prekey_bundle(0);

        let (message, alice_secret) = x3dh_initiate(&alice_identity, &bob.bundle, None).unwrap();
        let bob_secret = x3dh_respond(
            &BASE64.decode(&bob.identity_keypair.private_key).unwrap(),
            &BASE64.decode(&bob.signed_prekeypair.private_key).unwrap(),
            &message,
            None,
        )
        .unwrap();

        assert_eq!(message.one_time_prekey_id, None);
        assert_eq!(alice_secret, bob_secret);
    }

    #[test]
    fn double_ratchet_handles_dh_ratchet_and_out_of_order_messages() {
        let root_key = vec![7u8; 32];
        let bob = generate_prekey_bundle(0);
        let bob_dhs = RatchetKeyPair {
            public_key: BASE64.decode(&bob.signed_prekeypair.public_key).unwrap(),
            private_key: BASE64.decode(&bob.signed_prekeypair.private_key).unwrap(),
        };
        let mut alice = SessionState::new_initiator(root_key.clone(), bob_dhs.public_key.clone());
        let mut bob = SessionState::new_responder(root_key, bob_dhs, alice.dhs.public_key.clone());

        let (next_alice, header_one, ciphertext_one) = ratchet_encrypt(&alice, b"alice-1").unwrap();
        alice = next_alice;
        let (next_alice, header_two, ciphertext_two) = ratchet_encrypt(&alice, b"alice-2").unwrap();
        alice = next_alice;
        let (next_alice, header_three, ciphertext_three) =
            ratchet_encrypt(&alice, b"alice-3").unwrap();
        alice = next_alice;

        let (next_bob, plaintext_one) =
            ratchet_decrypt(&bob, &header_one, &ciphertext_one).unwrap();
        bob = next_bob;
        let (next_bob, plaintext_three) =
            ratchet_decrypt(&bob, &header_three, &ciphertext_three).unwrap();
        bob = next_bob;
        assert_eq!(plaintext_one, b"alice-1");
        assert_eq!(plaintext_three, b"alice-3");
        assert_eq!(bob.skipped_message_keys.len(), 1);

        let (next_bob, plaintext_two) =
            ratchet_decrypt(&bob, &header_two, &ciphertext_two).unwrap();
        bob = next_bob;
        assert_eq!(plaintext_two, b"alice-2");
        assert!(bob.skipped_message_keys.is_empty());

        let (next_bob, bob_header_one, bob_ciphertext_one) =
            ratchet_encrypt(&bob, b"bob-1").unwrap();
        bob = next_bob;
        let (_next_bob, bob_header_two, bob_ciphertext_two) =
            ratchet_encrypt(&bob, b"bob-2").unwrap();

        let (next_alice, bob_plaintext_one) =
            ratchet_decrypt(&alice, &bob_header_one, &bob_ciphertext_one).unwrap();
        alice = next_alice;
        let (_, bob_plaintext_two) =
            ratchet_decrypt(&alice, &bob_header_two, &bob_ciphertext_two).unwrap();
        assert_eq!(bob_plaintext_one, b"bob-1");
        assert_eq!(bob_plaintext_two, b"bob-2");
        assert_ne!(header_one.dh_public_key, bob_header_one.dh_public_key);
    }

    #[test]
    fn signed_prekey_round_trip_works() {
        let sender = generate_signed_prekey();
        let recipient = generate_signed_prekey();

        let plaintext = b"hello from alice";
        let ciphertext = encrypt_message(plaintext, &sender.private_key, &recipient.public_key);
        let result = decrypt_message(&ciphertext, &sender.public_key, &recipient.private_key);

        assert_eq!(result.unwrap(), plaintext.to_vec());
        assert_ne!(ciphertext, plaintext.to_vec());
        assert_ne!(sender.public_key, recipient.public_key);
    }

    #[test]
    fn signature_verifies() {
        let identity = generate_identity_keypair();
        let message = b"auth challenge";
        let signature = sign_message(message, &identity.private_key);
        assert!(verify_signature(message, &signature, &identity.public_key));
    }

    #[test]
    fn wrong_private_key_cannot_decrypt() {
        let sender = generate_signed_prekey();
        let recipient = generate_signed_prekey();
        let attacker = generate_signed_prekey();

        let ciphertext = encrypt_message(b"secret", &sender.private_key, &recipient.public_key);
        let result = decrypt_message(&ciphertext, &sender.public_key, &attacker.private_key);

        assert!(result.is_err());
    }

    #[test]
    fn invalid_signature_is_rejected() {
        let identity = generate_identity_keypair();
        let message = b"auth challenge";
        let bad_signature = b"not a valid signature";

        assert!(!verify_signature(
            message,
            bad_signature,
            &identity.public_key
        ));
    }

    #[test]
    fn one_time_prekey_is_consumed_once() {
        use crate::storage::{InMemorySecureStorage, OneTimePrekeyEntry, SecureStorage};

        let mut storage = InMemorySecureStorage::new();
        let opk = generate_one_time_prekey();

        storage.save_one_time_prekeys(vec![OneTimePrekeyEntry {
            key_id: 1,
            key_pair: crate::storage::KeyPairBase64 {
                public_key: BASE64.encode(&opk.public_key),
                private_key: BASE64.encode(&opk.private_key),
            },
        }]);

        assert!(storage.get_one_time_prekey(1).is_some());
        storage.remove_one_time_prekey(1);
        assert!(storage.get_one_time_prekey(1).is_none());
    }

    #[test]
    fn storage_state_restores_after_restart() {
        use crate::storage::{InMemorySecureStorage, KeyPairBase64, SecureStorage};

        let mut storage = InMemorySecureStorage::new();
        let ik = generate_identity_keypair();
        let spk = generate_signed_prekey();

        storage.save_identity_keypair(KeyPairBase64 {
            public_key: BASE64.encode(&ik.public_key),
            private_key: BASE64.encode(&ik.private_key),
        });

        storage.save_signed_prekey(KeyPairBase64 {
            public_key: BASE64.encode(&spk.public_key),
            private_key: BASE64.encode(&spk.private_key),
        });

        let restored_ik = storage.get_identity_keypair().unwrap();
        let restored_spk = storage.get_signed_prekey().unwrap();

        assert_eq!(
            BASE64.decode(restored_ik.public_key).unwrap().len(),
            ik.public_key.len()
        );
        assert_eq!(
            BASE64.decode(restored_spk.private_key).unwrap().len(),
            spk.private_key.len()
        );
    }
}
