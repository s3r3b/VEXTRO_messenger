pub mod storage;

use sodiumoxide::crypto::{
    box_::{self, Nonce, PublicKey, SecretKey},
    sign::{
        self, PublicKey as SignPublicKey, SecretKey as SignSecretKey, Signature as SignSignature,
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPair {
    pub public_key: Vec<u8>,
    pub private_key: Vec<u8>,
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
                public_key: base64::encode(&opk.public_key),
                private_key: base64::encode(&opk.private_key),
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
            public_key: base64::encode(&ik.public_key),
            private_key: base64::encode(&ik.private_key),
        });

        storage.save_signed_prekey(KeyPairBase64 {
            public_key: base64::encode(&spk.public_key),
            private_key: base64::encode(&spk.private_key),
        });

        let restored_ik = storage.get_identity_keypair().unwrap();
        let restored_spk = storage.get_signed_prekey().unwrap();

        assert_eq!(
            base64::decode(restored_ik.public_key).unwrap().len(),
            ik.public_key.len()
        );
        assert_eq!(
            base64::decode(restored_spk.private_key).unwrap().len(),
            spk.private_key.len()
        );
    }
}
