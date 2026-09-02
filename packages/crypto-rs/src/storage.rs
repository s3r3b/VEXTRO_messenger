use std::collections::HashMap;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KeyPairBase64 {
    pub public_key: String,
    pub private_key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OneTimePrekeyEntry {
    pub key_id: u32,
    pub key_pair: KeyPairBase64,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct SecureStorageState {
    pub identity_key: Option<KeyPairBase64>,
    pub signed_prekey: Option<KeyPairBase64>,
    pub one_time_prekeys: HashMap<u32, KeyPairBase64>,
    pub trusted_peers: HashMap<String, String>,
}

pub trait SecureStorage {
    fn save_identity_keypair(&mut self, key_pair: KeyPairBase64);
    fn get_identity_keypair(&self) -> Option<KeyPairBase64>;

    fn save_signed_prekey(&mut self, key_pair: KeyPairBase64);
    fn get_signed_prekey(&self) -> Option<KeyPairBase64>;

    fn save_one_time_prekeys(&mut self, keys: Vec<OneTimePrekeyEntry>);
    fn get_one_time_prekey(&self, key_id: u32) -> Option<KeyPairBase64>;
    fn remove_one_time_prekey(&mut self, key_id: u32);

    fn save_trusted_peer_identity(&mut self, peer_id: String, identity_key: String);
    fn get_trusted_peer_identity(&self, peer_id: &str) -> Option<String>;
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InMemorySecureStorage {
    state: SecureStorageState,
}

impl InMemorySecureStorage {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn state(&self) -> &SecureStorageState {
        &self.state
    }
}

impl SecureStorage for InMemorySecureStorage {
    fn save_identity_keypair(&mut self, key_pair: KeyPairBase64) {
        self.state.identity_key = Some(key_pair);
    }

    fn get_identity_keypair(&self) -> Option<KeyPairBase64> {
        self.state.identity_key.clone()
    }

    fn save_signed_prekey(&mut self, key_pair: KeyPairBase64) {
        self.state.signed_prekey = Some(key_pair);
    }

    fn get_signed_prekey(&self) -> Option<KeyPairBase64> {
        self.state.signed_prekey.clone()
    }

    fn save_one_time_prekeys(&mut self, keys: Vec<OneTimePrekeyEntry>) {
        for entry in keys {
            self.state
                .one_time_prekeys
                .insert(entry.key_id, entry.key_pair);
        }
    }

    fn get_one_time_prekey(&self, key_id: u32) -> Option<KeyPairBase64> {
        self.state.one_time_prekeys.get(&key_id).cloned()
    }

    fn remove_one_time_prekey(&mut self, key_id: u32) {
        self.state.one_time_prekeys.remove(&key_id);
    }

    fn save_trusted_peer_identity(&mut self, peer_id: String, identity_key: String) {
        self.state.trusted_peers.insert(peer_id, identity_key);
    }

    fn get_trusted_peer_identity(&self, peer_id: &str) -> Option<String> {
        self.state.trusted_peers.get(peer_id).cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_round_trip_identity_and_signed_prekey() {
        let mut storage = InMemorySecureStorage::new();

        storage.save_identity_keypair(KeyPairBase64 {
            public_key: "ik_pub".to_string(),
            private_key: "ik_priv".to_string(),
        });

        storage.save_signed_prekey(KeyPairBase64 {
            public_key: "spk_pub".to_string(),
            private_key: "spk_priv".to_string(),
        });

        assert_eq!(storage.get_identity_keypair().unwrap().public_key, "ik_pub");
        assert_eq!(storage.get_signed_prekey().unwrap().private_key, "spk_priv");
    }

    #[test]
    fn storage_tracks_one_time_prekeys_and_removes_them() {
        let mut storage = InMemorySecureStorage::new();

        storage.save_one_time_prekeys(vec![OneTimePrekeyEntry {
            key_id: 7,
            key_pair: KeyPairBase64 {
                public_key: "opk_pub".to_string(),
                private_key: "opk_priv".to_string(),
            },
        }]);

        assert_eq!(
            storage.get_one_time_prekey(7).unwrap().public_key,
            "opk_pub"
        );

        storage.remove_one_time_prekey(7);
        assert!(storage.get_one_time_prekey(7).is_none());
    }
}
