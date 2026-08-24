import * as SecureStore from 'expo-secure-store';
import AsyncStorage from '@react-native-async-storage/async-storage';
import { type SecureStorageAdapter, type KeyPairBase64 } from '@vextro/crypto';
import { DurableMessageStore, type DurableKeyValueStore } from '../../../../packages/crypto/src/DurableMessageStore';

const KEYS = {
    IDENTITY_KEY: 'vextro_ik',
    SIGNED_PREKEY: 'vextro_spk',
    OPK_PREFIX: 'vextro_opk_',
    TRUSTED_PEER_PREFIX: 'vextro_peer_'
};

export class MobileStorageAdapter implements SecureStorageAdapter, DurableKeyValueStore {
    // --- 1. ENKLAWA SPRZĘTOWA (Klucze Prywatne) ---

    async saveIdentityKeyPair(keyPair: KeyPairBase64): Promise<void> {
        await SecureStore.setItemAsync(KEYS.IDENTITY_KEY, JSON.stringify(keyPair));
    }

    async saveSignedPrekeyPair(keyPair: KeyPairBase64): Promise<void> {
        await SecureStore.setItemAsync(KEYS.SIGNED_PREKEY, JSON.stringify(keyPair));
    }

    async saveOneTimePrekeys(keys: { keyId: number; keyPair: KeyPairBase64 }[]): Promise<void> {
        // Promise.all przyspieszy zrzut 100 kluczy jednorazowych asynchronicznie
        await Promise.all(
            keys.map(item => 
                SecureStore.setItemAsync(`${KEYS.OPK_PREFIX}${item.keyId}`, JSON.stringify(item.keyPair))
            )
        );
    }

    async getIdentityKeyPair(): Promise<KeyPairBase64 | null> {
        const data = await SecureStore.getItemAsync(KEYS.IDENTITY_KEY);
        return data ? JSON.parse(data) : null;
    }

    async getSignedPrekeyPair(): Promise<KeyPairBase64 | null> {
        const data = await SecureStore.getItemAsync(KEYS.SIGNED_PREKEY);
        return data ? JSON.parse(data) : null;
    }

    async getOneTimePrekey(keyId: number): Promise<KeyPairBase64 | null> {
        const data = await SecureStore.getItemAsync(`${KEYS.OPK_PREFIX}${keyId}`);
        return data ? JSON.parse(data) : null;
    }

    async removeOneTimePrekey(keyId: number): Promise<void> {
        await SecureStore.deleteItemAsync(`${KEYS.OPK_PREFIX}${keyId}`);
    }

    async clearKeys(): Promise<void> {
        await SecureStore.deleteItemAsync(KEYS.IDENTITY_KEY);
        await SecureStore.deleteItemAsync(KEYS.SIGNED_PREKEY);
        // Uwaga operacyjna: Czyszczenie wszystkich OPK przy Hard Resecie
        // zrealizujemy później, dodając rejestr w Async Storage. Na ten moment jest okej.
    }

    // --- 2. SZYBKI MAGAZYN ZAUFANIA (Klucze Publiczne / TOFU) ---

    async saveTrustedPeerIdentity(peerId: string, identityKeyBase64: string): Promise<void> {
        await AsyncStorage.setItem(`${KEYS.TRUSTED_PEER_PREFIX}${peerId}`, identityKeyBase64);
    }

    async getTrustedPeerIdentity(peerId: string): Promise<string | null> {
        return await AsyncStorage.getItem(`${KEYS.TRUSTED_PEER_PREFIX}${peerId}`);
    }

    async getItem(key: string): Promise<string | null> {
        return AsyncStorage.getItem(key);
    }

    async setItem(key: string, value: string): Promise<void> {
        await AsyncStorage.setItem(key, value);
    }

    async removeItem(key: string): Promise<void> {
        await AsyncStorage.removeItem(key);
    }
}

export const mobileStorageAdapter = new MobileStorageAdapter();
export const mobileMessageStore = new DurableMessageStore(mobileStorageAdapter);