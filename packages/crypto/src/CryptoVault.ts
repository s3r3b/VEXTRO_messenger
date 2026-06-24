import _sodium from 'libsodium-wrappers';
import type { SecureStorageAdapter } from './StorageAdapter';

export class CryptoVault {
    #privateKey: Uint8Array | null = null;
    public publicKey: Uint8Array | null = null;

    private storage: SecureStorageAdapter | null = null;
    private sodiumReady: Promise<void>;

    constructor() {
        this.sodiumReady = _sodium.ready;
    }

    async init(storageAdapter: SecureStorageAdapter) {
        await this.sodiumReady;
        this.storage = storageAdapter;
        this.#privateKey = await this.storage.getPrivateKey();
        this.publicKey = await this.storage.getPublicKey();
    }

    async generateIdentity() {
        if (!this.storage) throw new Error("Vault nie został zainicjalizowany adapterem");
        await this.sodiumReady;

        const keypair = _sodium.crypto_box_keypair();
        this.#privateKey = keypair.privateKey;
        this.publicKey = keypair.publicKey;

        await this.storage.savePrivateKey(this.#privateKey);
        await this.storage.savePublicKey(this.publicKey);
    }

    isReady(): boolean {
        return this.#privateKey !== null && this.publicKey !== null;
    }

    async encryptMessage(plaintext: string, recipientPubKey: Uint8Array): Promise<Uint8Array> {
        if (!this.#privateKey) throw new Error("Vault zablokowany: brak klucza prywatnego.");
        await this.sodiumReady;

        const nonce = _sodium.randombytes_buf(_sodium.crypto_box_NONCEBYTES);
        const ciphertext = _sodium.crypto_box_easy(plaintext, nonce, recipientPubKey, this.#privateKey);

        const combined = new Uint8Array(nonce.length + ciphertext.length);
        combined.set(nonce);
        combined.set(ciphertext, nonce.length);

        return combined;
    }

    async decryptMessage(encryptedData: Uint8Array, senderPubKey: Uint8Array): Promise<string> {
        if (!this.#privateKey) throw new Error("Vault zablokowany: brak klucza prywatnego.");
        await this.sodiumReady;

        const nonce = encryptedData.slice(0, _sodium.crypto_box_NONCEBYTES);
        const ciphertext = encryptedData.slice(_sodium.crypto_box_NONCEBYTES);

        try {
            const decrypted = _sodium.crypto_box_open_easy(ciphertext, nonce, senderPubKey, this.#privateKey);
            return _sodium.to_string(decrypted);
        } catch (error) {
            throw new Error("Błąd deszyfrowania: Klucze nie pasują lub wiadomość została zmodyfikowana!");
        }
    }
}

// Eksportujemy zarówno klasę (do testów), jak i instancję (do aplikacji)
export const vault = new CryptoVault();