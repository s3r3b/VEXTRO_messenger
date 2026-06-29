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

   // Zastępuje stare generateIdentity()
    async generatePrekeyBundle(opkCount: number = 100): Promise<PrekeyBundlePayload> {
        if (!this.storage) throw new Error("CRITICAL: Vault nie został zainicjalizowany adapterem!");
        await this.sodiumReady;

        const base64Variant = _sodium.base64_variants.ORIGINAL;

        // 1. Identity Key (Ed25519) - Klucz tożsamości i podpisu
        const identityKey = _sodium.crypto_sign_keypair();
        const ikBase64 = {
            publicKey: _sodium.to_base64(identityKey.publicKey, base64Variant),
            privateKey: _sodium.to_base64(identityKey.privateKey, base64Variant)
        };

        // 2. Signed Prekey (X25519) - Średnioterminowy klucz wymiany
        const signedPrekey = _sodium.crypto_box_keypair();
        const spkBase64 = {
            publicKey: _sodium.to_base64(signedPrekey.publicKey, base64Variant),
            privateKey: _sodium.to_base64(signedPrekey.privateKey, base64Variant)
        };

        // 3. Podpisujemy klucz publiczny SPK prywatnym kluczem tożsamości
        const signature = _sodium.crypto_sign_detached(signedPrekey.publicKey, identityKey.privateKey);
        const signatureBase64 = _sodium.to_base64(signature, base64Variant);

        // 4. Generujemy pulę jednorazowych kluczy OPK
        const oneTimePrekeysPayload = [];
        const opksForStorage = [];
        
        for (let i = 1; i <= opkCount; i++) {
            const opk = _sodium.crypto_box_keypair();
            const opkPublicBase64 = _sodium.to_base64(opk.publicKey, base64Variant);
            
            opksForStorage.push({
                keyId: i,
                keyPair: {
                    publicKey: opkPublicBase64,
                    privateKey: _sodium.to_base64(opk.privateKey, base64Variant)
                }
            });
            
            oneTimePrekeysPayload.push({
                keyId: i,
                key: opkPublicBase64
            });
        }

        // 5. Trwały zapis w hermetycznym storage'u klienta
        await this.storage.saveIdentityKeyPair(ikBase64);
        await this.storage.saveSignedPrekeyPair(spkBase64);
        await this.storage.saveOneTimePrekeys(opksForStorage);

        // 6. Zwracamy czysty payload gotowy do wypchnięcia przez Fastify do Supabase
        return {
            identityKey: ikBase64.publicKey,
            signedPrekey: spkBase64.publicKey,
            signature: signatureBase64,
            oneTimePrekeys: oneTimePrekeysPayload
        };
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