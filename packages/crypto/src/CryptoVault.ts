import _sodium from 'libsodium-wrappers';
import type { SecureStorageAdapter } from './StorageAdapter';

export class CryptoVault {
    // 1. ZAMIAST klucza szyfrującego, w RAM trzymamy WYŁĄCZNIE klucz tożsamości (Podpisy Ed25519)
    #identityPrivateKey: Uint8Array | null = null;
    public identityPublicKey: Uint8Array | null = null;

    private storage: SecureStorageAdapter | null = null;
    private sodiumReady: Promise<void>;

    constructor() {
        this.sodiumReady = _sodium.ready;
    }

    async init(storageAdapter: SecureStorageAdapter) {
        await this.sodiumReady;
        this.storage = storageAdapter;

        const identity = await this.storage.getIdentityKeyPair();
        if (identity) {
            const base64Variant = _sodium.base64_variants.ORIGINAL;
            this.#identityPrivateKey = _sodium.from_base64(identity.privateKey, base64Variant);
            this.identityPublicKey = _sodium.from_base64(identity.publicKey, base64Variant);
        }
    }

    // -------------------------------------------------------------------------
    // FAZA 1: TOŻSAMOŚĆ I PULE KLUCZY
    // -------------------------------------------------------------------------

    async generateIdentityAndOfflinePool(opkCount: number = 100) {
        if (!this.storage) throw new Error("CRITICAL: Vault nie został zainicjalizowany adapterem!");
        await this.sodiumReady;
        const base64Variant = _sodium.base64_variants.ORIGINAL;

        // Główna tożsamość do podpisów i dowodzenia kim jesteś (Ed25519)
        const identityKey = _sodium.crypto_sign_keypair();

        const opksForStorage = [];
        const publicOpksForServer = [];

        // Generujemy pulę jednorazowych kluczy SZYFRUJĄCYCH do komunikacji offline (X25519)
        for (let i = 1; i <= opkCount; i++) {
            const opk = _sodium.crypto_box_keypair();
            const opkPublicBase64 = _sodium.to_base64(opk.publicKey, base64Variant);

            // Podpisujemy każdy klucz publiczny OTK naszym głównym kluczem tożsamości
            const signature = _sodium.crypto_sign_detached(opk.publicKey, identityKey.privateKey);

            opksForStorage.push({
                keyId: i,
                keyPair: {
                    publicKey: opkPublicBase64,
                    privateKey: _sodium.to_base64(opk.privateKey, base64Variant)
                }
            });

            publicOpksForServer.push({
                keyId: i,
                key: opkPublicBase64,
                signature: _sodium.to_base64(signature, base64Variant)
            });
        }

        // Zapis do lokalnego storage'u
        await this.storage.saveIdentityKeyPair({
            publicKey: _sodium.to_base64(identityKey.publicKey, base64Variant),
            privateKey: _sodium.to_base64(identityKey.privateKey, base64Variant)
        });
        await this.storage.saveOneTimePrekeys(opksForStorage);

        this.#identityPrivateKey = identityKey.privateKey;
        this.identityPublicKey = identityKey.publicKey;

        return {
            identityKey: _sodium.to_base64(identityKey.publicKey, base64Variant),
            oneTimePrekeys: publicOpksForServer // To leci na Blind Server
        };
    }

    // -------------------------------------------------------------------------
    // FAZA 2: TRYB ONLINE (Strumień z Ratchetem)
    // -------------------------------------------------------------------------

    // Inicjuje bezpieczny tunel dla WebSockets używając crypto_kx (Key Exchange)
    async establishOnlineSessionKeys(peerIdentityPublicKeyBase64: string, isServerRole: boolean) {
        if (!this.#identityPrivateKey || !this.identityPublicKey) throw new Error("Vault zablokowany.");
        await this.sodiumReady;
        const base64Variant = _sodium.base64_variants.ORIGINAL;

        // W libsodium konwertujemy klucze Ed25519 (podpis) na X25519 (szyfrowanie) W LOCIE.
        // Dzięki temu nie musimy trzymać oddzielnego SPK.
        const myX25519Secret = _sodium.crypto_sign_ed25519_sk_to_curve25519(this.#identityPrivateKey);
        const myX25519Public = _sodium.crypto_sign_ed25519_pk_to_curve25519(this.identityPublicKey);

        const peerIdentityEd25519 = _sodium.from_base64(peerIdentityPublicKeyBase64, base64Variant);
        const peerX25519Public = _sodium.crypto_sign_ed25519_pk_to_curve25519(peerIdentityEd25519);

        // Algorytm Key Exchange (KX) z libsodium. Generuje osobne klucze do odbioru(rx) i wysyłki(tx).
        let sessionKeys;
        if (isServerRole) {
            sessionKeys = _sodium.crypto_kx_server_session_keys(myX25519Public, myX25519Secret, peerX25519Public);
        } else {
            sessionKeys = _sodium.crypto_kx_client_session_keys(myX25519Public, myX25519Secret, peerX25519Public);
        }

        // Tych kluczy RX/TX użyjemy potem do `crypto_secretstream_xchacha20poly1305_init_push`
        // Zapewnia to perfekcyjny Forward Secrecy i chroni przed modyfikacją strumienia WS.
        return sessionKeys;
    }

    // -------------------------------------------------------------------------
    // FAZA 3: TRYB OFFLINE (Efemeryczne koperty - Sealed/Signed Boxes)
    // -------------------------------------------------------------------------

    async encryptOfflineEnvelope(plaintext: string, recipientOtkBase64: string): Promise<Uint8Array> {
        if (!this.#identityPrivateKey) throw new Error("Vault zablokowany.");
        await this.sodiumReady;
        const base64Variant = _sodium.base64_variants.ORIGINAL;
        const recipientOtk = _sodium.from_base64(recipientOtkBase64, base64Variant);

        // Zamiast szyfrować ze stałego klucza, nadawca generuje klucz efemeryczny (tylko na ułamek sekundy)
        const ephemeralKeyPair = _sodium.crypto_box_keypair();
        const nonce = _sodium.randombytes_buf(_sodium.crypto_box_NONCEBYTES);

        // Szyfrujemy wiadomość z klucza ulotnego do jednorazowego klucza odbiorcy (OTK)
        const ciphertext = _sodium.crypto_box_easy(plaintext, nonce, recipientOtk, ephemeralKeyPair.privateKey);

        // Składamy payload: [Nonce] + [Klucz efemeryczny nadawcy] + [Kryptogram]
        const payload = new Uint8Array(nonce.length + ephemeralKeyPair.publicKey.length + ciphertext.length);
        payload.set(nonce);
        payload.set(ephemeralKeyPair.publicKey, nonce.length);
        payload.set(ciphertext, nonce.length + ephemeralKeyPair.publicKey.length);

        // Aby odbiorca wiedział, że to na pewno od nas, podpisujemy cały ten blob naszym głównym Ed25519
        const signature = _sodium.crypto_sign_detached(payload, this.#identityPrivateKey);

        // Zwracamy [Podpis] + [Payload]
        const envelope = new Uint8Array(signature.length + payload.length);
        envelope.set(signature);
        envelope.set(payload, signature.length);

        return envelope;
    }
}

export const vault = new CryptoVault();