import _sodium from 'libsodium-wrappers';
import type { SecureStorageAdapter, PrekeyBundlePayload, PeerBundleResponse } from './StorageAdapter';

export class CryptoVault {
    // Używamy Signed Prekey (SPK) jako operacyjnego klucza do rutynowego E2EE
    #spkPrivateKey: Uint8Array | null = null;
    public spkPublicKey: Uint8Array | null = null;

    private storage: SecureStorageAdapter | null = null;
    private sodiumReady: Promise<void>;

    constructor() {
        this.sodiumReady = _sodium.ready;
    }

    async init(storageAdapter: SecureStorageAdapter) {
        await this.sodiumReady;
        this.storage = storageAdapter;
        
        // Ładujemy SPK do RAM-u przy starcie
        const spk = await this.storage.getSignedPrekeyPair();
        if (spk) {
            const base64Variant = _sodium.base64_variants.ORIGINAL;
            this.#spkPrivateKey = _sodium.from_base64(spk.privateKey, base64Variant);
            this.spkPublicKey = _sodium.from_base64(spk.publicKey, base64Variant);
        }
    }

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

        // 3. Podpis SPK (Ed25519 nad X25519)
        const signature = _sodium.crypto_sign_detached(signedPrekey.publicKey, identityKey.privateKey);
        const signatureBase64 = _sodium.to_base64(signature, base64Variant);

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
            oneTimePrekeysPayload.push({ keyId: i, key: opkPublicBase64 });
        }

        // Zapis w bezpiecznym magazynie urządzenia
        await this.storage.saveIdentityKeyPair(ikBase64);
        await this.storage.saveSignedPrekeyPair(spkBase64);
        await this.storage.saveOneTimePrekeys(opksForStorage);

        // Aktualizacja RAM
        this.#spkPrivateKey = signedPrekey.privateKey;
        this.spkPublicKey = signedPrekey.publicKey;

        return {
            identityKey: ikBase64.publicKey,
            signedPrekey: spkBase64.publicKey,
            signature: signatureBase64,
            oneTimePrekeys: oneTimePrekeysPayload
        };
    }

    async verifyAndPinPeerBundle(peerId: string, peerBundle: PeerBundleResponse): Promise<{ key: Uint8Array, opkId: number | null }> {
        if (!this.storage) throw new Error("CRITICAL: Vault niezainicjalizowany!");
        await this.sodiumReady;

        const base64Variant = _sodium.base64_variants.ORIGINAL;
        const peerIk = _sodium.from_base64(peerBundle.identityKey, base64Variant);
        const peerSpk = _sodium.from_base64(peerBundle.signedPrekey, base64Variant);
        const signature = _sodium.from_base64(peerBundle.signature, base64Variant);

        // 1. Weryfikacja kryptograficzna - TOFU i zapobieganie MitM
        if (!_sodium.crypto_sign_verify_detached(signature, peerSpk, peerIk)) {
            throw new Error(`ALARM: Nieważny podpis paczki dla ${peerId}! Serwer podsłuchuje (MitM).`);
        }

        const pinnedIkBase64 = await this.storage.getTrustedPeerIdentity(peerId);
        if (pinnedIkBase64) {
            if (pinnedIkBase64 !== peerBundle.identityKey) throw new Error(`ALARM MitM: Klucz tożsamości dla ${peerId} uległ zmianie!`);
        } else {
            await this.storage.saveTrustedPeerIdentity(peerId, peerBundle.identityKey);
        }

        let encryptionKeyBase64 = peerBundle.signedPrekey;
        let usedOpkId = null;

        if (peerBundle.oneTimePrekey) {
            encryptionKeyBase64 = peerBundle.oneTimePrekey.key;
            usedOpkId = peerBundle.oneTimePrekey.keyId;
        }

        return {
            key: _sodium.from_base64(encryptionKeyBase64, base64Variant),
            opkId: usedOpkId
        };
    }

    isReady(): boolean {
        return this.#spkPrivateKey !== null && this.spkPublicKey !== null;
    }

    async encryptMessage(plaintext: string, recipientPubKey: Uint8Array): Promise<Uint8Array> {
        if (!this.#spkPrivateKey) throw new Error("Vault zablokowany: brak klucza operacyjnego w RAM.");
        await this.sodiumReady;

        const nonce = _sodium.randombytes_buf(_sodium.crypto_box_NONCEBYTES);
        const ciphertext = _sodium.crypto_box_easy(plaintext, nonce, recipientPubKey, this.#spkPrivateKey);

        const combined = new Uint8Array(nonce.length + ciphertext.length);
        combined.set(nonce);
        combined.set(ciphertext, nonce.length);

        return combined;
    }

    async decryptMessage(encryptedData: Uint8Array, senderPubKey: Uint8Array, opkId: number | null): Promise<string> {
        if (!this.storage) throw new Error("Vault zablokowany: brak zainicjalizowanego adaptera.");
        await this.sodiumReady;
        
        let privateKeyToUse: Uint8Array;

        // MATRIOSZKA: Wybieramy klucz prywatny na podstawie nagłówka
        if (opkId !== null) {
            const opkPair = await this.storage.getOneTimePrekey(opkId);
            if (!opkPair) throw new Error(`KRYTYCZNE: Brak klucza OPK o ID ${opkId}! Został już zużyty lub nie istnieje.`);
            privateKeyToUse = _sodium.from_base64(opkPair.privateKey, _sodium.base64_variants.ORIGINAL);
            
            // KRYTYCZNE FORWARD SECRECY: Palimy jednorazowy klucz po wyjęciu z bazy
            await this.storage.removeOneTimePrekey(opkId);
        } else {
            if (!this.#spkPrivateKey) throw new Error("Brak klucza SPK w RAM do deszyfracji awaryjnej.");
            privateKeyToUse = this.#spkPrivateKey;
        }

        const nonce = encryptedData.slice(0, _sodium.crypto_box_NONCEBYTES);
        const ciphertext = encryptedData.slice(_sodium.crypto_box_NONCEBYTES);

        try {
            const decrypted = _sodium.crypto_box_open_easy(ciphertext, nonce, senderPubKey, privateKeyToUse);
            return _sodium.to_string(decrypted);
        } catch (error) {
            throw new Error("Błąd deszyfrowania: Klucze nie pasują lub wiadomość zmodyfikowana!");
        }
    }
}

export const vault = new CryptoVault();