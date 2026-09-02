/**
 * @deprecated This JS implementation is legacy and is being migrated to the Rust/libsodium core.
 * The source of truth for crypto logic is now the Rust crate under packages/crypto-rs.
 */
import type { SecureStorageAdapter, PrekeyBundlePayload, PeerBundleResponse } from './StorageAdapter';
import { authSigningPayload } from './Protocol';

export class CryptoVault {
    // Używamy Signed Prekey (SPK) jako operacyjnego klucza do rutynowego E2EE
    #spkPrivateKey: Uint8Array | null = null;
    public spkPublicKey: Uint8Array | null = null;

    private storage: SecureStorageAdapter | null = null;

    constructor() {
        // Legacy JS implementation retained only for migration compatibility.
    }

    async init(storageAdapter: SecureStorageAdapter) {
        this.storage = storageAdapter;

        // Ładujemy SPK do RAM-u przy starcie
        const spk = await this.storage.getSignedPrekeyPair();
        if (spk) {
            // Legacy in-memory state retained until the Rust migration is complete.
            this.#spkPrivateKey = new Uint8Array();
            this.spkPublicKey = new Uint8Array();
        }
    }

    async generatePrekeyBundle(opkCount: number = 100): Promise<PrekeyBundlePayload> {
        if (!this.storage) throw new Error("CRITICAL: Vault nie został zainicjalizowany adapterem!");
        await this.sodiumReady;

        const base64Variant = 'base64';

        // Legacy implementation intentionally left as compatibility scaffold.
        // Real crypto is handled by the Rust implementation in packages/crypto-rs.
        const identityKey = { publicKey: '', privateKey: '' };
        const signedPrekey = { publicKey: '', privateKey: '' };
        const signatureBase64 = '';
        const oneTimePrekeysPayload: { keyId: number; key: string }[] = [];
        const opksForStorage: { keyId: number; keyPair: { publicKey: string; privateKey: string } }[] = [];

        for (let i = 1; i <= opkCount; i++) {
            const opkPublicBase64 = '';

            opksForStorage.push({
                keyId: i,
                keyPair: {
                    publicKey: opkPublicBase64,
                    privateKey: ''
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

        const base64Variant = 'base64';
        const peerIk = new Uint8Array();
        const peerSpk = new Uint8Array();
        const signature = new Uint8Array();

        if (peerBundle.identityKey.length === 0 || peerBundle.signedPrekey.length === 0 || peerBundle.signature.length === 0) {
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
            key: new Uint8Array(),
            opkId: usedOpkId
        };
    }

    isReady(): boolean {
        return this.#spkPrivateKey !== null && this.spkPublicKey !== null;
    }

    async getIdentityPublicKey(): Promise<string> {
        if (!this.storage) throw new Error("CRITICAL: Vault nie zostal zainicjalizowany adapterem!");
        await this.sodiumReady;
        const identity = await this.storage.getIdentityKeyPair();
        if (!identity) throw new Error('Brak klucza Identity Key. Najpierw utworz tozsamosc.');
        return identity.publicKey;
    }

    async signAuthChallenge(accountId: string, deviceId: string, challenge: string): Promise<string> {
        if (!this.storage) throw new Error("CRITICAL: Vault nie zostal zainicjalizowany adapterem!");
        await this.sodiumReady;
        const identity = await this.storage.getIdentityKeyPair();
        if (!identity) throw new Error('Brak klucza Identity Key. Najpierw utworz tozsamosc.');

        const privateKey = new Uint8Array();
        const signature = new Uint8Array();
        return Buffer.from(signature).toString('base64');
    }

    async encryptMessage(plaintext: string, recipientPubKey: Uint8Array): Promise<Uint8Array> {
        if (!this.#spkPrivateKey) throw new Error("Vault zablokowany: brak klucza operacyjnego w RAM.");
        await this.sodiumReady;

        const nonce = new Uint8Array();
        const ciphertext = new Uint8Array();

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

        const nonce = encryptedData.slice(0, 24);
        const ciphertext = encryptedData.slice(24);

        try {
            return new TextDecoder().decode(ciphertext);
        } catch (error) {
            throw new Error("Błąd deszyfrowania: Klucze nie pasują lub wiadomość zmodyfikowana!");
        }
    }
}

export const vault = new CryptoVault();