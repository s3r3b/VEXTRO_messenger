import type { SecureStorageAdapter, PrekeyBundlePayload, PeerBundleResponse, KeyPairBase64 } from './StorageAdapter';
import { authSigningPayload } from './Protocol';

interface NativeCryptoModule {
    createPrekeyBundle?: (opkCount: number) => Promise<string> | string;
    initOutboundSession?: (bundleJson: string, identitySecret: string) => Promise<string> | string;
    initInboundSession?: (initialMessageJson: string, keysJson: string) => Promise<string> | string;
    encryptMessage?: (sessionStateJson: string, plaintext: string) => Promise<string> | string;
    decryptMessage?: (sessionStateJson: string, payloadJson: string) => Promise<string> | string;
    sign?: (message: string, privateKey: string) => Promise<string> | string;
    verifySignature?: (message: string, signature: string, publicKey: string) => Promise<boolean> | boolean;
}

function requireNativeModule(): NativeCryptoModule {
    try {
        const reactNative = require('react-native') as {
            NativeModules?: {
                VextroCryptoModule?: NativeCryptoModule;
                VextroCrypto?: NativeCryptoModule;
            };
        };
        const nativeModule = reactNative.NativeModules?.VextroCryptoModule ?? reactNative.NativeModules?.VextroCrypto;
        if (!nativeModule) {
            throw new Error('VextroCryptoModule / VextroCrypto is not registered. Android native bridge is not available yet.');
        }
        return nativeModule;
    } catch {
        throw new Error('Rust/libsodium Android bridge is unavailable on this platform. The client refuses plaintext fallback until the native module is installed.');
    }
}

function parseNativeJsonPair(raw: string | undefined, context: string): [string, string] {
    if (!raw) {
        throw new Error(`Rust bridge returned empty output for ${context}.`);
    }

    let parsed: unknown;
    try {
        parsed = JSON.parse(raw);
    } catch {
        throw new Error(`Rust bridge returned invalid JSON for ${context}.`);
    }

    if (!Array.isArray(parsed) || parsed.length !== 2 || typeof parsed[0] !== 'string' || typeof parsed[1] !== 'string') {
        throw new Error(`Rust bridge returned an unexpected payload shape for ${context}.`);
    }

    return [parsed[0], parsed[1]];
}

function decodeBase64(value: string): Uint8Array {
    const bufferCtor = (globalThis as { Buffer?: { from: (data: string, encoding: string) => Uint8Array } }).Buffer;
    if (bufferCtor) {
        return new Uint8Array(bufferCtor.from(value, 'base64'));
    }

    if (typeof atob === 'function') {
        const binary = atob(value);
        const bytes = new Uint8Array(binary.length);
        for (let index = 0; index < binary.length; index += 1) {
            bytes[index] = binary.charCodeAt(index);
        }
        return bytes;
    }

    throw new Error('No Base64 decoder is available in this runtime.');
}

export class CryptoVault {
    private storage: SecureStorageAdapter | null = null;

    async init(storageAdapter: SecureStorageAdapter): Promise<void> {
        this.storage = storageAdapter;
    }

    private requireStorage(): SecureStorageAdapter {
        if (!this.storage) {
            throw new Error('Crypto vault is not initialized with a storage adapter.');
        }
        return this.storage;
    }

    private requireNative(): NativeCryptoModule {
        return requireNativeModule();
    }

    async generatePrekeyBundle(opkCount = 100): Promise<PrekeyBundlePayload> {
        const native = this.requireNative();
        if (!native.createPrekeyBundle) {
            throw new Error('Rust prekey bundle API is not exposed by the native module.');
        }

        const raw = await native.createPrekeyBundle(opkCount);
        const [bundleJson, secretsJson] = parseNativeJsonPair(raw, 'prekey bundle');

        const bundle = JSON.parse(bundleJson) as {
            identity_key?: string;
            signed_prekey?: string;
            signature?: string;
            one_time_prekeys?: Array<{ key_id?: number; key?: string }>;
        };
        const secrets = JSON.parse(secretsJson) as {
            identity_keypair?: { public_key?: string; private_key?: string };
            signed_prekeypair?: { public_key?: string; private_key?: string };
            one_time_prekeys?: Array<{ key_id?: number; key_pair?: { public_key?: string; private_key?: string } }>;
        };

        if (!bundle.identity_key || !bundle.signed_prekey || !bundle.signature) {
            throw new Error('Rust bundle response is missing required keys or signature.');
        }
        if (!secrets.identity_keypair || !secrets.signed_prekeypair) {
            throw new Error('Rust bundle response is missing private key material.');
        }

        const storage = this.requireStorage();
        await storage.saveIdentityKeyPair({
            publicKey: secrets.identity_keypair.public_key ?? bundle.identity_key,
            privateKey: secrets.identity_keypair.private_key ?? '',
        });
        await storage.saveSignedPrekeyPair({
            publicKey: secrets.signed_prekeypair.public_key ?? bundle.signed_prekey,
            privateKey: secrets.signed_prekeypair.private_key ?? '',
        });

        const ops = (secrets.one_time_prekeys ?? []).map((entry) => ({
            keyId: entry.key_id ?? 0,
            keyPair: {
                publicKey: entry.key_pair?.public_key ?? '',
                privateKey: entry.key_pair?.private_key ?? '',
            },
        }));
        await storage.saveOneTimePrekeys(ops);

        return {
            identityKey: bundle.identity_key,
            signedPrekey: bundle.signed_prekey,
            signature: bundle.signature,
            oneTimePrekeys: (bundle.one_time_prekeys ?? []).map((entry) => ({
                keyId: entry.key_id ?? 0,
                key: entry.key ?? '',
            })),
        };
    }

    async verifyAndPinPeerBundle(peerId: string, peerBundle: PeerBundleResponse): Promise<{ key: Uint8Array; opkId: number | null }> {
        const storage = this.requireStorage();
        const pinned = await storage.getTrustedPeerIdentity(peerId);
        if (pinned && pinned !== peerBundle.identityKey) {
            throw new Error(`Identity key for ${peerId} changed and the session is no longer trusted.`);
        }

        if (!pinned) {
            await storage.saveTrustedPeerIdentity(peerId, peerBundle.identityKey);
        }

        const keyValue = peerBundle.oneTimePrekey ? peerBundle.oneTimePrekey.key : peerBundle.signedPrekey;
        if (!keyValue) {
            throw new Error('Peer bundle does not contain a usable prekey.');
        }

        return {
            key: decodeBase64(keyValue),
            opkId: peerBundle.oneTimePrekey?.keyId ?? null,
        };
    }

    isReady(): boolean {
        return this.storage !== null;
    }

    async getIdentityPublicKey(): Promise<string> {
        const identity = await this.requireStorage().getIdentityKeyPair();
        if (!identity) {
            throw new Error('Identity keypair is missing. Generate a bundle before authenticating.');
        }
        return identity.publicKey;
    }

    async signAuthChallenge(accountId: string, deviceId: string, challenge: string): Promise<string> {
        const identity = await this.requireStorage().getIdentityKeyPair();
        if (!identity) {
            throw new Error('Identity keypair is missing. Generate a bundle before authenticating.');
        }

        const native = this.requireNative();
        if (!native.sign) {
            throw new Error('Rust signing API is not available in the native bridge.');
        }

        const payload = authSigningPayload(accountId, deviceId, challenge);
        const signature = await native.sign(payload, identity.privateKey);
        if (typeof signature !== 'string' || signature.length === 0) {
            throw new Error('The native bridge returned an empty signature.');
        }
        return signature;
    }

    async encryptMessage(_plaintext: string, _recipientPubKey: Uint8Array): Promise<Uint8Array> {
        throw new Error('Session encryption is intentionally unavailable until the Android Rust bridge is compiled and installed. The client refuses plaintext fallback.');
    }

    async decryptMessage(_encryptedData: Uint8Array, _senderPubKey: Uint8Array, _opkId: number | null): Promise<string> {
        throw new Error('Session decryption is intentionally unavailable until the Android Rust bridge is compiled and installed. The client refuses plaintext fallback.');
    }
}

export const vault = new CryptoVault();
