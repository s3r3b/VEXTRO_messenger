export interface SecureStorageAdapter {
    savePrivateKey(key: Uint8Array): Promise<void>;
    getPrivateKey(): Promise<Uint8Array | null>;
    savePublicKey(key: Uint8Array): Promise<void>;
    getPublicKey(): Promise<Uint8Array | null>;
    clearKeys(): Promise<void>;
}