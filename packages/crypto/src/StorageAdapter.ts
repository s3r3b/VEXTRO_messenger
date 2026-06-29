export interface KeyPairBase64 {
    publicKey: string;
    privateKey: string;
}

export interface PrekeyBundlePayload {
    identityKey: string;         // Base64 (Ed25519)
    signedPrekey: string;        // Base64 (X25519)
    signature: string;           // Base64 (Podpis)
    oneTimePrekeys: { keyId: number; key: string }[]; // Tablica kluczy (X25519)
}

export interface SecureStorageAdapter {
    // Zapis stanu
    saveIdentityKeyPair(keyPair: KeyPairBase64): Promise<void>;
    saveSignedPrekeyPair(keyPair: KeyPairBase64): Promise<void>;
    saveOneTimePrekeys(keys: { keyId: number; keyPair: KeyPairBase64 }[]): Promise<void>;

    // Odczyt stanu
    getIdentityKeyPair(): Promise<KeyPairBase64 | null>;
    getSignedPrekeyPair(): Promise<KeyPairBase64 | null>;
    getOneTimePrekey(keyId: number): Promise<KeyPairBase64 | null>;
    
    // Zarządzanie kluczami jednorazowymi w miarę zużywania
    removeOneTimePrekey(keyId: number): Promise<void>;
    
    clearKeys(): Promise<void>;
}