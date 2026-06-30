export interface KeyPairBase64 {
    publicKey: string;
    privateKey: string;
}

export interface PrekeyBundlePayload {
    identityKey: string;         
    signedPrekey: string;        
    signature: string;           
    oneTimePrekeys: { keyId: number; key: string }[]; 
}

// Struktura odpowiedzi Ślepego Serwera z pojedynczym OPK
export interface PeerBundleResponse {
    identityKey: string;
    signedPrekey: string;
    signature: string;
    oneTimePrekey: { keyId: number; key: string } | null;
}

export interface SecureStorageAdapter {
    // Własny stan urządzenia
    saveIdentityKeyPair(keyPair: KeyPairBase64): Promise<void>;
    saveSignedPrekeyPair(keyPair: KeyPairBase64): Promise<void>;
    saveOneTimePrekeys(keys: { keyId: number; keyPair: KeyPairBase64 }[]): Promise<void>;

    getIdentityKeyPair(): Promise<KeyPairBase64 | null>;
    getSignedPrekeyPair(): Promise<KeyPairBase64 | null>;
    getOneTimePrekey(keyId: number): Promise<KeyPairBase64 | null>;
    
    removeOneTimePrekey(keyId: number): Promise<void>;
    clearKeys(): Promise<void>;

    // TOFU (Trust On First Use) - Pinowanie zweryfikowanych rozmówców
    saveTrustedPeerIdentity(peerId: string, identityKeyBase64: string): Promise<void>;
    getTrustedPeerIdentity(peerId: string): Promise<string | null>;
}