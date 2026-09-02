export type ByteArray = Uint8Array;
export type Base64String = string;

export interface KeyPair {
  publicKey: Base64String;
  privateKey: Base64String;
}

export interface OneTimePrekey {
  keyId: number;
  key: Base64String;
}

export interface PrekeyBundle {
  identityKey: Base64String;
  signedPrekey: Base64String;
  signature: Base64String;
  oneTimePrekeys: OneTimePrekey[];
}

export interface PeerBundleResponse {
  identityKey: Base64String;
  signedPrekey: Base64String;
  signature: Base64String;
  oneTimePrekey: OneTimePrekey | null;
}

export interface CryptoContract {
  generateIdentityKeypair(): Promise<KeyPair> | KeyPair;
  generateSignedPrekey(): Promise<KeyPair> | KeyPair;
  generateOneTimePrekey(): Promise<KeyPair> | KeyPair;

  signMessage(
    message: string | ByteArray,
    privateKey: string | ByteArray,
  ): Promise<string | ByteArray> | string | ByteArray;

  verifySignature(
    message: string | ByteArray,
    signature: string | ByteArray,
    publicKey: string | ByteArray,
  ): Promise<boolean> | boolean;

  encryptMessage(
    plaintext: string | ByteArray,
    senderPrivateKey: string | ByteArray,
    recipientPublicKey: string | ByteArray,
  ): Promise<string | ByteArray> | string | ByteArray;

  decryptMessage(
    ciphertext: string | ByteArray,
    senderPublicKey: string | ByteArray,
    recipientPrivateKey: string | ByteArray,
  ): Promise<string | ByteArray> | string | ByteArray;
}

export const CRYPTO_API = [
  'generateIdentityKeypair',
  'generateSignedPrekey',
  'generateOneTimePrekey',
  'signMessage',
  'verifySignature',
  'encryptMessage',
  'decryptMessage',
] as const;
