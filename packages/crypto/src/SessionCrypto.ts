import type { DeviceAddress, EncryptedMessageEnvelope, E2EEProtocol } from './Protocol';

export interface SessionCrypto {
    readonly protocol: E2EEProtocol;
    hasSession(peer: DeviceAddress): Promise<boolean>;
    establishSession(peer: DeviceAddress): Promise<void>;
    encrypt(
        plaintext: string,
        context: {
            messageId: string;
            conversationId: string;
            sender: DeviceAddress;
            recipient: DeviceAddress;
        },
    ): Promise<EncryptedMessageEnvelope>;
    decrypt(envelope: EncryptedMessageEnvelope): Promise<string>;
}

export class UnavailableSessionCrypto implements SessionCrypto {
    readonly protocol = 'libsodium-rust-v1' as const;

    async hasSession(): Promise<boolean> {
        return false;
    }

    async establishSession(): Promise<void> {
        throw new Error('Rust/libsodium backend is not configured for this platform');
    }

    async encrypt(): Promise<EncryptedMessageEnvelope> {
        throw new Error('Refusing to encrypt: Rust/libsodium backend is not configured');
    }

    async decrypt(): Promise<string> {
        throw new Error('Refusing to decrypt: Rust/libsodium backend is not configured');
    }
}