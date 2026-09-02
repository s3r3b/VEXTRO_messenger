import type { PeerBundleResponse, PrekeyBundlePayload } from './StorageAdapter';

export const PROTOCOL_VERSION = 1 as const;

export const E2EE_PROTOCOL = 'libsodium-rust-v1' as const;

export type E2EEProtocol = typeof E2EE_PROTOCOL;

export function authSigningPayload(accountId: string, deviceId: string, challenge: string): string {
    return `${accountId}.${deviceId}.${challenge}`;
}

export type MessageStatus = 'queued' | 'accepted' | 'delivered' | 'failed';

export interface DeviceAddress {
    accountId: string;
    deviceId: string;
}

export interface EncryptedMessageEnvelope {
    protocolVersion: typeof PROTOCOL_VERSION;
    e2eeProtocol: E2EEProtocol;
    type: 'message';
    messageId: string;
    conversationId: string;
    sender: DeviceAddress;
    recipient: DeviceAddress;
    ciphertext: string;
    createdAt: number;
}

export interface MessageAck {
    protocolVersion: typeof PROTOCOL_VERSION;
    type: 'message_ack';
    messageId: string;
    status: Extract<MessageStatus, 'accepted' | 'delivered'>;
}

export interface AuthRequest {
    protocolVersion: typeof PROTOCOL_VERSION;
    type: 'auth';
    accountId: string;
    deviceId: string;
    identityKey: string;
    challenge: string;
    signature: string;
}

export interface AuthChallengeRequest {
    protocolVersion: typeof PROTOCOL_VERSION;
    type: 'auth_challenge';
    accountId: string;
    deviceId: string;
}

export interface RegisterBundleRequest {
    protocolVersion: typeof PROTOCOL_VERSION;
    type: 'register_bundle';
    accountId: string;
    deviceId: string;
    bundle: PrekeyBundlePayload;
}

export interface RequestBundle {
    protocolVersion: typeof PROTOCOL_VERSION;
    type: 'request_bundle';
    target: DeviceAddress;
}

export interface SystemEvent {
    protocolVersion: typeof PROTOCOL_VERSION;
    type: 'system';
    status: 'authenticated' | 'bundle_registered';
}

export interface ErrorEvent {
    protocolVersion: typeof PROTOCOL_VERSION;
    type: 'error';
    code: string;
    message: string;
}

export type ClientMessage =
    | AuthChallengeRequest
    | AuthRequest
    | RegisterBundleRequest
    | RequestBundle
    | EncryptedMessageEnvelope
    | MessageAck;

export type ServerMessage =
    | SystemEvent
    | AuthChallengeEvent
    | ErrorEvent
    | EncryptedMessageEnvelope
    | MessageAck
    | PeerBundleResponseMessage;

export interface AuthChallengeEvent {
    protocolVersion: typeof PROTOCOL_VERSION;
    type: 'auth_challenge';
    accountId: string;
    deviceId: string;
    challenge: string;
}

export interface PeerBundleResponseMessage {
    protocolVersion: typeof PROTOCOL_VERSION;
    type: 'bundle_response';
    target: DeviceAddress;
    bundle: PeerBundleResponse;
}
