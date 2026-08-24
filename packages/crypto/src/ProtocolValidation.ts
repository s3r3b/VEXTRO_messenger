import {
    type ClientMessage,
    type DeviceAddress,
    type EncryptedMessageEnvelope,
    type ServerMessage,
    PROTOCOL_VERSION,
} from './Protocol';
import type { PeerBundleResponse, PrekeyBundlePayload } from './StorageAdapter';

type UnknownRecord = Record<string, unknown>;

function isRecord(value: unknown): value is UnknownRecord {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isString(value: unknown): value is string {
    return typeof value === 'string' && value.length > 0;
}

function isFiniteNumber(value: unknown): value is number {
    return typeof value === 'number' && Number.isFinite(value);
}

function hasProtocolVersion(value: UnknownRecord): boolean {
    return value.protocolVersion === PROTOCOL_VERSION;
}

function isDeviceAddress(value: unknown): value is DeviceAddress {
    if (!isRecord(value)) return false;
    return isString(value.accountId) && isString(value.deviceId);
}

function isPeerBundle(value: unknown): value is PeerBundleResponse {
    if (!isRecord(value)) return false;
    if (!isString(value.identityKey) || !isString(value.signedPrekey) || !isString(value.signature)) {
        return false;
    }

    if (value.oneTimePrekey !== null && !isRecord(value.oneTimePrekey)) return false;
    if (value.oneTimePrekey === null) return true;

    return (
        isFiniteNumber(value.oneTimePrekey.keyId) &&
        Number.isInteger(value.oneTimePrekey.keyId) &&
        value.oneTimePrekey.keyId >= 0 &&
        isString(value.oneTimePrekey.key)
    );
}

function isPrekeyBundle(value: unknown): value is PrekeyBundlePayload {
    if (!isRecord(value)) return false;
    if (!isString(value.identityKey) || !isString(value.signedPrekey) || !isString(value.signature)) {
        return false;
    }
    if (!Array.isArray(value.oneTimePrekeys)) return false;

    return value.oneTimePrekeys.every((prekey) => {
        if (!isRecord(prekey)) return false;
        return (
            isFiniteNumber(prekey.keyId) &&
            Number.isInteger(prekey.keyId) &&
            prekey.keyId >= 0 &&
            isString(prekey.key)
        );
    });
}

function isEncryptedMessage(value: unknown): value is EncryptedMessageEnvelope {
    if (!isRecord(value)) return false;
    return (
        hasProtocolVersion(value) &&
        value.type === 'message' &&
        isString(value.messageId) &&
        isString(value.conversationId) &&
        isDeviceAddress(value.sender) &&
        isDeviceAddress(value.recipient) &&
        isString(value.ciphertext) &&
        isFiniteNumber(value.createdAt)
    );
}

function isMessageAck(value: UnknownRecord): boolean {
    return (
        hasProtocolVersion(value) &&
        value.type === 'message_ack' &&
        isString(value.messageId) &&
        (value.status === 'accepted' || value.status === 'delivered')
    );
}

function isAuthRequest(value: UnknownRecord): boolean {
    return (
        hasProtocolVersion(value) &&
        value.type === 'auth' &&
        isString(value.accountId) &&
        isString(value.deviceId) &&
        isString(value.identityKey) &&
        isString(value.challenge) &&
        isString(value.signature)
    );
}

function isAuthChallengeRequest(value: UnknownRecord): boolean {
    return (
        hasProtocolVersion(value) &&
        value.type === 'auth_challenge' &&
        isString(value.accountId) &&
        isString(value.deviceId)
    );
}

function isRegisterBundleRequest(value: UnknownRecord): boolean {
    return (
        hasProtocolVersion(value) &&
        value.type === 'register_bundle' &&
        isString(value.accountId) &&
        isString(value.deviceId) &&
        isPrekeyBundle(value.bundle)
    );
}

function isRequestBundle(value: UnknownRecord): boolean {
    return hasProtocolVersion(value) && value.type === 'request_bundle' && isDeviceAddress(value.target);
}

function isSystemEvent(value: UnknownRecord): boolean {
    return (
        hasProtocolVersion(value) &&
        value.type === 'system' &&
        (value.status === 'authenticated' || value.status === 'bundle_registered')
    );
}

function isAuthChallengeEvent(value: UnknownRecord): boolean {
    return (
        hasProtocolVersion(value) &&
        value.type === 'auth_challenge' &&
        isString(value.accountId) &&
        isString(value.deviceId) &&
        isString(value.challenge)
    );
}

function isErrorEvent(value: UnknownRecord): boolean {
    return hasProtocolVersion(value) && value.type === 'error' && isString(value.code) && isString(value.message);
}

function isBundleResponse(value: UnknownRecord): boolean {
    return hasProtocolVersion(value) && value.type === 'bundle_response' && isDeviceAddress(value.target) && isPeerBundle(value.bundle);
}

function parseMessage<T>(value: unknown, validator: (record: UnknownRecord) => boolean, name: string): T {
    if (!isRecord(value) || !validator(value)) {
        throw new Error(`Invalid ${name} protocol message`);
    }
    return value as T;
}

export function parseClientMessage(value: unknown): ClientMessage {
    return parseMessage<ClientMessage>(
        value,
        (record) =>
            isAuthChallengeRequest(record) ||
            isAuthRequest(record) ||
            isRegisterBundleRequest(record) ||
            isRequestBundle(record) ||
            isEncryptedMessage(record) ||
            isMessageAck(record),
        'client',
    );
}

export function parseServerMessage(value: unknown): ServerMessage {
    return parseMessage<ServerMessage>(
        value,
        (record) =>
            isSystemEvent(record) ||
            isAuthChallengeEvent(record) ||
            isErrorEvent(record) ||
            isEncryptedMessage(record) ||
            isMessageAck(record) ||
            isBundleResponse(record),
        'server',
    );
}

export function parseJsonMessage<T>(json: string, parser: (value: unknown) => T): T {
    let value: unknown;
    try {
        value = JSON.parse(json);
    } catch {
        throw new Error('Invalid JSON protocol message');
    }
    return parser(value);
}