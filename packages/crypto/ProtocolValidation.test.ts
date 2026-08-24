import assert from 'node:assert/strict';
import { parseClientMessage, parseJsonMessage, parseServerMessage } from './src/ProtocolValidation';

const bundle = {
    identityKey: 'identity',
    signedPrekey: 'signed-prekey',
    signature: 'signature',
    oneTimePrekeys: [{ keyId: 1, key: 'opk' }],
};

const message = {
    protocolVersion: 1 as const,
    type: 'message' as const,
    messageId: 'message-1',
    conversationId: 'conversation-1',
    sender: { accountId: 'alice', deviceId: 'alice-device' },
    recipient: { accountId: 'bob', deviceId: 'bob-device' },
    ciphertext: 'ciphertext',
    createdAt: 1,
};

parseClientMessage({ protocolVersion: 1, type: 'register_bundle', accountId: 'alice', deviceId: 'alice-device', bundle });
parseClientMessage({
    protocolVersion: 1,
    type: 'auth_challenge',
    accountId: 'alice',
    deviceId: 'alice-device',
});
parseClientMessage({
    protocolVersion: 1,
    type: 'auth',
    accountId: 'alice',
    deviceId: 'alice-device',
    identityKey: 'identity',
    challenge: 'challenge',
    signature: 'signature',
});
parseServerMessage(message);
parseServerMessage({
    protocolVersion: 1,
    type: 'auth_challenge',
    accountId: 'alice',
    deviceId: 'alice-device',
    challenge: 'challenge',
});
parseJsonMessage(JSON.stringify(message), parseServerMessage);

assert.throws(() => parseServerMessage({ ...message, protocolVersion: 2 }));
assert.throws(() => parseServerMessage({ ...message, ciphertext: '' }));
assert.throws(() => parseClientMessage({ protocolVersion: 1, type: 'auth', accountId: 'alice', deviceId: 'device', sessionProof: 'old-api' }));
assert.throws(() => parseClientMessage({ protocolVersion: 1, type: 'register_bundle', accountId: 'alice', deviceId: 'device', bundle: { ...bundle, oneTimePrekeys: [{ keyId: 'bad', key: 'opk' }] } }));
assert.throws(() => parseJsonMessage('{not-json', parseServerMessage));

console.log('protocol validation tests passed');