import assert from 'node:assert/strict';
import { DurableMessageStore, type DurableKeyValueStore } from './src/DurableMessageStore';
import type { EncryptedMessageEnvelope } from './src/Protocol';

class MemoryStore implements DurableKeyValueStore {
    private readonly values = new Map<string, string>();

    async getItem(key: string): Promise<string | null> { return this.values.get(key) ?? null; }
    async setItem(key: string, value: string): Promise<void> { this.values.set(key, value); }
    async removeItem(key: string): Promise<void> { this.values.delete(key); }
}

const envelope: EncryptedMessageEnvelope = {
    protocolVersion: 1,
    type: 'message',
    messageId: 'message-1',
    conversationId: 'conversation-1',
    sender: { accountId: 'alice', deviceId: 'alice-device' },
    recipient: { accountId: 'bob', deviceId: 'bob-device' },
    ciphertext: 'ciphertext-only',
    createdAt: 1,
};

async function run(): Promise<void> {
    const store = new DurableMessageStore(new MemoryStore(), 'test.messages', () => 1000);
    const first = await store.enqueue('outbox', envelope);
    const duplicate = await store.enqueue('outbox', envelope);
    assert.equal(first.createdAt, duplicate.createdAt);
    assert.equal((await store.listReady('outbox')).length, 1);

    await store.markAttempt('outbox', envelope.messageId, 5000);
    assert.equal((await store.listReady('outbox', 1000)).length, 0);
    assert.equal((await store.get('outbox', envelope.messageId))?.attempts, 1);

    await store.transition('outbox', envelope.messageId, 'accepted');
    await store.transition('outbox', envelope.messageId, 'queued');
    assert.equal((await store.get('outbox', envelope.messageId))?.status, 'accepted');

    await store.transition('outbox', envelope.messageId, 'delivered');
    await store.remove('outbox', envelope.messageId);
    assert.equal(await store.get('outbox', envelope.messageId), null);

    console.log('durable message store tests passed');
}

run().catch((error: unknown) => {
    console.error(error);
    process.exitCode = 1;
});