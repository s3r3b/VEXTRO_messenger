import type { EncryptedMessageEnvelope, MessageStatus } from './Protocol';

export interface DurableKeyValueStore {
    getItem(key: string): Promise<string | null>;
    setItem(key: string, value: string): Promise<void>;
    removeItem(key: string): Promise<void>;
}

export type DurableQueueName = 'outbox' | 'inbox';

export interface DurableMessageRecord {
    envelope: EncryptedMessageEnvelope;
    status: MessageStatus;
    attempts: number;
    createdAt: number;
    updatedAt: number;
    nextAttemptAt: number;
}

interface QueueSnapshot {
    version: 2;
    sequence: number;
    records: Record<string, DurableMessageRecord>;
}

const EMPTY_SNAPSHOT: QueueSnapshot = { version: 2, sequence: 0, records: {} };
const STATUS_RANK: Record<MessageStatus, number> = {
    queued: 0,
    accepted: 1,
    delivered: 2,
    failed: 3,
};

function isRecord(value: unknown): value is Record<string, unknown> {
    return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function parseSnapshot(value: string | null): QueueSnapshot | null {
    if (!value) return null;

    try {
        const parsed: unknown = JSON.parse(value);
        if (!isRecord(parsed) || !isRecord(parsed.records)) {
            return null;
        }
        if (parsed.version === 2 && typeof parsed.sequence === 'number' && Number.isInteger(parsed.sequence)) {
            return parsed as unknown as QueueSnapshot;
        }
        if (parsed.version === 1) {
            return { version: 2, sequence: 0, records: parsed.records as Record<string, DurableMessageRecord> };
        }
        return null;
    } catch {
        return null;
    }
}

function cloneSnapshot(snapshot: QueueSnapshot): QueueSnapshot {
    return { version: 2, sequence: snapshot.sequence, records: { ...snapshot.records } };
}

function canTransition(from: MessageStatus, to: MessageStatus): boolean {
    return STATUS_RANK[to] >= STATUS_RANK[from];
}

export class DurableMessageStore {
    private readonly locks = new Map<DurableQueueName, Promise<void>>();

    constructor(
        private readonly storage: DurableKeyValueStore,
        private readonly namespace = 'vextro.messages',
        private readonly now: () => number = () => Date.now(),
    ) {}

    async enqueue(queue: DurableQueueName, envelope: EncryptedMessageEnvelope): Promise<DurableMessageRecord> {
        return this.withQueueLock(queue, async () => {
            const snapshot = await this.read(queue);
            const existing = snapshot.records[envelope.messageId];
            if (existing) return existing;

            const timestamp = this.now();
            const record: DurableMessageRecord = {
                envelope,
                status: 'queued',
                attempts: 0,
                createdAt: timestamp,
                updatedAt: timestamp,
                nextAttemptAt: timestamp,
            };
            snapshot.records[envelope.messageId] = record;
            await this.write(queue, snapshot);
            return record;
        });
    }

    async get(queue: DurableQueueName, messageId: string): Promise<DurableMessageRecord | null> {
        const snapshot = await this.read(queue);
        return snapshot.records[messageId] ?? null;
    }

    async listReady(queue: DurableQueueName, timestamp = this.now()): Promise<DurableMessageRecord[]> {
        const snapshot = await this.read(queue);
        return Object.values(snapshot.records)
            .filter((record) => record.status !== 'delivered' && record.status !== 'failed' && record.nextAttemptAt <= timestamp)
            .sort((left, right) => left.createdAt - right.createdAt);
    }

    async markAttempt(queue: DurableQueueName, messageId: string, retryDelayMs: number): Promise<DurableMessageRecord | null> {
        return this.withQueueLock(queue, async () => {
            const snapshot = await this.read(queue);
            const record = snapshot.records[messageId];
            if (!record) return null;

            record.attempts += 1;
            record.updatedAt = this.now();
            record.nextAttemptAt = record.updatedAt + Math.max(0, retryDelayMs);
            await this.write(queue, snapshot);
            return record;
        });
    }

    async transition(queue: DurableQueueName, messageId: string, status: MessageStatus): Promise<DurableMessageRecord | null> {
        return this.withQueueLock(queue, async () => {
            const snapshot = await this.read(queue);
            const record = snapshot.records[messageId];
            if (!record) return null;
            if (!canTransition(record.status, status)) return record;

            record.status = status;
            record.updatedAt = this.now();
            await this.write(queue, snapshot);
            return record;
        });
    }

    async remove(queue: DurableQueueName, messageId: string): Promise<boolean> {
        return this.withQueueLock(queue, async () => {
            const snapshot = await this.read(queue);
            if (!snapshot.records[messageId]) return false;
            delete snapshot.records[messageId];
            await this.write(queue, snapshot);
            return true;
        });
    }

    async clear(queue: DurableQueueName): Promise<void> {
        return this.withQueueLock(queue, async () => {
            await Promise.all([
                this.storage.removeItem(this.slotKey(queue, 0)),
                this.storage.removeItem(this.slotKey(queue, 1)),
                this.storage.removeItem(this.key(queue)),
            ]);
        });
    }

    private async read(queue: DurableQueueName): Promise<QueueSnapshot> {
        const [slotA, slotB, legacy] = await Promise.all([
            this.storage.getItem(this.slotKey(queue, 0)),
            this.storage.getItem(this.slotKey(queue, 1)),
            this.storage.getItem(this.key(queue)),
        ]);
        const snapshots = [parseSnapshot(slotA), parseSnapshot(slotB), parseSnapshot(legacy)]
            .filter((snapshot): snapshot is QueueSnapshot => snapshot !== null);
        return snapshots.reduce(
            (latest, snapshot) => snapshot.sequence > latest.sequence ? snapshot : latest,
            cloneSnapshot(EMPTY_SNAPSHOT),
        );
    }

    private async write(queue: DurableQueueName, snapshot: QueueSnapshot): Promise<void> {
        const nextSnapshot: QueueSnapshot = {
            version: 2,
            sequence: snapshot.sequence + 1,
            records: snapshot.records,
        };
        const slot: 0 | 1 = nextSnapshot.sequence % 2 === 0 ? 0 : 1;
        await this.storage.setItem(this.slotKey(queue, slot), JSON.stringify(nextSnapshot));
    }

    private key(queue: DurableQueueName): string {
        return `${this.namespace}.${queue}`;
    }

    private slotKey(queue: DurableQueueName, slot: 0 | 1): string {
        return `${this.key(queue)}.${slot}`;
    }

    private async withQueueLock<T>(queue: DurableQueueName, operation: () => Promise<T>): Promise<T> {
        const previous = this.locks.get(queue) ?? Promise.resolve();
        let release: () => void = () => undefined;
        const current = new Promise<void>((resolve) => { release = resolve; });
        const chain = previous.then(() => current);
        this.locks.set(queue, chain);

        await previous;
        try {
            return await operation();
        } finally {
            release();
            if (this.locks.get(queue) === chain) this.locks.delete(queue);
        }
    }
}