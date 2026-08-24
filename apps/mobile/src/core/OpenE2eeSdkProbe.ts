import { createSignalProtocolClient } from '@open-e2ee/signal-protocol-sdk';
import { inMemoryStore } from '@open-e2ee/signal-protocol-sdk/local/store/memory';
import { inMemoryRelay } from '@open-e2ee/signal-protocol-sdk/remote/relay/memory';

export async function createOpenE2eeSdkProbe(accountId: string) {
    return createSignalProtocolClient({
        identity: { userId: accountId },
        adapters: { storage: inMemoryStore() },
    });
}

export async function runOpenE2eeRoundTripProbe(): Promise<string> {
    const relay = inMemoryRelay();
    await relay.registerDevice('probe-alice', { encryptedDeviceName: new ArrayBuffer(0) });
    await relay.registerDevice('probe-bob', { encryptedDeviceName: new ArrayBuffer(0) });

    const alice = await createSignalProtocolClient({
        identity: { userId: 'probe-alice' },
        adapters: { storage: inMemoryStore(), relay },
    });
    const bob = await createSignalProtocolClient({
        identity: { userId: 'probe-bob' },
        adapters: { storage: inMemoryStore(), relay },
    });

    await alice.syncToServer();
    await bob.syncToServer();

    const result = new Promise<string>((resolve) => {
        bob.registerHook('onMessageDecrypted', async (message) => resolve(message.content));
    });
    bob.startRelaySubscription();
    await alice.send('probe-bob', 'probe-message');
    return result;
}