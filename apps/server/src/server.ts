import Fastify from 'fastify';
import fastifyWebsocket from '@fastify/websocket';
import type { WebSocket } from 'ws';
import { db } from './db';
import { offlineMessages, identities, oneTimePrekeys } from './db/schema';
import { eq } from 'drizzle-orm';

const app = Fastify({ logger: true });
app.register(fastifyWebsocket);

const activeConnections = new Map<string, WebSocket>();

app.register(async function (fastify) {
    fastify.get('/ws', { websocket: true }, (socket, req) => {
        let currentUserId: string | null = null;

        socket.on('message', async (message: Buffer) => {
            try {
                const payload = JSON.parse(message.toString('utf-8'));

                // 1. AUTH & BUFOR OFFLINE
                if (payload.type === 'auth') {
                    if (!payload.userId) return;
                    currentUserId = payload.userId;
                    activeConnections.set(currentUserId, socket);

                    console.log(`[AUTH] Użytkownik ${currentUserId} online.`);
                    socket.send(JSON.stringify({ type: 'system', status: 'authenticated' }));

                    const pending = await db.select().from(offlineMessages).where(eq(offlineMessages.recipientId, currentUserId));
                    if (pending.length > 0) {
                        for (const msg of pending) {
                            socket.send(JSON.stringify({ type: 'message', senderId: msg.senderId, ciphertext: msg.ciphertext }));
                            await db.delete(offlineMessages).where(eq(offlineMessages.id, msg.id));
                        }
                    }
                    return;
                }

                // 2. ROUTING KOPERT (MATRIOSZEK)
                if (payload.type === 'message') {
                    if (!currentUserId) return;
                    const { recipientId, ciphertext } = payload;
                    const targetSocket = activeConnections.get(recipientId);

                    if (targetSocket) {
                        targetSocket.send(JSON.stringify({ type: 'message', senderId: currentUserId, ciphertext }));
                    } else {
                        await db.insert(offlineMessages).values({ recipientId, senderId: currentUserId, ciphertext });
                        console.log(`[DB] Zrzut offline dla ${recipientId}.`);
                    }
                    return;
                }

                // 3. REJESTRACJA TOŻSAMOŚCI (PREKEY BUNDLE)
                if (payload.type === 'register_bundle') {
                    if (!currentUserId) return;
                    const { bundle } = payload;
                    
                    try {
                        await db.transaction(async (tx) => {
                            await tx.insert(identities).values({
                                userId: currentUserId!,
                                identityKey: bundle.identityKey,
                                signedPrekey: bundle.signedPrekey,
                                signature: bundle.signature
                            }).onConflictDoUpdate({
                                target: identities.userId,
                                set: {
                                    identityKey: bundle.identityKey,
                                    signedPrekey: bundle.signedPrekey,
                                    signature: bundle.signature,
                                    updatedAt: new Date()
                                }
                            });

                            await tx.delete(oneTimePrekeys).where(eq(oneTimePrekeys.userId, currentUserId!));
                            
                            const opksToInsert = bundle.oneTimePrekeys.map((opk: any) => ({
                                userId: currentUserId!,
                                keyId: opk.keyId,
                                key: opk.key
                            }));
                            
                            if (opksToInsert.length > 0) {
                                await tx.insert(oneTimePrekeys).values(opksToInsert);
                            }
                        });
                        console.log(`[KEY SERVER] Zarejestrowano paczkę dla: ${currentUserId}`);
                        socket.send(JSON.stringify({ type: 'system', status: 'bundle_registered' }));
                    } catch (err) {
                        console.error('[DB ERROR] Błąd zapisu bundle:', err);
                    }
                    return;
                }

                // 4. WYDAWANIE PACZKI KLUCZY (KEY DISTRIBUTION)
                if (payload.type === 'request_bundle') {
                    if (!currentUserId) return;
                    const { targetUserId } = payload;

                    try {
                        const identityRecord = await db.select().from(identities).where(eq(identities.userId, targetUserId)).limit(1);
                        if (identityRecord.length === 0) return;

                        const opkRecords = await db.select().from(oneTimePrekeys).where(eq(oneTimePrekeys.userId, targetUserId)).limit(1);
                        let opk = null;

                        if (opkRecords.length > 0) {
                            opk = { keyId: opkRecords[0].keyId, key: opkRecords[0].key };
                            await db.delete(oneTimePrekeys).where(eq(oneTimePrekeys.id, opkRecords[0].id));
                        }

                        socket.send(JSON.stringify({
                            type: 'bundle_response',
                            targetUserId,
                            bundle: {
                                identityKey: identityRecord[0].identityKey,
                                signedPrekey: identityRecord[0].signedPrekey,
                                signature: identityRecord[0].signature,
                                oneTimePrekey: opk
                            }
                        }));
                        console.log(`[KEY SERVER] Wydano paczkę kluczy ${targetUserId} dla ${currentUserId}`);
                    } catch (err) {
                        console.error('[DB ERROR] Błąd wydawania bundle:', err);
                    }
                    return;
                }

            } catch (err) {
                console.error('[ERROR] Błąd przetwarzania:', err);
            }
        });

        socket.on('close', () => {
            if (currentUserId) activeConnections.delete(currentUserId);
        });
    });
});

const start = async () => {
    try {
        await app.listen({ port: 3001, host: '0.0.0.0' });
        console.log('🚀 [VEXTRO] Blind Server nasłuchuje na http://0.0.0.0:3001');
    } catch (err) {
        console.error('[CRITICAL] Błąd startu serwera:', err);
        process.exit(1);
    }
};

start();