import Fastify from 'fastify';
import fastifyWebsocket from '@fastify/websocket';
import { createPublicKey, randomBytes, verify } from 'node:crypto';
import { authSigningPayload, type AuthChallengeRequest, type AuthRequest, type ClientMessage, PROTOCOL_VERSION } from '@vextro/crypto';
import { parseClientMessage, parseJsonMessage } from '../../../packages/crypto/src/ProtocolValidation';
import { db } from './db';
import { offlineMessages, identities, oneTimePrekeys } from './db/schema';
import { eq, sql } from 'drizzle-orm';

const app = Fastify({ logger: true });
app.register(fastifyWebsocket);

type SocketLike = { readyState: number; send(data: string): void };

const activeConnections = new Map<string, SocketLike>();

const ED25519_SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function authSigningBytes(request: Pick<AuthRequest, 'accountId' | 'deviceId' | 'challenge'>): Buffer {
    return Buffer.from(authSigningPayload(request.accountId, request.deviceId, request.challenge), 'utf8');
}

function verifyAuthSignature(request: AuthRequest, storedIdentityKey: string): boolean {
    try {
        const rawPublicKey = Buffer.from(storedIdentityKey, 'base64');
        const signature = Buffer.from(request.signature, 'base64');
        const publicKey = createPublicKey({
            key: Buffer.concat([ED25519_SPKI_PREFIX, rawPublicKey]),
            format: 'der',
            type: 'spki',
        });
        return verify(null, authSigningBytes(request), publicKey, signature);
    } catch {
        return false;
    }
}

app.register(async function (fastify) {
    fastify.get('/ws', { websocket: true }, (socket, req) => {
        let currentUserId: string | null = null;
        let pendingChallenge: { accountId: string; deviceId: string; value: string } | null = null;

        socket.on('message', async (message: Buffer) => {
            try {
                const payload: ClientMessage = parseJsonMessage(message.toString('utf-8'), parseClientMessage);

                if (payload.protocolVersion !== PROTOCOL_VERSION) return;

                // 1. AUTH & BUFOR OFFLINE
                if (payload.type === 'auth_challenge') {
                    const request = payload as AuthChallengeRequest;
                    const identityRecord = await db.select().from(identities).where(eq(identities.userId, request.accountId)).limit(1);
                    if (identityRecord.length === 0) {
                        socket.send(JSON.stringify({ protocolVersion: PROTOCOL_VERSION, type: 'error', code: 'UNKNOWN_ACCOUNT', message: 'Unknown account' }));
                        return;
                    }

                    const challenge = randomBytes(32).toString('base64');
                    pendingChallenge = { accountId: request.accountId, deviceId: request.deviceId, value: challenge };
                    socket.send(JSON.stringify({
                        protocolVersion: PROTOCOL_VERSION,
                        type: 'auth_challenge',
                        accountId: request.accountId,
                        deviceId: request.deviceId,
                        challenge,
                    }));
                    return;
                }

                if (payload.type === 'auth') {
                    const request = payload as AuthRequest;
                    if (!pendingChallenge ||
                        pendingChallenge.accountId !== request.accountId ||
                        pendingChallenge.deviceId !== request.deviceId ||
                        pendingChallenge.value !== request.challenge) {
                        socket.send(JSON.stringify({ protocolVersion: PROTOCOL_VERSION, type: 'error', code: 'INVALID_CHALLENGE', message: 'Invalid or expired challenge' }));
                        return;
                    }

                    const identityRecord = await db.select().from(identities).where(eq(identities.userId, request.accountId)).limit(1);
                    pendingChallenge = null;
                    if (identityRecord.length === 0 || identityRecord[0].identityKey !== request.identityKey || !verifyAuthSignature(request, identityRecord[0].identityKey)) {
                        socket.send(JSON.stringify({ protocolVersion: PROTOCOL_VERSION, type: 'error', code: 'UNAUTHORIZED', message: 'Invalid device proof' }));
                        return;
                    }

                    currentUserId = request.accountId;
                    activeConnections.set(currentUserId, socket);

                    console.log(`[AUTH] Uzytkownik ${currentUserId} online.`);
                    socket.send(JSON.stringify({ protocolVersion: PROTOCOL_VERSION, type: 'system', status: 'authenticated' }));

                    const pending = await db.select().from(offlineMessages).where(eq(offlineMessages.recipientId, currentUserId));
                    if (pending.length > 0) {
                        for (const msg of pending) {
                            socket.send(JSON.stringify({ protocolVersion: PROTOCOL_VERSION, e2eeProtocol: 'signal-compatible-v1', type: 'message', messageId: msg.messageId, conversationId: msg.conversationId, sender: { accountId: msg.senderId, deviceId: msg.senderDeviceId }, recipient: { accountId: currentUserId, deviceId: msg.recipientDeviceId }, ciphertext: msg.ciphertext, createdAt: msg.createdAt.getTime() }));
                        }
                    }
                    return;
                }

                // 2. ROUTING KOPERT (MATRIOSZEK)
                if (payload.type === 'message') {
                    if (!currentUserId) return;
                    const { recipient, ciphertext, messageId, conversationId, sender } = payload;
                    if (sender.accountId !== currentUserId) return;
                    const targetSocket = activeConnections.get(recipient.accountId);

                    await db.insert(offlineMessages).values({
                        messageId,
                        conversationId,
                        recipientId: recipient.accountId,
                        senderId: currentUserId,
                        senderDeviceId: sender.deviceId,
                        recipientDeviceId: recipient.deviceId,
                        ciphertext,
                    }).onConflictDoNothing({ target: offlineMessages.messageId });

                    socket.send(JSON.stringify({
                        protocolVersion: PROTOCOL_VERSION,
                        type: 'message_ack',
                        messageId,
                        status: 'accepted',
                    }));

                    if (targetSocket && targetSocket.readyState === 1) {
                        targetSocket.send(JSON.stringify(payload));
                    }
                    return;
                }

                if (payload.type === 'message_ack') {
                    if (!currentUserId) return;

                    const storedMessage = await db.select().from(offlineMessages).where(eq(offlineMessages.messageId, payload.messageId)).limit(1);
                    if (storedMessage.length === 0 || storedMessage[0].recipientId !== currentUserId) return;

                    await db.delete(offlineMessages).where(eq(offlineMessages.messageId, payload.messageId));
                    const senderSocket = activeConnections.get(storedMessage[0].senderId);
                    if (senderSocket && senderSocket.readyState === 1) {
                        senderSocket.send(JSON.stringify(payload));
                    }
                    return;
                }

                // 3. REJESTRACJA TOŻSAMOŚCI (PREKEY BUNDLE)
                if (payload.type === 'register_bundle') {
                    const { accountId, bundle } = payload;
                    if (currentUserId && currentUserId !== accountId) return;

                    if (!currentUserId) {
                        const existingIdentity = await db.select().from(identities).where(eq(identities.userId, accountId)).limit(1);
                        if (existingIdentity.length > 0) {
                            socket.send(JSON.stringify({ protocolVersion: PROTOCOL_VERSION, type: 'error', code: 'ACCOUNT_EXISTS', message: 'Account already exists' }));
                            return;
                        }
                        await db.insert(identities).values({
                            userId: accountId,
                            identityKey: bundle.identityKey,
                            signedPrekey: bundle.signedPrekey,
                            signature: bundle.signature,
                        });
                        currentUserId = accountId;
                        activeConnections.set(currentUserId, socket);
                    }
                    
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
                        socket.send(JSON.stringify({ protocolVersion: PROTOCOL_VERSION, type: 'system', status: 'bundle_registered' }));
                    } catch (err) {
                        console.error('[DB ERROR] Błąd zapisu bundle:', err);
                    }
                    return;
                }

                // 4. WYDAWANIE PACZKI KLUCZY (KEY DISTRIBUTION)
                if (payload.type === 'request_bundle') {
                    if (!currentUserId) return;
                    const { target } = payload;
                    const targetUserId = target.accountId;

                    try {
                        const identityRecord = await db.select().from(identities).where(eq(identities.userId, targetUserId)).limit(1);
                        if (identityRecord.length === 0) return;

                        const opkRecords = await db.execute<{ id: string; key_id: number; key: string }>(sql`
                            DELETE FROM one_time_prekeys
                            WHERE id = (
                                SELECT id
                                FROM one_time_prekeys
                                WHERE user_id = ${targetUserId}
                                ORDER BY id
                                FOR UPDATE SKIP LOCKED
                                LIMIT 1
                            )
                            RETURNING id, key_id, key
                        `);
                        let opk = null;

                        if (opkRecords.length > 0) {
                            opk = { keyId: opkRecords[0].key_id, key: opkRecords[0].key };
                        }

                        socket.send(JSON.stringify({
                            protocolVersion: PROTOCOL_VERSION,
                            type: 'bundle_response',
                            target,
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