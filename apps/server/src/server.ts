import Fastify from 'fastify';
import fastifyWebsocket from '@fastify/websocket';
import type { WebSocket } from 'ws';
import { db } from './db';
import { offlineMessages, identities, oneTimePrekeys } from './db/schema'; // NOWE TABELE
import { eq } from 'drizzle-orm';

const app = Fastify({ logger: true });
app.register(fastifyWebsocket);

const activeConnections = new Map<string, WebSocket>();

app.register(async function (fastify) {
    fastify.get('/ws', { websocket: true }, (socket, req) => {
        let currentUserId: string | null = null;

        socket.on('message', async (message: Buffer) => { // Zmienione na async
            try {
                const payload = JSON.parse(message.toString('utf-8'));

                // 1. AUTH: Po zalogowaniu sprawdzamy bazę pod kątem wiadomości offline
                if (payload.type === 'auth') {
                    if (!payload.userId) return;
                    currentUserId = payload.userId;
                    activeConnections.set(currentUserId, socket);

                    console.log(`[AUTH] Użytkownik ${currentUserId} online.`);
                    socket.send(JSON.stringify({ type: 'system', status: 'authenticated' }));

                    // CZYTANIE Z BAZY: Pobieramy wszystko co czeka na tego usera
                    const pending = await db.select().from(offlineMessages).where(eq(offlineMessages.recipientId, currentUserId));

                    if (pending.length > 0) {
                        console.log(`[DB] Znaleziono ${pending.length} wiadomości offline dla ${currentUserId}. Wypycham...`);
                        for (const msg of pending) {
                            socket.send(JSON.stringify({
                                type: 'message',
                                senderId: msg.senderId,
                                ciphertext: msg.ciphertext
                            }));
                            // Usuwamy z bazy po wysyłce (Forward Secrecy - nie trzymamy śmieci)
                            await db.delete(offlineMessages).where(eq(offlineMessages.id, msg.id));
                        }
                    }
                    return;
                }

                // 2. ROUTING
                if (payload.type === 'message') {
                    if (!currentUserId) return;

                    const { recipientId, ciphertext } = payload;
                    const targetSocket = activeConnections.get(recipientId);

                    if (targetSocket) {
                        targetSocket.send(JSON.stringify({ type: 'message', senderId: currentUserId, ciphertext }));
                    } else {
                        // ZAPIS DO BAZY: Odbiorca offline
                        await db.insert(offlineMessages).values({
                            recipientId,
                            senderId: currentUserId,
                            ciphertext
                        });
                        console.log(`[DB] Wiadomość od ${currentUserId} dla ${recipientId} zapisana w offline_messages.`);
                    }
                }
                // 3. REJESTRACJA TOŻSAMOŚCI (PREKEY BUNDLE)
                if (payload.type === 'register_bundle') {
                    if (!currentUserId) return; // Wymaga uprzedniego auth
                    const { bundle } = payload;
                    
                    try {
                        // Używamy transakcji, żeby zapobiec uszkodzonym paczkom
                        await db.transaction(async (tx) => {
                            // 1. Zapis/Aktualizacja tożsamości głównej
                            await tx.insert(identities).values({
                                userId: currentUserId,
                                identityKey: bundle.identityKey,
                                signedPrekey: bundle.signedPrekey,
                                signature: bundle.signature
                            }).onConflictDoUpdate({
                                target: identities.userId, // Wymaga unique/primary key na userId
                                set: {
                                    identityKey: bundle.identityKey,
                                    signedPrekey: bundle.signedPrekey,
                                    signature: bundle.signature,
                                    updatedAt: new Date()
                                }
                            });

                            // 2. Czyścimy stare OPK (jeśli to reinstalacja)
                            await tx.delete(oneTimePrekeys).where(eq(oneTimePrekeys.userId, currentUserId));
                            
                            // 3. Batch insert nowych kluczy jednorazowych
                            const opksToInsert = bundle.oneTimePrekeys.map((opk: any) => ({
                                userId: currentUserId,
                                keyId: opk.keyId,
                                key: opk.key
                            }));
                            
                            if (opksToInsert.length > 0) {
                                await tx.insert(oneTimePrekeys).values(opksToInsert);
                            }
                        });
                        
                        console.log(`[KEY SERVER] Zarejestrowano paczkę kluczy dla: ${currentUserId}`);
                        socket.send(JSON.stringify({ type: 'system', status: 'bundle_registered' }));
                    } catch (err) {
                        console.error('[DB ERROR] Błąd zapisu bundle:', err);
                        socket.send(JSON.stringify({ type: 'error', message: 'Bundle registration failed' }));
                    }
                    return;
                }

                // 4. POBIERANIE PACZKI KLUCZY ROZMÓWCY (KEY DISTRIBUTION)
                if (payload.type === 'request_bundle') {
                    if (!currentUserId) return;
                    const { targetUserId } = payload;

                    try {
                        // Pobieramy tożsamość i SPK
                        const identityRecord = await db.select().from(identities).where(eq(identities.userId, targetUserId)).limit(1);
                        
                        if (identityRecord.length === 0) {
                            socket.send(JSON.stringify({ type: 'error', message: 'Target user bundle not found' }));
                            return;
                        }

                        // Pobieramy JEDEN klucz jednorazowy i bezwzględnie palimy go w bazie
                        const opkRecords = await db.select().from(oneTimePrekeys).where(eq(oneTimePrekeys.userId, targetUserId)).limit(1);
                        let opk = null;

                        if (opkRecords.length > 0) {
                            opk = { keyId: opkRecords[0].keyId, key: opkRecords[0].key };
                            await db.delete(oneTimePrekeys).where(eq(oneTimePrekeys.id, opkRecords[0].id));
                        }

                        // Ślepy Serwer wysyła czysty payload. Odszyfrowanie i weryfikacja podpisu to problem klienta.
                        socket.send(JSON.stringify({
                            type: 'bundle_response',
                            targetUserId,
                            bundle: {
                                identityKey: identityRecord[0].identityKey,
                                signedPrekey: identityRecord[0].signedPrekey,
                                signature: identityRecord[0].signature,
                                oneTimePrekey: opk // X3DH mówi jasno: Jeśli pula OPK się wyczerpała (null), zjeżdżamy na sam SPK. System E2EE nie pada.
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

// === TUTAJ JEST BRAKUJĄCY BLOK URUCHAMIAJĄCY SERWER ===
const start = async () => {
    try {
        // HOST 0.0.0.0 TO ABSOLUTNY WYMÓG W KONTENERZE!
        await app.listen({ port: 3001, host: '0.0.0.0' });
        console.log('🚀 [VEXTRO] Blind Server nasłuchuje na http://0.0.0.0:3001');
    } catch (err) {
        console.error('[CRITICAL] Błąd startu serwera:', err);
        process.exit(1);
    }
};

start();