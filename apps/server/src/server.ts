import Fastify from 'fastify';
import fastifyWebsocket from '@fastify/websocket';
import type { WebSocket } from 'ws';
import { db } from './db'; // Import naszej konfiguracji Drizzle
import { offlineMessages } from './db/schema'; // Import tabeli
import { eq } from 'drizzle-orm'; // Import operatora równości

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
            } catch (err) {
                console.error('[ERROR] Błąd przetwarzania:', err);
            }
        });

        socket.on('close', () => {
            if (currentUserId) activeConnections.delete(currentUserId);
        });
    });
});

// ... reszta kodu (start() itd.) zostaje bez zmian.