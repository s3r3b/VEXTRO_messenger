import Fastify from 'fastify';
import fastifyWebsocket from '@fastify/websocket';
import type { WebSocket } from 'ws'; // Typ z zależności @fastify/websocket

const app = Fastify({ logger: true });
app.register(fastifyWebsocket);

// Menedżer Połączeń (RAM)
// Mapowanie: userId -> aktywny obiekt gniazda WebSocket
const activeConnections = new Map<string, WebSocket>();

app.register(async function (fastify) {
    fastify.get('/ws', { websocket: true }, (socket, req) => {
        let currentUserId: string | null = null;

        socket.on('message', (message: Buffer) => {
            try {
                // Dekodujemy Kopertę (JSON)
                const payload = JSON.parse(message.toString('utf-8'));

                // 1. Inicjalizacja połączenia (AUTH)
                if (payload.type === 'auth') {
                    if (!payload.userId) {
                        socket.send(JSON.stringify({ type: 'error', message: 'Brak userId.' }));
                        return;
                    }

                    currentUserId = payload.userId;
                    activeConnections.set(currentUserId, socket);

                    console.log(`[AUTH] Połączono: ${currentUserId} | Aktywni: ${activeConnections.size}`);
                    socket.send(JSON.stringify({ type: 'system', status: 'authenticated' }));
                    return;
                }

                // 2. Routing wiadomości (MESSAGE)
                if (payload.type === 'message') {
                    if (!currentUserId) {
                        socket.send(JSON.stringify({ type: 'error', message: 'Brak autoryzacji gniazda.' }));
                        return;
                    }

                    const { recipientId, ciphertext } = payload;

                    if (!recipientId || !ciphertext) {
                        socket.send(JSON.stringify({ type: 'error', message: 'Błędny format wiadomości.' }));
                        return;
                    }

                    console.log(`[ROUTER] Sieczka od ${currentUserId} do ${recipientId}`);
                    const targetSocket = activeConnections.get(recipientId);

                    if (targetSocket) {
                        // Odbiorca jest online - uderzamy bezpośrednio w RAM
                        targetSocket.send(JSON.stringify({
                            type: 'message',
                            senderId: currentUserId,
                            ciphertext: ciphertext // Zaszyfrowany payload w Base64
                        }));
                    } else {
                        // Odbiorca jest offline 
                        // TODO: Tutaj wejdzie Drizzle ORM + PostgreSQL
                        console.log(`[OFFLINE] ${recipientId} niedostępny. Pakiet idzie w eter (WIP - oczekuje na bazę).`);
                        socket.send(JSON.stringify({
                            type: 'system',
                            info: 'Odbiorca offline. Zrzut do bazy nie jest jeszcze zaimplementowany.'
                        }));
                    }
                }
            } catch (err) {
                console.error('[ERROR] Błąd parsowania ramki - to nie jest prawidłowy JSON:', err);
                socket.send(JSON.stringify({ type: 'error', message: 'Wymagany format Koperty JSON.' }));
            }
        });

        // Czyszczenie pamięci po rozłączeniu (KRYTYCZNE - inaczej mamy wyciek pamięci)
        socket.on('close', () => {
            if (currentUserId) {
                activeConnections.delete(currentUserId);
                console.log(`[DISCONNECT] Rozłączono: ${currentUserId} | Aktywni: ${activeConnections.size}`);
            }
        });
    });
});

app.get('/health', async () => {
    return {
        status: 'VEXTRO Blind Server is running',
        protocol: 'E2EE',
        activeSockets: activeConnections.size
    };
});

const start = async () => {
    try {
        await app.listen({ port: 3001, host: '0.0.0.0' });
        console.log('🔥 VEXTRO Server (Router Mode) nasłuchuje na ws://localhost:3001/ws');
    } catch (err) {
        app.log.error(err);
        process.exit(1);
    }
};

start();