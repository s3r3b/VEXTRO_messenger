import Fastify from 'fastify';
import fastifyWebsocket from '@fastify/websocket';

const app = Fastify({ logger: true });

app.register(fastifyWebsocket);

app.register(async function (fastify) {
    // W v11 pierwszy argument to bezpośrednio 'socket'
    fastify.get('/ws', { websocket: true }, (socket, req) => {
        socket.on('message', (message: Buffer) => {
            console.log(`[BLIND SERVER] Otrzymano zaszyfrowany blob: ${message.length} bajtów`);
            // Odsyłamy echo
            socket.send(message);
        });
    });
});

app.get('/health', async () => {
    return { status: 'VEXTRO Blind Server is running', protocol: 'E2EE' };
});

const start = async () => {
    try {
        await app.listen({ port: 3001, host: '0.0.0.0' });
        console.log('🔥 VEXTRO Server nasłuchuje na ws://localhost:3001/ws');
    } catch (err) {
        app.log.error(err);
        process.exit(1);
    }
};

start();