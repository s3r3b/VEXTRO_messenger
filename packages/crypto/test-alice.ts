import { CryptoVault } from './src/CryptoVault';
import type { SecureStorageAdapter } from './src/StorageAdapter';
import * as fs from 'fs';

class FileStorageAdapter implements SecureStorageAdapter {
    constructor(private user: string) {}
    async savePrivateKey(key: Uint8Array) { fs.writeFileSync(`${this.user}-priv.bin`, key); }
    async getPrivateKey() { return fs.existsSync(`${this.user}-priv.bin`) ? fs.readFileSync(`${this.user}-priv.bin`) : null; }
    async savePublicKey(key: Uint8Array) { fs.writeFileSync(`${this.user}-pub.bin`, key); }
    async getPublicKey() { return fs.existsSync(`${this.user}-pub.bin`) ? fs.readFileSync(`${this.user}-pub.bin`) : null; }
    async clearKeys() {}
}

async function runAlice() {
    console.log("=== VEXTRO: ALICJA (NADAWCA) ===");
    const alice = new CryptoVault();
    await alice.init(new FileStorageAdapter('alice'));
    
    if (!alice.isReady()) {
        await alice.generateIdentity();
        console.log("✅ Wygenerowano nową tożsamość Alicji.");
    }

    const ws = new globalThis.WebSocket('ws://localhost:3001/ws');

    ws.onopen = () => {
        console.log("✅ Połączono z serwerem. Autoryzacja...");
        ws.send(JSON.stringify({ type: 'auth', userId: 'alice' }));
    };

    ws.onmessage = async (event) => {
        const payload = JSON.parse(event.data as string);

        if (payload.type === 'system' && payload.status === 'authenticated') {
            try {
                // Symulujemy pobranie klucza publicznego Boba (w produkcji to zrobi Key Server)
                if (!fs.existsSync('bob-pub.bin')) {
                    console.error("❌ Brak klucza Boba. Uruchom najpierw Boba, aby zapisał klucz na dysk!");
                    process.exit(1);
                }
                const bobPubKey = fs.readFileSync('bob-pub.bin');

                const message = `Tajne kody VEXTRO. Raport sytuacyjny. Czas: ${new Date().toLocaleTimeString()}`;
                console.log(`📤 Szyfruję wiadomość: "${message}"`);
                
                const encryptedBlob = await alice.encryptMessage(message, bobPubKey);
                const base64Ciphertext = Buffer.from(encryptedBlob).toString('base64');
                
                ws.send(JSON.stringify({
                    type: 'message',
                    recipientId: 'bob',
                    ciphertext: base64Ciphertext
                }));
                
                console.log("✅ Paczka wysłana do serwera (routing). Zamykam proces Alicji.");
                setTimeout(() => process.exit(0), 500);
            } catch (e) {
                console.error("❌ Błąd:", e);
            }
        }
    };
}
runAlice().catch(console.error);