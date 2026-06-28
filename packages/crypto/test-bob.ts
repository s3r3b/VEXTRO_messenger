import { CryptoVault } from './src/CryptoVault';
import type { SecureStorageAdapter } from './src/StorageAdapter';
import * as fs from 'fs';

// Adapter zrzucający klucze na dysk, żeby przetrwały restart procesu
class FileStorageAdapter implements SecureStorageAdapter {
    constructor(private user: string) {}
    async savePrivateKey(key: Uint8Array) { fs.writeFileSync(`${this.user}-priv.bin`, key); }
    async getPrivateKey() { return fs.existsSync(`${this.user}-priv.bin`) ? fs.readFileSync(`${this.user}-priv.bin`) : null; }
    async savePublicKey(key: Uint8Array) { fs.writeFileSync(`${this.user}-pub.bin`, key); }
    async getPublicKey() { return fs.existsSync(`${this.user}-pub.bin`) ? fs.readFileSync(`${this.user}-pub.bin`) : null; }
    async clearKeys() {}
}

async function runBob() {
    console.log("=== VEXTRO: BOB (ODBIORCA) ===");
    const bob = new CryptoVault();
    await bob.init(new FileStorageAdapter('bob'));
    
    if (!bob.isReady()) {
        await bob.generateIdentity();
        console.log("✅ Wygenerowano nową tożsamość Boba.");
    } else {
        console.log("✅ Wczytano istniejącą tożsamość Boba z dysku.");
    }

    const ws = new globalThis.WebSocket('ws://localhost:3001/ws');

    ws.onopen = () => {
        console.log("✅ Połączono z serwerem. Autoryzacja...");
        ws.send(JSON.stringify({ type: 'auth', userId: 'bob' }));
    };

    ws.onmessage = async (event) => {
        const payload = JSON.parse(event.data as string);

        if (payload.type === 'system' && payload.status === 'authenticated') {
            console.log("✅ Autoryzacja udana. Czekam na wiadomości...");
            console.log("🔴 TERAZ MOŻESZ ZABIĆ TEN PROCES (Ctrl+C), ABY ZASYMULOWAĆ OFFLINE.\n");
        }

        if (payload.type === 'message') {
            console.log(`\n📥 Odebrano zaszyfrowaną paczkę od: ${payload.senderId}`);
            
            try {
                // Wczytujemy z dysku klucz publiczny nadawcy (Alicji) do deszyfracji
                const alicePubKey = fs.readFileSync(`${payload.senderId}-pub.bin`);
                const receivedData = new Uint8Array(Buffer.from(payload.ciphertext, 'base64'));
                
                const decrypted = await bob.decryptMessage(receivedData, alicePubKey);
                console.log(`🔥 [SUKCES] Odszyfrowano: "${decrypted}"`);
                
                setTimeout(() => process.exit(0), 500);
            } catch (e) {
                console.error("❌ Błąd deszyfrowania:", e);
            }
        }
    };
}
runBob().catch(console.error);