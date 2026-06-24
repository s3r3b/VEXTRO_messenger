import { CryptoVault } from './src/CryptoVault';
import type { SecureStorageAdapter } from './src/StorageAdapter';

// Fałszywy magazyn RAM do testów
class MockRAMStorage implements SecureStorageAdapter {
    private priv: Uint8Array | null = null;
    private pub: Uint8Array | null = null;
    async savePrivateKey(key: Uint8Array) { this.priv = key; }
    async getPrivateKey() { return this.priv; }
    async savePublicKey(key: Uint8Array) { this.pub = key; }
    async getPublicKey() { return this.pub; }
    async clearKeys() { this.priv = null; this.pub = null; }
}

async function runNetworkTest() {
    console.log("=== START TESTU SIECIOWEGO E2EE ===");

    // 1. Inicjalizujemy uczestników
    const alice = new CryptoVault();
    const bob = new CryptoVault();

    await alice.init(new MockRAMStorage());
    await bob.init(new MockRAMStorage());
    await alice.generateIdentity();
    await bob.generateIdentity();

    // 2. Łączymy się ze Ślepym Serwerem
    const ws = new globalThis.WebSocket('ws://localhost:3001/ws');

    // Ważne: wymuszamy odbieranie surowych bajtów, nie jako string (blob)
    ws.binaryType = 'arraybuffer';

    ws.onopen = async () => {
        console.log("✅ Połączono ze Ślepym Serwerem!");

        const message = "Tajne kody: Projekt VEXTRO działa przez sieć.";
        console.log(`[ALICJA] Szyfruje: "${message}"`);

        // Alicja szyfruje surową wiadomość używając klucza publicznego Boba
        const encryptedBlob = await alice.encryptMessage(message, bob.publicKey!);

        console.log(`[ALICJA] Wysyła paczkę E2EE (${encryptedBlob.length} bajtów) przez WebSocket...`);
        ws.send(encryptedBlob);
    };

    ws.onmessage = async (event) => {
        // Serwer odbił wiadomość. Zamieniamy ArrayBuffer z powrotem na Uint8Array dla libsodium
        const receivedData = new Uint8Array(event.data as ArrayBuffer);
        console.log(`[SIEĆ] Odebrano paczkę z serwera: ${receivedData.length} bajtów`);

        try {
            // Odbiorcą jest Bob. Próbuje on odszyfrować surowe bajty kluczem publicznym Alicji
            const decrypted = await bob.decryptMessage(receivedData, alice.publicKey!);
            console.log(`[BOB] Sukces! Odszyfrowano: "${decrypted}"`);
            console.log("🔥 TEST SIECIOWY ZALICZONY: Architektura E2EE wymiata!");
        } catch (e) {
            console.error("❌ BŁĄD: Odszyfrowywanie z sieci zawiodło:", e);
        }

        // Kończymy test
        ws.close();
    };

    ws.onerror = (error) => {
        console.error("❌ Błąd połączenia WebSocket. Czy serwer na pewno działa?", error);
    };
}

runNetworkTest().catch(console.error);