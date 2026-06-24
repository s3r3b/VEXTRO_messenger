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
    console.log("=== START TESTU ROUTINGU E2EE (KOPERTA JSON) ===");

    // 1. Inicjalizujemy uczestników
    const alice = new CryptoVault();
    const bob = new CryptoVault();

    await alice.init(new MockRAMStorage());
    await bob.init(new MockRAMStorage());
    await alice.generateIdentity();
    await bob.generateIdentity();

    // 2. Podłączamy Boba (Odbiorcę)
    const wsBob = new globalThis.WebSocket('ws://localhost:3001/ws');

    // Zauważ, że usunąłem ws.binaryType = 'arraybuffer'. Teraz lecimy na stringach (JSON)

    wsBob.onopen = () => {
        console.log("[BOB] Gniazdo otwarte. Wysyłam żądanie autoryzacji...");
        wsBob.send(JSON.stringify({ type: 'auth', userId: 'bob' }));
    };

    wsBob.onmessage = async (event) => {
        const payload = JSON.parse(event.data as string);

        // Krok 3: Bob zalogowany -> Podłączamy Alicję (Nadawcę)
        if (payload.type === 'system' && payload.status === 'authenticated') {
            console.log("[BOB] Autoryzacja udana. Czekam na wiadomości...\n");

            const wsAlice = new globalThis.WebSocket('ws://localhost:3001/ws');

            wsAlice.onopen = () => {
                console.log("[ALICJA] Gniazdo otwarte. Wysyłam żądanie autoryzacji...");
                wsAlice.send(JSON.stringify({ type: 'auth', userId: 'alice' }));
            };

            wsAlice.onmessage = async (aliceEvent) => {
                const alicePayload = JSON.parse(aliceEvent.data as string);

                // Krok 4: Alicja zalogowana -> Szyfruje i wysyła JSON-a
                if (alicePayload.type === 'system' && alicePayload.status === 'authenticated') {
                    console.log("[ALICJA] Autoryzacja udana.");

                    const message = "Tajne kody: Projekt VEXTRO działa przez sieć z nowym routingiem!";
                    console.log(`[ALICJA] Szyfruje: "${message}"`);

                    const encryptedBlob = await alice.encryptMessage(message, bob.publicKey!);

                    // KONWERSJA: Uint8Array -> Base64 (KRYTYCZNE DLA JSONA)
                    const base64Ciphertext = Buffer.from(encryptedBlob).toString('base64');

                    const envelope = {
                        type: 'message',
                        recipientId: 'bob', // Wskazujemy adresata dla Ślepego Serwera
                        ciphertext: base64Ciphertext
                    };

                    console.log(`[ALICJA] Wysyła Kopertę JSON (${base64Ciphertext.length} znaków Base64)...`);
                    wsAlice.send(JSON.stringify(envelope));
                }
            };
        }

        // Krok 5: Bob odbiera zaszyfrowaną wiadomość i deszyfruje
        if (payload.type === 'message') {
            console.log(`\n[SIEĆ] Gniazdo Boba odebrało paczkę od: ${payload.senderId}`);

            try {
                // KONWERSJA: Base64 -> Uint8Array
                const receivedData = new Uint8Array(Buffer.from(payload.ciphertext, 'base64'));

                const decrypted = await bob.decryptMessage(receivedData, alice.publicKey!);
                console.log(`[BOB] Sukces! Odszyfrowano: "${decrypted}"`);
                console.log("🔥 TEST ROUTINGU ZALICZONY: Krypto-silnik + Serwer JSON wymiata!");

                // Zamykamy wszystko bez żalu i wycieków pamięci
                wsBob.close();
                process.exit(0); // Wymuszamy zamknięcie procesu po udanym teście (wsAlice zamknie się w tle)
            } catch (e) {
                console.error("❌ BŁĄD: Odszyfrowywanie z sieci zawiodło:", e);
                process.exit(1);
            }
        }

        if (payload.type === 'error') {
            console.error("[ERROR Z SERWERA]:", payload.message);
        }
    };

    wsBob.onerror = (error) => {
        console.error("❌ Błąd połączenia wsBob. Czy serwer Fastify na pewno działa?", error);
    };
}

runNetworkTest().catch(console.error);