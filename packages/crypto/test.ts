import { CryptoVault } from './src/CryptoVault';
import type { SecureStorageAdapter } from './src/StorageAdapter';

// Wirtualny, fałszywy RAM-storage tylko na potrzeby testu w terminalu
class MockRAMStorage implements SecureStorageAdapter {
    private priv: Uint8Array | null = null;
    private pub: Uint8Array | null = null;

    async savePrivateKey(key: Uint8Array) { this.priv = key; }
    async getPrivateKey() { return this.priv; }
    async savePublicKey(key: Uint8Array) { this.pub = key; }
    async getPublicKey() { return this.pub; }
    async clearKeys() { this.priv = null; this.pub = null; }
}

async function runTest() {
    console.log("=== START TESTU E2EE VEXTRO ===\n");

    // 1. Inicjalizacja Alicji i Boba
    const alice = new CryptoVault();
    const bob = new CryptoVault();

    await alice.init(new MockRAMStorage());
    await bob.init(new MockRAMStorage());

    await alice.generateIdentity();
    await bob.generateIdentity();

    console.log("✅ Tożsamości wygenerowane pomyślnie.");
    console.log(`Klucz publiczny Boba ma długość: ${bob.publicKey?.length} bajtów\n`);

    // 2. Alicja szyfruje wiadomość do Boba
    const message = "Tajna wiadomość dla Boba: Spotykamy się o 21:00 w kryjówce.";
    console.log(`[ALICJA PISZE]: ${message}`);

    const encryptedData = await alice.encryptMessage(message, bob.publicKey!);
    console.log(`[SIEĆ / SERWER WIDZI]: <zaszyfrowany blob Uint8Array o długości ${encryptedData.length} bajtów>`);

    // 3. Bob odbiera i odszyfrowuje
    const decryptedMessage = await bob.decryptMessage(encryptedData, alice.publicKey!);
    console.log(`[BOB ODCZYTUJE]: ${decryptedMessage}\n`);

    if (message === decryptedMessage) {
        console.log("🔥 TEST ZALICZONY: Krypto-silnik działa i jest hermetyczny!");
    } else {
        console.error("❌ BŁĄD: Odszyfrowana wiadomość nie pasuje.");
    }
}

runTest().catch(console.error);