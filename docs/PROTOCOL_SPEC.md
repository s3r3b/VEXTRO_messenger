# VEXTRO E2EE Protocol Baseline

## Decyzja

MVP uzywa wersjonowanego protokolu `libsodium-rust-v1`, implementowanego wylacznie w Rust w `packages/crypto-rs` z backendem libsodium. Nie uzywamy zewnetrznego SDK kryptograficznego.

Wywolania libsodium sa dostepne dla aplikacji tylko przez jawne API Rust protokolu. Samo `crypto_box` nie definiuje protokolu; koperta, AAD, sesja, replay i rotacja kluczy musza byc zaimplementowane i przetestowane w Rust.

## Material kluczowy

- Identity Key: dlugoterminowa para urzadzenia.
- Signed Prekey: srednioterminowy publiczny klucz podpisany Identity Key.
- One-Time Prekeys: pula publicznych kluczy z unikalnymi ID.
- Ephemeral key: krotkoterminowy klucz inicjatora sesji.
- Session state: trwaly stan ratchetu, licznikow i kluczy odbioru.

## Zasady

1. Serwer przechowuje tylko publiczny bundle.
2. Prywatny material kluczowy opuszcza urzadzenie tylko w zaszyfrowanym backupie uzytkownika.
3. Kazda wiadomosc ma unikalny `messageId` i numer ratchetu.
4. Koperta zawiera wersje protokolu, rozmowe, nadawce, odbiorce, sender device key lub ephemeral key, numer wiadomosci, opcjonalne `opkId` i ciphertext.
5. Naglowek jest uwierzytelniony jako AAD.
6. Replay i ponowne zaakceptowanie tego samego numeru sa odrzucane.
7. Wiadomosci poza kolejnoscia sa obslugiwane wedlug polityki biblioteki, bez nadpisania stanu sesji.
8. Bledny ciphertext nie usuwa OPK ani nie zatwierdza zmiany stanu.
9. OPK jest zuzywany atomowo po stronie serwera i uznawany za wykorzystany zgodnie z tranzakcja klienta.

## Format logiczny bundle

- `protocolVersion`
- `accountId`
- `deviceId`
- `identityKeyPublic`
- `signedPrekeyPublic`
- `signedPrekeySignature`
- lista `{ keyId, publicKey }` OPK
- `bundleVersion`
- `expiresAt` lub zasada rotacji

## Format logiczny wiadomosci

- `protocolVersion`
- `messageId`
- `conversationId`
- `senderAccountId`
- `senderDeviceId`
- `recipientAccountId`
- `recipientDeviceId`
- `sessionId`
- `messageNumber`
- `ephemeralPublicKey` dla inicjalizacji, jezeli wymagany
- `opkId` dla inicjalizacji, jezeli uzyty
- `ciphertext`
- `createdAt`

## Odpowiedzialnosc klienta

Klient szyfruje przed wyslaniem, trwale zapisuje outbox, weryfikuje bundle i identity key, odszyfrowuje dopiero po walidacji, trwale zapisuje rezultat oraz wysyla ACK po udanym zapisie.

## Odpowiedzialnosc serwera

Serwer routuje i przechowuje ciphertext. Nie deszyfruje, nie generuje kluczy prywatnych i nie moze uznac samego `accountId` za dowod tozsamosci.
