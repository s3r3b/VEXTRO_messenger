# VEXTRO Server Privacy Contract

## Serwer moze przechowywac

- Opaque `accountId` i `deviceId` potrzebne do routingu.
- Publiczne identity keys i prekey bundle.
- `messageId`, nadawce, odbiorce, czas, rozmiar i status dostarczenia.
- Ciphertext wiadomosci i zaszyfrowany backup.
- Logi techniczne bez plaintextu i prywatnych kluczy.

## Serwer nie moze przechowywac

- Plaintextu wiadomosci.
- Prywatnych identity keys, SPK, OPK ani kluczy sesji.
- Hasla lub klucza backupu.
- Jawnej historii rozmow jako tresci.

## Dostarczanie

Serwer realizuje at-least-once delivery:

1. Przyjmuje wiadomosc z unikalnym `messageId`.
2. Zapisuje ciphertext przed potwierdzeniem przyjecia.
3. Wysyla go online albo przechowuje offline.
4. Moze dostarczyc te sama paczke ponownie.
5. Usuwa ja dopiero po ACK oznaczajacym trwaly zapis klienta.
6. Deduplikuje po `messageId`.

Brak ACK nie oznacza, ze wiadomosc zostala trwale zapisana na urzadzeniu.

## Granice zaufania

Serwer moze blokowac, opozniac, powtarzac lub usuwac ciphertext. Klient musi wykrywac modyfikacje przez uwierzytelnienie kryptograficzne, a brak dostarczenia pokazywac jako stan aplikacji.

## Operacyjne wymagania

- WSS/TLS w produkcji.
- Walidacja typow komunikatow i limit rozmiaru.
- Rate limiting.
- Sekrety poza repozytorium.
- Retencja ciphertextow opisana w polityce produktu.
- Brak logowania payloadow i plaintextu.
