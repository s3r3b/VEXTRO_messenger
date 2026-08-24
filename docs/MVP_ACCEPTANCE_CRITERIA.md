# VEXTRO MVP Acceptance Criteria

## Funkcjonalne

- Dwa urzadzenia tworza rozmowe 1:1.
- A wysyla tekst, B go odszyfrowuje.
- Wiadomosc dziala online i po pozniejszym polaczeniu offline.
- Historia jest dostepna po restarcie aplikacji.
- Reconnect nie wymaga recznego ponownego wysylania wiadomosci.

## Kryptograficzne

- Serwer nie potrafi odszyfrowac ciphertextu.
- Niepoprawny podpis bundle jest odrzucany.
- Zmiana pinned identity key daje ostrzezenie lub blokade.
- Modyfikacja ciphertextu, AAD lub naglowka jest wykrywana.
- Replay tej samej wiadomosci jest odrzucany lub ignorowany idempotentnie.
- Bledny ciphertext nie spala OPK i nie niszczy sesji.
- Dwa rownolegle pobrania nie otrzymuja tego samego OPK.
- Prywatne klucze nie wystepuja w bazie serwera, AsyncStorage ani logach.

## Niezawodnosc

- Crash przed ACK nie powoduje utraty wiadomosci.
- Crash po zapisie i przed ACK nie tworzy duplikatu.
- Wiadomosc ma stabilny `messageId` przez wszystkie retry.
- Outbox przezywa restart procesu.
- Inbox i stan sesji sa zapisywane atomowo.
- Wiadomosc pozostaje na serwerze do ACK.

## Recovery

- Backup jest szyfrowany przez AEAD.
- Niepoprawne haslo nie ujawnia danych.
- Restore odtwarza te sama identity key.
- Przy braku backupu aplikacja jasno komunikuje ryzyko utraty dostepu.

## Release

- Typecheck, lint, build i testy integracyjne przechodza.
- APK/AAB dziala bez dev servera.
- Test na dwu emulatorach obejmuje online, offline, reconnect, restart i restore.
- Release build nie loguje plaintextu ani sekretow.
- Polityka prywatnosci i deklaracja Data Safety odpowiadaja rzeczywistemu zachowaniu aplikacji.

## Go / No-Go

Release jest NO-GO, jesli wystepuje choc jeden z ponizszych warunkow:

- serwer moze podszyc sie pod konto przez samo `accountId`;
- plaintext trafia do niezabezpieczonego storage;
- wiadomosc jest usuwana przed ACK;
- OPK moze zostac wydany dwom sesjom;
- restart traci klucz, sesje lub outbox;
- test modyfikacji ciphertextu przechodzi bez bledu;
- nie ma udokumentowanego backupu albo polityki utraty urzadzenia.
