# VEXTRO Threat Model

## Chronione zasoby

- Tresc wiadomosci.
- Prywatne identity keys, signed prekeys, one-time prekeys i klucze sesji.
- Integralnosc i autentycznosc wiadomosci.
- Powiazanie wiadomosci z wlasciwym nadawca i odbiorca.
- Trwalosc outbox, inbox, sesji i historii.

## Przeciwnicy

- Zlosliwy lub przejety serwer aplikacji.
- Administrator PostgreSQL.
- Atakujacy majacy dostep do ciphertextow z bazy lub backupow.
- Atakujacy modyfikujacy, opozniajacy, usuwajacy lub powtarzajacy pakiety.
- Aktywny MITM przy pierwszym kontakcie.
- Osoba probujaca podszyc sie pod `accountId`.
- Utracone, odinstalowane lub uszkodzone urzadzenie.
- Crash aplikacji, ubity proces i utrata polaczenia.

## Poza modelem

- Root, malware lub debugger kontrolujacy odblokowane urzadzenie.
- Screenshoty i reczne skopiowanie tresci przez uzytkownika.
- Kompromitacja aplikacji podczas odblokowanej sesji.
- Odzyskanie kluczy bez skonfigurowanego backupu.
- Analiza zaawansowanych metadanych przez zewnetrznego obserwatora sieci.

## Cele bezpieczenstwa

1. Serwer nie moze odszyfrowac tresci.
2. Modyfikacja ciphertextu lub naglowka jest wykrywana.
3. Replay wiadomosci jest odrzucany.
4. Zmiana identity key peer'a jest wykrywana i blokuje lub ostrzega przed rozmowa.
5. Prywatne klucze nie trafiaja do serwera, AsyncStorage ani logow.
6. Niepoprawna wiadomosc nie niszczy trwale stanu sesji ani OPK.
7. Sama znajomosc `accountId` nie wystarcza do uwierzytelnienia urzadzenia.

## Krytyczne zalozenia

- Biblioteka protokolu E2EE jest audytowana albo jej uzycie zostaje ograniczone do jasno zdefiniowanych prymitywow.
- Storage Androida zapewnia poufnosc kluczy prywatnych.
- Serwer nie otrzymuje hasla ani klucza backupu.
- Klient weryfikuje podpisy, identity key i integralnosc kopert.

## Znane ograniczenia

Serwer nadal widzi identyfikatory routingu, czasy, rozmiary, liczbe wiadomosci, publiczne bundle i fakt komunikacji. MVP chroni tresc oraz klucze, nie zapewnia pelnej anonimowosci metadanych.
