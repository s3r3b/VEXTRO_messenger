# VEXTRO MVP Scope

## Cel

Dostarczyc pierwsza wersje komunikatora Android, ktora pozwala dwu uzytkownikom wymieniac wiadomosci tekstowe 1:1 przez serwer relay. Tresc wiadomosci i prywatne klucze pozostaja poza serwerem.

## Platforma

- Android APK do testow oraz AAB dla Google Play Internal Testing.
- Webapp jest poza zakresem MVP.

## Funkcje MVP

- Utworzenie lokalnej tozsamosci i jednego urzadzenia.
- Losowy, niezgadywalny `accountId`.
- Rejestracja publicznego prekey bundle.
- Rozmowa 1:1.
- Wysylanie i odbieranie tekstu.
- Dostarczanie online i offline.
- Reconnect po utracie sieci.
- Lokalna historia wiadomosci.
- Stany: pending, sent, delivered, failed.
- Weryfikacja identity key rozmowcy.
- Zaszyfrowany backup i restore tozsamosci.

## Poza MVP

- Grupy.
- Zalaczniki i multimedia.
- Audio i video.
- Wiele urzadzen dla jednego konta.
- Pelna anonimowosc metadanych.
- Wyszukiwanie po stronie serwera.
- Edycja i usuwanie wiadomosci.
- Publiczne odzyskiwanie przez e-mail lub SMS.

## Zalozenia

- Jedno aktywne urzadzenie na konto.
- Serwer moze znac routing i metadane opisane w `SERVER_PRIVACY_CONTRACT.md`.
- Utrata urzadzenia bez backupu oznacza utrate dostepu do lokalnych kluczy i historii.
- Klucze sa w RAM tylko przez czas operacji kryptograficznej; nie da sie wykonac szyfrowania bez chwilowego uzycia pamieci.

## Definicja sukcesu

Uzytkownik A wysyla tekst do B, B moze go odczytac online lub po pozniejszym polaczeniu, a restart, crash, duplikat pakietu lub chwilowa utrata sieci nie powoduje utraty wiadomosci ani kluczy.
