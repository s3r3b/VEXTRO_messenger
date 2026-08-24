# VEXTRO Identity and Recovery

## Tozsamosc

- `accountId` jest losowym opaque ID, nie numerem telefonu ani adresem e-mail.
- `deviceId` identyfikuje jedno urzadzenie.
- Identity Key jest generowany lokalnie i pozostaje stabilny dla danego konta.
- Serwer uznaje urzadzenie dopiero po dowodzie posiadania odpowiedniego klucza.
- Pakiet `auth` zawierajacy samo `userId` jest niewystarczajacy.

## Pierwszy kontakt

Klient pobiera bundle peer'a, weryfikuje podpis signed prekey i zapisuje identity key jako pinned key. Przy pierwszym kontakcie uzytkownik powinien miec dostep do fingerprintu lub QR. Zmiana pinned identity key wymaga jawnej decyzji uzytkownika i domyslnie blokuje wysylanie.

## Rotacja

Signed prekey jest rotowany wedlug ustalonego okresu lub po podejrzeniu kompromitacji. Nowa wersja bundle nie moze usuwac kluczy potrzebnych istniejacym sesjom. OPK sa wydawane atomowo i nie moga byc zwrocone dwom inicjatorom.

## Backup

- Backup przechowuje zaszyfrowany material potrzebny do odzyskania tozsamosci.
- Klucz backupu jest wyprowadzany z hasla uzytkownika przez Argon2id.
- Dane sa szyfrowane i uwierzytelniane przez AEAD.
- Format backupu ma wersje i parametry KDF.
- Serwer moze przechowywac tylko ciphertext backupu.
- Haslo i klucz backupu nie sa wysylane na serwer.

## Restore

Restore odtwarza te sama tozsamosc tylko po poprawnym zweryfikowaniu backupu. Po restore nowe urzadzenie jest traktowane zgodnie z ograniczeniem MVP jednego urzadzenia; poprzednie urzadzenie powinno zostac uniewaznione lub jawnie zastapione.

## Utrata danych

Bez backupu utrata urzadzenia oznacza utrate prywatnych kluczy i mozliwosci odszyfrowania historii. Aplikacja musi pokazac ten fakt przed zakonczeniem konfiguracji. Pelna historia moze zostac odzyskana tylko wtedy, gdy jest objeta backupem albo pozostaje dostepna na tym samym urzadzeniu.
