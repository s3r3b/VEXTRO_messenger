# LATEST STATUS

## Co robiliśmy w ostatnich krokach

1. Zrobiliśmy audyt projektu i ustaliliśmy główny blokujący element MVP: brak realnej native Android bridge dla Rust cryptography.
2. Potwierdziliśmy, że warstwa Rust (`packages/crypto-rs`) działa i ma testy: `cargo test` przechodzi dla lokalnych targetów, a odpowiedzialny moduł FFI / facade jest już zintegrowany z protokołem.
3. Znormalizowaliśmy typy i eksporty w pakiecie `packages/crypto`, usuwając aktywną ścieżkę legacy JS crypto fallback i zostawiając wymaganie na natywny moduł Android.
4. Zastosowaliśmy projektowe założenie: klient ma "fail closed" zamiast fallbacku do JS crypto; to jest zgodne z wymaganiem bezpieczeństwa i architekturą.
5. Przygotowaliśmy i zarejestrowaliśmy native bridge Android w Kotlin:
   - `VextroCryptoModule.kt`
   - `VextroCryptoPackage.kt`
   - wpięcie do `MainApplication.kt`
6. Zbudowaliśmy bibliotekę Rust dla Androida (`cargo-ndk` + targety `aarch64-linux-android` i `x86_64-linux-android`) i skopiowaliśmy `.so` do `apps/mobile/android/app/src/main/jniLibs`.
7. Wykryliśmy i usunęliśmy część problemów środowiskowych związanych z SDK / NDK: zainstalowaliśmy wymagane narzędzia Android, jednak okazało się, że katalog `/usr/lib/android-sdk` nie ma praw zapisu dla Gradle, co blokuje auto-install pakietów NDK potrzebnych przez React Native.

## Co robimy teraz

Obecnie blokuje nas środowisko Android / Gradle, a nie logika samego bridge’a:

- Gradle próbuje zainstalować NDK `27.1.12297006` automatycznie,
- ale SDK jest pod montowanym katalogiem bez odpowiednich uprawnień do zapisu,
- więc build nie dochodzi do kompilacji Kotlin / JNI i zatrzymuje się na konfiguracji projektu.

Czyli obecny główny problem to:

- ustawienie poprawnych praw do `/usr/lib/android-sdk`
- ewentualnie przeniesienie SDK / NDK do katalogu, do którego Gradle ma dostęp,
- potem ponowne uruchomienie `./gradlew :app:compileDebugKotlin`
- i dopiero wtedy sprawdzenie, czy `VextroCrypto` ładuje `.so` i czy native methods są poprawnie zarejestrowane.

## Co musimy zrobić w następnych krokach

1. Naprawić środowisko Android SDK/NDK (uprawnienia / lokalizacja).
2. Uruchomić pełny build Androida ponownie i sprawdzić, czy Kotlin/Gradle przechodzą.
3. Zweryfikować, że native module `VextroCrypto` jest widoczny w React Native (`NativeModules.VextroCrypto`).
4. Potwierdzić, że `libvextro_crypto_rs.so` ładuje się poprawnie na emulatorze / urządzeniu.
5. Zrobić end-to-end testy funkcji bridge’a:
   - `createPrekeyBundle`
   - `initOutboundSession`
   - `initInboundSession`
   - `encryptMessage`
   - `decryptMessage`
6. Po pomyślnej integracji wrócić do pełnego flow MVP komunikatora: auth, relay server, offline delivery, ACK i finalna walidacja pakietu.

## Jak wrócić do pracy po ponownym starcie

Gdy komputer zostanie odpalony ponownie, zacząć od:

1. `cd /workspace/apps/mobile/android`
2. sprawdzenie uprawnień do `ANDROID_SDK_ROOT` i katalogu SDK,
3. uruchomienie:
   - `export ANDROID_HOME=/usr/lib/android-sdk`
   - `export ANDROID_SDK_ROOT=/usr/lib/android-sdk`
   - `./gradlew :app:compileDebugKotlin`
4. jeśli jest błąd z NDK / uprawnieniami: naprawić środowisko, a nie wracać do aplikacyjnej logiki.

To jest aktualnie jedyny punkt, który jest na szczycie priorytetu. Po nim wracamy do natywnej integracji Rust z mobilnym klientem i dalszych testów secure flow.

## Dodatkowy kontekst

Projekt jest już na właściwym torze:

- Rust crypto ma faktyczną implementację,
- TypeScript/Expo jest już stabilny,
- server i protokół są zbudowane,
- brakuje dopiero finalnego połączenia natywnego bridge’a Android + zweryfikacji runtime.

To jest ostatni kluczowy fragment MVP, który trzeba dopiąć, zanim ruszymy w pełną integrację komunikatora.
