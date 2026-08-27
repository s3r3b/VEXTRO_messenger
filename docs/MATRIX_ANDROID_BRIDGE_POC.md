# Matrix Android Bridge PoC

## Cel

Uruchomic Matrix Rust SDK crypto na Androidzie przez oficjalne `matrix-sdk-crypto-ffi` i UniFFI, a z React Native wystawic tylko wysokopoziomowy kontrakt. Node.js binding nie jest uzywany.

## Licencja

`matrix-sdk-crypto-ffi` i Matrix Rust SDK deklaruja Apache-2.0. Przed dystrybucja trzeba wygenerowac liste third-party notices dla wszystkich zaleznosci Rust i Android.

## Zakres PoC

- jeden proces Android;
- jeden `OlmMachine`;
- jedna lokalna baza stanu;
- inicjalizacja po restarcie;
- przekazanie szyfrowanego envelope do TypeScript;
- brak integracji z UI i produkcyjnym relayem na tym etapie.

## Granica warstw

```text
TypeScript: MatrixCryptoClient
    -> React Native NativeModules/TurboModule
Kotlin: MatrixCryptoModule
    -> generated UniFFI Kotlin bindings
Rust: matrix-sdk-crypto-ffi + matrix-sdk-sqlite
    -> Android .so per ABI
```

## Artefakty Android

Wymagane ABI dla MVP:

- `arm64-v8a` - fizyczne telefony;
- `x86_64` - emulator CI/development;
- `armeabi-v7a` tylko jesli minimalny zakres urzadzen tego wymaga.

Android nie jest dostarczany w sprawdzonym release ZIP `MatrixSDKCryptoFFI.zip`; ten asset zawiera xcframework dla Apple. Android `.so` trzeba zbudowac z `matrix-sdk-crypto-ffi` przez Cargo. Oczekiwana nazwa biblioteki z aktualnego FFI to `libmatrix_sdk_crypto_ffi.so`; finalna nazwa i sposob ladowania musza odpowiadac wygenerowanym bindingom Kotlin. Nie kopiowac plikow `.so` z niezweryfikowanego zrodla.

## Wymagania lokalne

- Rust toolchain;
- Android SDK;
- Android NDK;
- targety Rust `aarch64-linux-android` i `x86_64-linux-android`;
- linker Clang z tego samego NDK;
- UniFFI generator zgodny z wersja FFI;
- Gradle/AGP zgodne z wygenerowanym Kotlin API.

Aktualny dev container nie ma skonfigurowanego `ANDROID_HOME`, `ANDROID_SDK_ROOT`, `ANDROID_NDK` ani Javy, dlatego budowa `.so` i APK nie jest jeszcze mozliwa.

## Zweryfikowany build FFI

Na podstawie oficjalnego `uniffi.toml`:

- Kotlin package: `org.matrix.rustcomponents.sdk.crypto`;
- cdylib: `matrix_sdk_crypto_ffi`;
- Android target przykladowy: `aarch64-linux-android`;
- linker: Clang z tego samego Android NDK;
- generator Kotlin musi byc uruchomiony z tego samego commita FFI co Cargo build.

Release `matrix-sdk-crypto-ffi-0.17.0` ma jeden asset Apple-only, wiec nie jest zrodlem Android `.so`.

## Kolejnosc PoC

1. Zamrozic commit Matrix Rust SDK i wersje UniFFI.
2. Zainstalowac NDK i dodac targety Rust.
3. Zbudowac FFI dla `arm64-v8a` i `x86_64`.
4. Wygenerowac Kotlin bindings z tego samego commita.
5. Dodac `.so` i bindings do Android source set, nie do JS bundle.
6. Dodac Kotlin wrapper, ktory kontroluje lifecycle i mapuje bledy.
7. Dodac persistence directory w app sandbox oraz klucz bazy przez Android Keystore.
8. Dodac minimalny React Native module.
9. Zbudowac release APK z R8 i sprawdzic ladowanie biblioteki.
10. Wykonac restart/force-stop i sprawdzic odczyt stanu.

## Zakaz fallbacku

Jesli native FFI nie jest dostepne, modul ma zwrocic blad `MATRIX_CRYPTO_UNAVAILABLE`. Nie wolno przechodzic na stary statyczny `crypto_box`, niezatwierdzony SDK ani plaintext.

## Kryteria akceptacji

- APK release startuje na `arm64-v8a`;
- FFI laduje sie bez `UnsatisfiedLinkError`;
- pierwszy `OlmMachine` tworzy stan;
- stan po restarcie jest odczytywany;
- prywatny stan nie opuszcza sandboxa Androida;
- TypeScript dostaje tylko wynik operacji i zaszyfrowane koperty;
- R8 nie usuwa klas UniFFI ani metod JNI;
- brak prywatnych kluczy i plaintextu w logach;
- wszystkie third-party licenses sa zebrane przed release.

## Otwarte decyzje

- czy VEXTRO przechodzi na pelny Matrix Client-Server API;
- czy relay VEXTRO implementuje wymagane operacje Matrix to-device/sync;
- czy storage FFI bedzie uzywal `matrix-sdk-sqlite`, czy aplikacyjnego wrappera;
- minimalna wersja Androida i lista ABI;
- wersja SDK Matrix przypieta do pierwszego release.
