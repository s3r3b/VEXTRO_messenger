# Rust/libsodium Android FFI

## Status

The MVP cryptographic implementation is exclusively `packages/crypto-rs`.
The crate now produces both an internal Rust library and an Android-compatible
`cdylib`. Its exported ABI is intentionally small and versioned.

## ABI

- `vextro_crypto_version`
- `vextro_generate_identity_keypair`
- `vextro_generate_signed_prekey`
- `vextro_generate_one_time_prekey`
- `vextro_sign`

All functions return an integer status code and write into caller-owned
buffers. A future Android module must keep private key buffers inside the
native boundary and expose only public bundles, signatures, ciphertext and
explicit operation results to React Native.

## Android build boundary

The Android build must compile this crate for `aarch64-linux-android` and
`x86_64-linux-android`, then package the resulting `libvextro_crypto_rs.so`
under the matching `jniLibs` ABI directories. The linker must come from the
same Android NDK used by Gradle.

No Matrix, external crypto SDK, Node native module or JavaScript crypto
fallback is allowed.
