# VEXTRO Stage 0 Decisions

Status: accepted baseline for implementation.

## D-001 Platform

Android-first. Deliver a signed APK for device testing and an AAB for Google Play Internal Testing. Web is not part of MVP.

## D-002 Product scope

MVP is one-to-one text messaging, one active device per account, online/offline delivery, reconnect, local encrypted history, identity verification and encrypted recovery backup.

## D-003 Account identity

Use a random opaque `accountId`, a `deviceId` and a device identity key. A plain account ID is never an authentication credential.

## D-004 E2EE protocol
Use the VEXTRO protocol implemented exclusively in the Rust crate under `packages/crypto-rs`, with libsodium as its cryptographic backend. The protocol version is `libsodium-rust-v1`. The wire envelope, authenticated headers, session state, replay handling and prekey consumption must be specified and tested before release.

## D-005 Libsodium role
Rust/libsodium is the only cryptographic implementation for the MVP. JavaScript/TypeScript may validate envelopes and manage delivery, but must not generate, store or use private cryptographic keys. Direct primitive calls are not sufficient by themselves; all calls must be behind the versioned VEXTRO Rust protocol API.

## D-006 Recovery

Use an encrypted backup or recovery phrase that restores the same identity. The server may store only backup ciphertext. The user controls the password or recovery secret.

## D-007 Blind server boundary

The server is blind to plaintext, private keys and session keys. It may see routing IDs, timing, sizes, public bundles, ciphertext and delivery state. Strong metadata anonymity is out of scope.

## D-008 Delivery guarantee

Use at-least-once delivery with stable `messageId`, durable outbox/inbox, ACK after local durable write, retry and client-side deduplication.

## D-009 Release gate

No release while plaintext or private keys appear in server storage, AsyncStorage or production logs; while authentication trusts only an account ID; or while messages/OPKs can be lost because of a missing ACK or non-atomic operation.

## Implementation constraint

The Rust/libsodium backend must be integrated through a verified Android native bridge. Node-only native packages must not be imported into the mobile bundle. Until the bridge exists, the client must refuse plaintext encryption rather than fall back to JavaScript crypto or plaintext.

## Open decisions intentionally deferred

- Exact Rust Android FFI and storage integration strategy.
- Backup retention and whether local message history is included in backup.
- Exact retention period for offline ciphertext.
- Exact UI wording for identity change and recovery warnings.
