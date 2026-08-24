# VEXTRO Stage 0 Decisions

Status: accepted baseline for implementation.

## D-001 Platform

Android-first. Deliver a signed APK for device testing and an AAB for Google Play Internal Testing. Web is not part of MVP.

## D-002 Product scope

MVP is one-to-one text messaging, one active device per account, online/offline delivery, reconnect, local encrypted history, identity verification and encrypted recovery backup.

## D-003 Account identity

Use a random opaque `accountId`, a `deviceId` and a device identity key. A plain account ID is never an authentication credential.

## D-004 E2EE protocol

Use a Signal-compatible protocol with prekeys and Double Ratchet through an audited or established library compatible with React Native. Do not implement an unaudited custom ratchet for MVP.

## D-005 Libsodium role

`libsodium` may provide cryptographic primitives or be used by the selected protocol implementation. Direct `crypto_box` calls alone are not the application protocol.

## D-006 Recovery

Use an encrypted backup or recovery phrase that restores the same identity. The server may store only backup ciphertext. The user controls the password or recovery secret.

## D-007 Blind server boundary

The server is blind to plaintext, private keys and session keys. It may see routing IDs, timing, sizes, public bundles, ciphertext and delivery state. Strong metadata anonymity is out of scope.

## D-008 Delivery guarantee

Use at-least-once delivery with stable `messageId`, durable outbox/inbox, ACK after local durable write, retry and client-side deduplication.

## D-009 Release gate

No release while plaintext or private keys appear in server storage, AsyncStorage or production logs; while authentication trusts only an account ID; or while messages/OPKs can be lost because of a missing ACK or non-atomic operation.

## Open decisions intentionally deferred

- Exact Signal-compatible library and native integration strategy.
- Backup retention and whether local message history is included in backup.
- Exact retention period for offline ciphertext.
- Exact UI wording for identity change and recovery warnings.
