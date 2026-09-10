import * as SecureStore from 'expo-secure-store';
import { requireNativeModule } from 'expo-modules-core';

import type { PrekeyBundle } from '@vextro/crypto';

interface VextroCryptoNativeModule {
  createPrekeyBundle(opkCount: number): Promise<string>;
  initOutboundSession(bundleJson: string, identitySecret: string): Promise<string>;
  initInboundSession(initialMessageJson: string, keysJson: string): Promise<string>;
  encryptMessage(sessionStateJson: string, plaintext: string): Promise<string>;
  decryptMessage(sessionStateJson: string, payloadJson: string): Promise<string>;
}

const NativeCrypto = requireNativeModule<VextroCryptoNativeModule>('VextroCrypto');
const SESSION_PREFIX = 'vextro.crypto.session.';
const KEYS_STORE_KEY = 'vextro.crypto.prekey-secrets';

type FacadePair = [string, string];

function parsePair(result: string): FacadePair {
  const value: unknown = JSON.parse(result);
  if (!Array.isArray(value) || value.length !== 2 || !value.every((item) => typeof item === 'string')) {
    throw new Error('Invalid crypto facade response');
  }
  return value as FacadePair;
}

export async function createPrekeyBundle(opkCount = 50): Promise<PrekeyBundle> {
  const [bundleJson, secretKeysJson] = parsePair(await NativeCrypto.createPrekeyBundle(opkCount));
  await SecureStore.setItemAsync(KEYS_STORE_KEY, secretKeysJson);
  return JSON.parse(bundleJson) as PrekeyBundle;
}

export async function initOutboundSession(
  bobBundle: PrekeyBundle,
  myIdentitySecret: string,
  sessionId: string,
): Promise<{ stateJson: string; initialMessageJson: string }> {
  const [stateJson, initialMessageJson] = parsePair(
    await NativeCrypto.initOutboundSession(JSON.stringify(bobBundle), myIdentitySecret),
  );
  await saveSessionState(sessionId, stateJson);
  return { stateJson, initialMessageJson };
}

export async function initInboundSession(
  initialMessageJson: string,
  sessionId: string,
): Promise<{ stateJson: string; decryptedText: string }> {
  const keysJson = await SecureStore.getItemAsync(KEYS_STORE_KEY);
  if (!keysJson) {
    throw new Error('Prekey secrets are not available in SecureStore');
  }
  const [stateJson, decryptedText] = parsePair(
    await NativeCrypto.initInboundSession(initialMessageJson, keysJson),
  );
  await saveSessionState(sessionId, stateJson);
  return { stateJson, decryptedText };
}

export async function encryptMessage(
  sessionId: string,
  plaintext: string,
): Promise<{ stateJson: string; payloadJson: string }> {
  const stateJson = await loadSessionState(sessionId);
  const [newStateJson, payloadJson] = parsePair(
    await NativeCrypto.encryptMessage(stateJson, plaintext),
  );
  await saveSessionState(sessionId, newStateJson);
  return { stateJson: newStateJson, payloadJson };
}

export async function decryptMessage(
  sessionId: string,
  payloadJson: string,
): Promise<{ stateJson: string; decryptedText: string }> {
  const stateJson = await loadSessionState(sessionId);
  const [newStateJson, decryptedText] = parsePair(
    await NativeCrypto.decryptMessage(stateJson, payloadJson),
  );
  await saveSessionState(sessionId, newStateJson);
  return { stateJson: newStateJson, decryptedText };
}

export async function saveSessionState(sessionId: string, stateJson: string): Promise<void> {
  await SecureStore.setItemAsync(`${SESSION_PREFIX}${sessionId}`, stateJson);
}

export async function loadSessionState(sessionId: string): Promise<string> {
  const stateJson = await SecureStore.getItemAsync(`${SESSION_PREFIX}${sessionId}`);
  if (!stateJson) {
    throw new Error(`Session state not found: ${sessionId}`);
  }
  return stateJson;
}

export async function clearSessionState(sessionId: string): Promise<void> {
  await SecureStore.deleteItemAsync(`${SESSION_PREFIX}${sessionId}`);
}
