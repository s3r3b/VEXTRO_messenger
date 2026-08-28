import { NativeModules, Platform } from 'react-native';

interface MatrixCryptoNativeModule {
  isAvailable(): Promise<boolean>;
  initialize(): Promise<void>;
}

const nativeModule = NativeModules.MatrixCrypto as MatrixCryptoNativeModule | undefined;

export async function isMatrixCryptoAvailable(): Promise<boolean> {
  if (Platform.OS !== 'android' || !nativeModule) return false;
  return nativeModule.isAvailable();
}

export async function initializeMatrixCrypto(): Promise<void> {
  if (Platform.OS !== 'android' || !nativeModule) {
    throw new Error('MATRIX_CRYPTO_UNAVAILABLE');
  }
  await nativeModule.initialize();
}