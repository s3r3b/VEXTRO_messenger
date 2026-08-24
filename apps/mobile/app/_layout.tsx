import 'react-native-get-random-values';
import { useEffect } from 'react';
import { Stack, useRouter, useSegments } from 'expo-router';
import { StatusBar } from 'expo-status-bar';
import { useVextroStore } from '../src/core/store';
import { clientEngine } from '../src/core/VextroClient';
import type { EncryptedMessageEnvelope } from '@vextro/crypto';

export default function RootLayout() {
  const { userId, serverIp, isEnclaveReady, setEnclaveReady, addMessage } = useVextroStore();
  const segments = useSegments();
  const router = useRouter();

  useEffect(() => {
    // Dodane jawne typowanie: senderId: string, plaintext: string
    clientEngine.setOnMessageListener((envelope: EncryptedMessageEnvelope) => {
      addMessage({
        id: envelope.messageId,
        senderId: envelope.sender.accountId,
        text: '[Wiadomosc zaszyfrowana - deszyfrowanie w Etapie 2]',
        timestamp: envelope.createdAt
      });
    });
  }, []);

  useEffect(() => {
    const isAuthGroup = segments[0] === '(auth)';
    
    if (!userId || !serverIp) {
      if (!isAuthGroup) router.replace('/(auth)/setup');
    } else if (!isEnclaveReady) {
      clientEngine.init(userId, serverIp)
        .then(() => setEnclaveReady(true))
        // Dodane jawne typowanie: err: unknown
        .catch((err: unknown) => console.error("KRYTYCZNY BŁĄD ENKLAWY:", err));
    } else {
      if (isAuthGroup) router.replace('/(chat)');
    }
  }, [userId, serverIp, isEnclaveReady, segments]);

  return (
    <>
      <StatusBar style="light" />
      <Stack screenOptions={{ 
        headerStyle: { backgroundColor: '#1A1A1A' },
        headerTintColor: '#9D4EDD',
        headerTitleStyle: { fontWeight: 'bold' },
        contentStyle: { backgroundColor: '#121212' }
      }}>
        <Stack.Screen name="(auth)" options={{ headerShown: false }} />
        <Stack.Screen name="(chat)" options={{ headerShown: false }} />
      </Stack>
    </>
  );
}