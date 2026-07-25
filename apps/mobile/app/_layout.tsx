import 'react-native-get-random-values';
import { useEffect } from 'react';
import { Stack, useRouter, useSegments } from 'expo-router';
import { StatusBar } from 'expo-status-bar';
import { useVextroStore } from '../src/core/store';
import { clientEngine } from '../src/core/VextroClient';

export default function RootLayout() {
  const { userId, serverIp, isEnclaveReady, setEnclaveReady, addMessage } = useVextroStore();
  const segments = useSegments();
  const router = useRouter();

  useEffect(() => {
    // Dodane jawne typowanie: senderId: string, plaintext: string
    clientEngine.setOnMessageListener((senderId: string, plaintext: string) => {
      addMessage({
        id: Date.now().toString() + Math.random().toString(),
        senderId,
        text: plaintext,
        timestamp: Date.now()
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
      if (isAuthGroup || segments.length === 0) router.replace('/(chat)');
    }
  }, [userId, serverIp, isEnclaveReady, segments]);

  return (
    <>
      <StatusBar style="light" />
      <Stack screenOptions={{ 
        headerStyle: { backgroundColor: '#1A1A1A' },
        headerTintColor: '#9D4EDD',
        headerTitleStyle: { fontWeight: 'bold', letterSpacing: 1 },
        contentStyle: { backgroundColor: '#121212' }
      }}>
        <Stack.Screen name="(auth)" options={{ headerShown: false }} />
        <Stack.Screen name="(chat)" options={{ headerShown: false }} />
      </Stack>
    </>
  );
}