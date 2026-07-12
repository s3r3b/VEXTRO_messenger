import 'react-native-get-random-values'; // ABSOLUTNIE KRYTYCZNE: Ten polifil musi być linijką nr 1!
import React, { useState, useEffect } from 'react';
import { StyleSheet, Text, View, TextInput, TouchableOpacity, ScrollView, SafeAreaView, KeyboardAvoidingView, Platform } from 'react-native';
import { clientEngine } from './src/core/VextroClient';

export default function App() {
  // UWAGA ARCHITEKTONICZNA: W React Native 'localhost' kieruje na telefon/emulator, a nie na komputer!
  // Musisz wpisać tutaj fizyczne IP swojego komputera w sieci LAN (np. 192.168.1.X)
  const [serverIp, setServerIp] = useState('192.168.');
  const [userId, setUserId] = useState('');
  const [isReady, setIsReady] = useState(false);

  const [targetId, setTargetId] = useState('');
  const [message, setMessage] = useState('');
  const [chatLogs, setChatLogs] = useState<string[]>([]);

  useEffect(() => {
    // Nasłuchiwanie na przychodzące, ODSZYFROWANE Matrioszki z naszego silnika
    clientEngine.setOnMessageListener((senderId, plaintext) => {
      setChatLogs(prev => [...prev, `[📥 ${senderId}]: ${plaintext}`]);
    });
  }, []);

  const handleLogin = async () => {
    if (!userId || !serverIp || serverIp === '192.168.') return;
    try {
      await clientEngine.init(userId, serverIp);
      setIsReady(true);
      setChatLogs(prev => [...prev, `[SYSTEM] Enklawa załadowana. Zalogowano jako: ${userId}`]);
    } catch (error) {
      console.error(error);
      setChatLogs(prev => [...prev, `[BŁĄD KRYTYCZNY] ${error}`]);
    }
  };

  const handleSend = () => {
    if (!targetId || !message) return;
    clientEngine.sendMessage(targetId, message);
    setChatLogs(prev => [...prev, `[📤 DO ${targetId}]: ${message}`]);
    setMessage('');
  };

  if (!isReady) {
    return (
      <SafeAreaView style={styles.container}>
        <View style={styles.authBox}>
          <Text style={styles.title}>VEXTRO<Text style={styles.neonOrange}>_CORE</Text></Text>
          <TextInput
            style={styles.input}
            placeholder="IP Serwera LAN (np. 192.168.0.15)"
            placeholderTextColor="#666"
            value={serverIp}
            onChangeText={setServerIp}
          />
          <TextInput
            style={styles.input}
            placeholder="Twój identyfikator (np. alicja)"
            placeholderTextColor="#666"
            value={userId}
            onChangeText={setUserId}
          />
          <TouchableOpacity style={styles.buttonPurple} onPress={handleLogin}>
            <Text style={styles.buttonText}>INICJALIZUJ ENKLAWĘ</Text>
          </TouchableOpacity>
        </View>
      </SafeAreaView>
    );
  }

  return (
    <SafeAreaView style={styles.container}>
      <KeyboardAvoidingView behavior={Platform.OS === 'ios' ? 'padding' : 'height'} style={{ flex: 1 }}>
        <View style={styles.header}>
          <Text style={styles.title}>VEXTRO<Text style={styles.neonPurple}>_LIVE</Text></Text>
          <Text style={styles.subtitle}>E2EE Active | User: {userId}</Text>
        </View>

        <ScrollView style={styles.chatArea}>
          {chatLogs.map((log, index) => (
            <Text key={index} style={styles.logText}>{log}</Text>
          ))}
        </ScrollView>

        <View style={styles.controlPanel}>
          <TextInput
            style={[styles.input, { marginBottom: 10 }]}
            placeholder="ID Odbiorcy (np. bob)"
            placeholderTextColor="#666"
            value={targetId}
            onChangeText={setTargetId}
          />
          <View style={styles.row}>
            <TextInput
              style={[styles.input, { flex: 1, marginRight: 10 }]}
              placeholder="Tajny ładunek..."
              placeholderTextColor="#666"
              value={message}
              onChangeText={setMessage}
            />
            <TouchableOpacity style={styles.buttonOrange} onPress={handleSend}>
              <Text style={styles.buttonText}>WYŚLIJ</Text>
            </TouchableOpacity>
          </View>
        </View>
      </KeyboardAvoidingView>
    </SafeAreaView>
  );
}

const styles = StyleSheet.create({
  container: {
    flex: 1,
    backgroundColor: '#121212', // Matte Black / Charcoal
  },
  authBox: {
    flex: 1,
    justifyContent: 'center',
    padding: 30,
  },
  title: {
    fontSize: 32,
    fontWeight: '900',
    color: '#E0E0E0',
    letterSpacing: 2,
    marginBottom: 30,
    textAlign: 'center',
  },
  subtitle: {
    color: '#888',
    fontSize: 12,
    textAlign: 'center',
    marginTop: 5,
  },
  neonPurple: { color: '#9D4EDD' },
  neonOrange: { color: '#FF7900' },
  input: {
    backgroundColor: '#1E1E1E',
    color: '#FFF',
    padding: 15,
    borderRadius: 8,
    borderWidth: 1,
    borderColor: '#333',
    marginBottom: 15,
    fontSize: 16,
  },
  buttonPurple: {
    backgroundColor: '#9D4EDD',
    padding: 15,
    borderRadius: 8,
    alignItems: 'center',
    shadowColor: '#9D4EDD',
    shadowOffset: { width: 0, height: 0 },
    shadowOpacity: 0.8,
    shadowRadius: 10,
  },
  buttonOrange: {
    backgroundColor: '#FF7900',
    padding: 15,
    borderRadius: 8,
    justifyContent: 'center',
    alignItems: 'center',
    shadowColor: '#FF7900',
    shadowOffset: { width: 0, height: 0 },
    shadowOpacity: 0.8,
    shadowRadius: 10,
  },
  buttonText: {
    color: '#FFF',
    fontWeight: 'bold',
    letterSpacing: 1,
  },
  header: {
    padding: 20,
    borderBottomWidth: 1,
    borderBottomColor: '#222',
  },
  chatArea: {
    flex: 1,
    padding: 20,
  },
  logText: {
    color: '#00FF41', // Matrix green for debug visibility
    fontFamily: Platform.OS === 'ios' ? 'Courier' : 'monospace',
    marginBottom: 8,
    fontSize: 13,
  },
  controlPanel: {
    padding: 20,
    backgroundColor: '#1A1A1A',
    borderTopWidth: 1,
    borderTopColor: '#333',
  },
  row: {
    flexDirection: 'row',
  }
});