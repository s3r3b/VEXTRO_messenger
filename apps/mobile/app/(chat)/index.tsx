import { View, Text, StyleSheet } from 'react-native';
export default function ChatScreen() {
  return <View style={styles.container}><Text style={styles.text}>VEXTRO SECURE CHAT</Text></View>;
}
const styles = StyleSheet.create({ container: { flex: 1, backgroundColor: '#121212', justifyContent: 'center', alignItems: 'center'}, text: { color: '#00FF41' } });