import { View, Text, StyleSheet } from 'react-native';
export default function SetupScreen() {
  return <View style={styles.container}><Text style={styles.text}>VEXTRO SETUP (Brak Danych)</Text></View>;
}
const styles = StyleSheet.create({ container: { flex: 1, backgroundColor: '#121212', justifyContent: 'center', alignItems: 'center'}, text: { color: '#9D4EDD' } });