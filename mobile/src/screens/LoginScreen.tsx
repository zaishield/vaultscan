// LoginScreen — pairs the mobile app with a desktop session.
//
// Production flow:
//   1. User logs into the desktop portal with email + password + MFA.
//   2. Settings → Mobile shows a QR code containing
//        vaultscan-mobile://pair?api=<URL>&token=<short-lived-JWT>&tenant=<UUID>
//   3. User opens the mobile app, taps "Scan QR", scans the desktop's
//      code. The app extracts the params and stores them in
//      SecureStore via lib/session.ts.
//   4. The short-lived JWT is exchanged for the full mobile session
//      token via POST /api/v1/auth/mobile-pair (separate endpoint
//      that issues a longer-lived mobile token + records the device).
//
// This starter screen accepts manual entry of the three values for
// dev-mode testing. A separate QR-scan flow is wired in a follow-up.

import { useState } from 'react';
import { Text, TextInput, View, Pressable, StyleSheet } from 'react-native';
import { NativeStackScreenProps } from '@react-navigation/native-stack';

import { saveSession } from '../lib/session';
import { configureNotifications } from '../lib/notifications';
import { RootStackParamList } from '../../App';

type Props = NativeStackScreenProps<RootStackParamList, 'Login'>;

export function LoginScreen({ navigation }: Props) {
  const [apiBase, setAPIBase] = useState('https://api.vaultscan.zaishield.com');
  const [tenantId, setTenantId] = useState('');
  const [token, setToken] = useState('');
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  async function pair() {
    if (!apiBase || !tenantId || !token) {
      setError('all three fields required');
      return;
    }
    setBusy(true);
    setError(null);
    try {
      // Production exchanges the short-lived `token` here for a
      // longer-lived mobile session token. For the dev path we
      // accept the supplied token as-is.
      await saveSession({ apiBase, tenantId, userId: '', token });
      await configureNotifications();
      navigation.replace('Dashboard');
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  }

  return (
    <View style={styles.container}>
      <Text style={styles.heading}>Pair this device</Text>
      <Text style={styles.help}>
        Scan the QR code shown in the desktop portal under{'\n'}
        Settings → Mobile → Pair device. For dev use, paste the values
        below.
      </Text>
      <Text style={styles.label}>API URL</Text>
      <TextInput style={styles.input} value={apiBase} onChangeText={setAPIBase}
                 autoCapitalize="none" autoCorrect={false}
                 placeholder="https://api.vaultscan.zaishield.com" />
      <Text style={styles.label}>Tenant ID (UUID)</Text>
      <TextInput style={styles.input} value={tenantId} onChangeText={setTenantId}
                 autoCapitalize="none" autoCorrect={false}
                 placeholder="00000000-0000-0000-0000-000000000000" />
      <Text style={styles.label}>Bearer Token</Text>
      <TextInput style={styles.input} value={token} onChangeText={setToken}
                 secureTextEntry autoCapitalize="none" autoCorrect={false}
                 placeholder="eyJhbGc..." />
      {error && <Text style={styles.error}>{error}</Text>}
      <Pressable style={[styles.btn, busy && { opacity: 0.5 }]}
                 disabled={busy} onPress={pair}>
        <Text style={styles.btnText}>{busy ? 'PAIRING...' : 'PAIR'}</Text>
      </Pressable>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, padding: 24, backgroundColor: '#0a0a0a' },
  heading:   { color: '#ff6b00', fontSize: 24, fontWeight: 'bold', marginBottom: 8 },
  help:      { color: '#888', marginBottom: 16, fontSize: 12 },
  label:     { color: '#888', fontSize: 11, textTransform: 'uppercase',
               letterSpacing: 2, marginTop: 12, marginBottom: 4 },
  input:     { backgroundColor: '#1a1a1a', color: '#fff', padding: 12,
               borderRadius: 4, fontFamily: 'Courier', fontSize: 13 },
  btn:       { backgroundColor: '#ff6b00', padding: 14, marginTop: 24,
               borderRadius: 4, alignItems: 'center' },
  btnText:   { color: '#000', fontWeight: 'bold', letterSpacing: 2 },
  error:     { color: '#ef4444', marginTop: 12, fontSize: 13 },
});
