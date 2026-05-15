import { useState } from 'react';
import { View, Text, TextInput, Pressable, StyleSheet, Alert } from 'react-native';

import { api } from '../lib/api';
import { loadSession } from '../lib/session';

export function EmergencyStopScreen() {
  const [reason, setReason] = useState('Mobile-initiated kill (drill)');
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<string | null>(null);

  async function fire() {
    Alert.alert(
      'Confirm Emergency Stop',
      'This will halt every running scan in your tenant. You cannot undo this. Are you sure?',
      [
        { text: 'Cancel', style: 'cancel' },
        { text: 'STOP ALL', style: 'destructive', onPress: doFire },
      ],
    );
  }

  async function doFire() {
    setBusy(true);
    setResult(null);
    try {
      const session = await loadSession();
      if (!session) throw new Error('not authenticated');
      const r = await api.emergencyStop(session.tenantId, reason);
      setResult(`Stopped ${r.stopped} job(s) — reason: ${r.reason}`);
    } catch (e) {
      setResult(`Failed: ${(e as Error).message}`);
    } finally {
      setBusy(false);
    }
  }

  return (
    <View style={styles.container}>
      <Text style={styles.heading}>EMERGENCY STOP</Text>
      <Text style={styles.help}>
        Triggers the §11.6 30-second SLA path. Halts every running scan
        in your tenant. Use only when you've authorised the operation
        out-of-band.
      </Text>
      <Text style={styles.label}>Reason</Text>
      <TextInput style={styles.input} value={reason} onChangeText={setReason}
                 multiline />
      <Pressable style={[styles.btn, busy && { opacity: 0.5 }]}
                 disabled={busy} onPress={fire}>
        <Text style={styles.btnText}>{busy ? 'STOPPING...' : 'FIRE EMERGENCY STOP'}</Text>
      </Pressable>
      {result && <Text style={styles.result}>{result}</Text>}
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, padding: 24, backgroundColor: '#0a0a0a' },
  heading:   { color: '#ef4444', fontSize: 24, fontWeight: 'bold',
               marginBottom: 12, letterSpacing: 2 },
  help:      { color: '#888', fontSize: 13, marginBottom: 16 },
  label:     { color: '#888', fontSize: 11, textTransform: 'uppercase',
               letterSpacing: 2, marginTop: 12, marginBottom: 4 },
  input:     { backgroundColor: '#1a1a1a', color: '#fff', padding: 12,
               borderRadius: 4, fontFamily: 'Courier', minHeight: 80 },
  btn:       { backgroundColor: '#ef4444', padding: 16, marginTop: 24,
               borderRadius: 4, alignItems: 'center' },
  btnText:   { color: '#fff', fontWeight: 'bold', letterSpacing: 2 },
  result:    { color: '#10b981', marginTop: 16, fontSize: 13 },
});
