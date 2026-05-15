import { useEffect, useState } from 'react';
import { ScrollView, View, Text, Pressable, StyleSheet, RefreshControl } from 'react-native';

import { api, MobileDashboard } from '../lib/api';

export function AlertsScreen() {
  const [dash, setDash] = useState<MobileDashboard | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const refresh = async () => {
    setRefreshing(true);
    try { setDash(await api.dashboard()); setError(null); }
    catch (e) { setError((e as Error).message); }
    finally { setRefreshing(false); }
  };
  useEffect(() => { refresh(); }, []);

  async function ack(id: string) {
    try { await api.ackAlert(id); await refresh(); }
    catch (e) { setError((e as Error).message); }
  }

  return (
    <ScrollView style={styles.container}
                refreshControl={<RefreshControl refreshing={refreshing} onRefresh={refresh}
                  tintColor="#ff6b00" />}>
      {error && <Text style={styles.error}>{error}</Text>}
      {(dash?.pending_approvals?.length ?? 0) === 0 ? (
        <Text style={styles.empty}>No alerts pending acknowledgement.</Text>
      ) : (
        dash?.pending_approvals.map(a => (
          <View key={a.id} style={styles.card}>
            <Text style={styles.title}>{a.title}</Text>
            <Text style={[styles.severity, severityStyle(a.severity)]}>
              {a.severity.toUpperCase()}
            </Text>
            <Text style={styles.requested}>{a.requested_at}</Text>
            <Pressable style={styles.ackBtn} onPress={() => ack(a.id)}>
              <Text style={styles.ackText}>ACKNOWLEDGE</Text>
            </Pressable>
          </View>
        ))
      )}
    </ScrollView>
  );
}

function severityStyle(s: string) {
  switch (s) {
    case 'critical': return { color: '#ef4444' };
    case 'high':     return { color: '#ff6b00' };
    case 'medium':   return { color: '#f59e0b' };
    default:         return { color: '#888' };
  }
}

const styles = StyleSheet.create({
  container:  { flex: 1, backgroundColor: '#0a0a0a', padding: 16 },
  card:       { padding: 16, marginBottom: 12, backgroundColor: '#1a1a1a', borderRadius: 4 },
  title:      { color: '#fff', fontWeight: 'bold', marginBottom: 8 },
  severity:   { fontSize: 11, letterSpacing: 2, marginBottom: 4 },
  requested:  { color: '#666', fontSize: 11, marginBottom: 12 },
  ackBtn:     { backgroundColor: '#10b981', padding: 12, borderRadius: 4,
                alignItems: 'center' },
  ackText:    { color: '#fff', fontWeight: 'bold', letterSpacing: 2 },
  empty:      { color: '#888', fontSize: 13 },
  error:      { color: '#ef4444', marginBottom: 12 },
});
