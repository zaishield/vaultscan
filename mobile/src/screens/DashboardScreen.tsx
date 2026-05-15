import { useEffect, useState } from 'react';
import { ScrollView, View, Text, Pressable, StyleSheet, RefreshControl } from 'react-native';
import { NativeStackScreenProps } from '@react-navigation/native-stack';

import { api, MobileDashboard } from '../lib/api';
import { RootStackParamList } from '../../App';

type Props = NativeStackScreenProps<RootStackParamList, 'Dashboard'>;

export function DashboardScreen({ navigation }: Props) {
  const [dash, setDash] = useState<MobileDashboard | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const refresh = async () => {
    setRefreshing(true);
    try {
      setDash(await api.dashboard());
      setError(null);
    } catch (e) { setError((e as Error).message); }
    finally { setRefreshing(false); }
  };
  useEffect(() => { refresh(); }, []);

  return (
    <ScrollView style={styles.container}
                refreshControl={<RefreshControl refreshing={refreshing} onRefresh={refresh}
                  tintColor="#ff6b00" />}>
      {error && <Text style={styles.error}>{error}</Text>}
      <View style={styles.statRow}>
        <Stat label="Critical"  value={dash?.open_critical_count ?? 0}
              color={(dash?.open_critical_count ?? 0) > 0 ? '#ef4444' : '#888'} />
        <Stat label="Pending Approvals" value={dash?.alerts_pending ?? 0} color="#ff6b00" />
      </View>
      <View style={styles.statRow}>
        <Stat label="Agents Online"  value={dash?.agents_online ?? 0}  color="#10b981" />
        <Stat label="Agents Offline" value={dash?.agents_offline ?? 0}
              color={(dash?.agents_offline ?? 0) > 0 ? '#f59e0b' : '#888'} />
      </View>
      <Stat label="Jobs Running" value={dash?.jobs_running ?? 0} color="#888" wide />

      <Pressable style={styles.actionBtn}
                 onPress={() => navigation.navigate('Alerts')}>
        <Text style={styles.actionText}>VIEW ALERTS</Text>
      </Pressable>
      <Pressable style={[styles.actionBtn, styles.danger]}
                 onPress={() => navigation.navigate('EmergencyStop')}>
        <Text style={[styles.actionText, { color: '#fff' }]}>EMERGENCY STOP</Text>
      </Pressable>
    </ScrollView>
  );
}

function Stat({ label, value, color, wide }: {
  label: string; value: number; color: string; wide?: boolean;
}) {
  return (
    <View style={[styles.stat, wide && { width: '100%' }]}>
      <Text style={styles.statLabel}>{label}</Text>
      <Text style={[styles.statValue, { color }]}>{value}</Text>
    </View>
  );
}

const styles = StyleSheet.create({
  container: { flex: 1, backgroundColor: '#0a0a0a', padding: 16 },
  statRow:   { flexDirection: 'row', gap: 12, marginBottom: 12 },
  stat:      { flex: 1, padding: 16, backgroundColor: '#1a1a1a', borderRadius: 4 },
  statLabel: { color: '#888', fontSize: 10, textTransform: 'uppercase',
               letterSpacing: 2, marginBottom: 8 },
  statValue: { fontSize: 28, fontWeight: 'bold' },
  actionBtn: { backgroundColor: '#ff6b00', padding: 16, borderRadius: 4,
               alignItems: 'center', marginTop: 16 },
  actionText:{ color: '#000', fontWeight: 'bold', letterSpacing: 2 },
  danger:    { backgroundColor: '#ef4444' },
  error:     { color: '#ef4444', marginBottom: 12 },
});
