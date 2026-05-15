// App.tsx — VAULTSCAN mobile entry. Wires:
//   * SecureStore-backed bearer token (after MFA login on the desktop
//     portal, the user scans a QR code to provision the mobile session)
//   * expo-notifications for APNS/FCM push token registration +
//     foreground/background handlers
//   * react-navigation stack: Login → Dashboard → Alerts → Approvals
//
// Production deployments enable the Expo Updates channel (eas.json
// "production") so over-the-air JS updates roll out without an
// app-store re-submission for non-native changes.

import { NavigationContainer } from '@react-navigation/native';
import { createNativeStackNavigator } from '@react-navigation/native-stack';
import { StatusBar } from 'expo-status-bar';
import { useEffect, useState } from 'react';
import { Alert } from 'react-native';

import { LoginScreen } from './src/screens/LoginScreen';
import { DashboardScreen } from './src/screens/DashboardScreen';
import { AlertsScreen } from './src/screens/AlertsScreen';
import { EmergencyStopScreen } from './src/screens/EmergencyStopScreen';
import { configureNotifications } from './src/lib/notifications';
import { loadSession } from './src/lib/session';

export type RootStackParamList = {
  Login: undefined;
  Dashboard: undefined;
  Alerts: undefined;
  EmergencyStop: undefined;
};

const Stack = createNativeStackNavigator<RootStackParamList>();

export default function App() {
  const [initialRoute, setInitialRoute] = useState<keyof RootStackParamList>('Login');
  const [ready, setReady] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        const session = await loadSession();
        if (session?.token && session?.tenantId) {
          setInitialRoute('Dashboard');
        }
        await configureNotifications();
      } catch (e) {
        Alert.alert('Boot error', String(e));
      } finally {
        setReady(true);
      }
    })();
  }, []);

  if (!ready) return null;

  return (
    <NavigationContainer>
      <StatusBar style="light" />
      <Stack.Navigator
        initialRouteName={initialRoute}
        screenOptions={{
          headerStyle: { backgroundColor: '#0a0a0a' },
          headerTintColor: '#ff6b00',
          headerTitleStyle: { fontWeight: 'bold' },
          contentStyle: { backgroundColor: '#0a0a0a' },
        }}>
        <Stack.Screen name="Login" component={LoginScreen} options={{ title: 'VAULTSCAN' }} />
        <Stack.Screen name="Dashboard" component={DashboardScreen} options={{ title: 'Dashboard' }} />
        <Stack.Screen name="Alerts" component={AlertsScreen} options={{ title: 'Alerts' }} />
        <Stack.Screen name="EmergencyStop" component={EmergencyStopScreen}
          options={{ title: 'Emergency Stop', headerTintColor: '#ef4444' }} />
      </Stack.Navigator>
    </NavigationContainer>
  );
}
