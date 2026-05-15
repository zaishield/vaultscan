// notifications.ts — push-token registration + handler config.
//
// Three layers:
//
//   1. Permission prompt (iOS shows the system permission sheet;
//      Android 13+ shows the POST_NOTIFICATIONS sheet).
//   2. expo-notifications.getDevicePushTokenAsync() yields the
//      raw APNS device token (iOS) or FCM registration token
//      (Android). Both go to our backend's POST /api/v1/mobile/devices.
//   3. setNotificationHandler decides what to do when a push arrives
//      while the app is in foreground (alert vs silent).
//
// We do NOT use Expo's push service (https://exp.host/--/api/v2/push)
// in production because it adds an extra hop + Expo-managed lifecycle.
// Instead we send the raw device token to our own backend so the
// notify package's APNS/FCM dispatcher can target it directly.

import * as Device from 'expo-device';
import * as Notifications from 'expo-notifications';
import { Platform } from 'react-native';

import { loadSession } from './session';

Notifications.setNotificationHandler({
  handleNotification: async () => ({
    shouldShowAlert: true,
    shouldPlaySound: true,
    shouldSetBadge: true,
    shouldShowBanner: true,
    shouldShowList: true,
  }),
});

export async function configureNotifications(): Promise<void> {
  if (!Device.isDevice) {
    // Simulator / emulator can't receive push.
    return;
  }
  const { status: existingStatus } = await Notifications.getPermissionsAsync();
  let status = existingStatus;
  if (status !== 'granted') {
    const req = await Notifications.requestPermissionsAsync({
      ios: {
        allowAlert: true,
        allowBadge: true,
        allowSound: true,
        allowAnnouncements: true,
      },
    });
    status = req.status;
  }
  if (status !== 'granted') {
    return;
  }

  // Android needs a notification channel registered for alerts to
  // honor the priority + vibration we want.
  if (Platform.OS === 'android') {
    await Notifications.setNotificationChannelAsync('vaultscan-alerts', {
      name: 'Security Alerts',
      importance: Notifications.AndroidImportance.HIGH,
      vibrationPattern: [0, 250, 250, 250],
      lightColor: '#ff6b00',
    });
  }

  const tokenObj = await Notifications.getDevicePushTokenAsync();
  await registerDeviceWithBackend(tokenObj.data, Platform.OS);
}

async function registerDeviceWithBackend(token: string, platform: string): Promise<void> {
  const session = await loadSession();
  if (!session) {
    // Not yet authenticated — token will be re-registered after login.
    return;
  }
  try {
    await fetch(`${session.apiBase}/api/v1/mobile/devices`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${session.token}`,
        'X-Tenant-Id': session.tenantId,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        tenant_id: session.tenantId,
        platform,
        push_token: token,
        device_label: `${Device.modelName ?? 'Device'} (${Platform.OS})`,
      }),
    });
  } catch (err) {
    console.warn('mobile: device registration failed', err);
  }
}
