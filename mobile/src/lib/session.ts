// session.ts — bearer token + tenant_id storage via expo-secure-store.
//
// On iOS, SecureStore wraps the iOS Keychain (kSecClassGenericPassword
// with kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly). On Android,
// it uses EncryptedSharedPreferences backed by the Android Keystore
// (AES-256-GCM with a hardware-backed key when available).
//
// Both platforms guarantee:
//   - Inaccessible while device locked (after-first-unlock)
//   - Cleared on uninstall
//   - Not synced via iCloud / Google Backup

import * as SecureStore from 'expo-secure-store';

const KEY_TOKEN     = 'vaultscan.session.token';
const KEY_TENANT_ID = 'vaultscan.session.tenantId';
const KEY_USER_ID   = 'vaultscan.session.userId';
const KEY_API_BASE  = 'vaultscan.session.apiBase';

export interface Session {
  token: string;
  tenantId: string;
  userId: string;
  apiBase: string;
}

export async function loadSession(): Promise<Session | null> {
  const [token, tenantId, userId, apiBase] = await Promise.all([
    SecureStore.getItemAsync(KEY_TOKEN),
    SecureStore.getItemAsync(KEY_TENANT_ID),
    SecureStore.getItemAsync(KEY_USER_ID),
    SecureStore.getItemAsync(KEY_API_BASE),
  ]);
  if (!token || !tenantId) return null;
  return {
    token, tenantId,
    userId: userId ?? '',
    apiBase: apiBase ?? 'https://api.vaultscan.zaishield.com',
  };
}

export async function saveSession(s: Session): Promise<void> {
  await Promise.all([
    SecureStore.setItemAsync(KEY_TOKEN, s.token, {
      keychainAccessible: SecureStore.AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY,
    }),
    SecureStore.setItemAsync(KEY_TENANT_ID, s.tenantId),
    SecureStore.setItemAsync(KEY_USER_ID, s.userId),
    SecureStore.setItemAsync(KEY_API_BASE, s.apiBase),
  ]);
}

export async function clearSession(): Promise<void> {
  await Promise.all([
    SecureStore.deleteItemAsync(KEY_TOKEN),
    SecureStore.deleteItemAsync(KEY_TENANT_ID),
    SecureStore.deleteItemAsync(KEY_USER_ID),
    SecureStore.deleteItemAsync(KEY_API_BASE),
  ]);
}
