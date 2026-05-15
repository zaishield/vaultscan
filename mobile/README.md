# VAULTSCAN Mobile (Expo + React Native)

Single TypeScript codebase that compiles to native iOS + Android via
Expo. Replaces the previous "two separate apps in Swift + Kotlin"
plan from the forensic report.

## Why Expo

- **One codebase, two binaries.** The same TypeScript ships to both
  App Store + Play Store; no Swift / Kotlin source duplication.
- **Push notifications work out of the box.** `expo-notifications`
  wraps APNS (iOS) + FCM (Android) under the same API. Backend
  receives the raw device token via `getDevicePushTokenAsync()`,
  meaning our `internal/notify/push.go` dispatcher targets the
  vendor APIs directly without going through Expo's push relay.
- **Over-the-air JS updates** via Expo Updates — non-native changes
  ship instantly without an app-store review (use sparingly; respect
  Apple's guideline §3.3.2).
- **EAS Build** handles signing, provisioning, code-signing on
  Apple/Google's hosted build infra. No mac mini farm, no Android
  SDK on dev laptops.

## Layout

```
mobile/
├── package.json          deps + scripts
├── app.json              Expo config (icons, perms, push channel)
├── eas.json              EAS Build profiles (preview, production)
├── tsconfig.json         strict TS
├── App.tsx               navigation root + boot
├── src/
│   ├── lib/
│   │   ├── session.ts        SecureStore-backed token + tenant
│   │   ├── notifications.ts  push permission + token registration
│   │   └── api.ts            typed fetch against /api/v1/mobile/*
│   └── screens/
│       ├── LoginScreen.tsx        QR-pair (manual entry as fallback)
│       ├── DashboardScreen.tsx    /api/v1/mobile/dashboard
│       ├── AlertsScreen.tsx       /api/v1/mobile/alerts/ack
│       └── EmergencyStopScreen.tsx /api/v1/mobile/emergency-stop
└── assets/               icons, splash (placeholder PNGs)
```

## Local dev

```bash
cd mobile
npm install
npm start          # opens the Expo dev server with QR code
npm run ios        # opens iOS simulator
npm run android    # opens Android emulator
```

You need:
- Node 20+
- For iOS local builds: macOS + Xcode
- For Android local builds: Android Studio + SDK

For iOS-on-Linux / Android-on-Mac, use **EAS Build** (cloud) instead.

## Secure storage

Bearer token + tenant ID stored via
`expo-secure-store` (Keychain on iOS, EncryptedSharedPreferences
backed by Android Keystore on Android). `keychainAccessible:
AFTER_FIRST_UNLOCK_THIS_DEVICE_ONLY` so a locked device denies
access; uninstall clears the credentials; iCloud / Google Backup
is opted out.

## Push notification flow

```
Mobile app boot → configureNotifications():
  1. Permission prompt (system sheet)
  2. getDevicePushTokenAsync() → APNS token (iOS) | FCM token (Android)
  3. POST /api/v1/mobile/devices  {push_token, platform, device_label}
     ↓ stored in mobile_devices table

Backend critical-finding event →
  notify.Push.Send(platform, deviceToken, msg)
    iOS  → APNSTransport.Send  (HTTP/2 + ES256 JWT to api.push.apple.com)
    Android → FCMTransport.Send (HTTP/1 + RSA-SHA256 SA-JWT to fcm.googleapis.com)

Mobile receives push → setNotificationHandler decides foreground UX
  (currently: alert + sound + badge for everything).
```

Both transport implementations live in
`backend/internal/notify/push.go` and handle:
- Token caching (APNS provider tokens valid 1h, FCM access tokens valid 1h)
- ErrDeviceTokenInvalid surfacing (410 Gone / NOT_FOUND / UNREGISTERED)
  so the backend can prune the device

## Pairing UX

The desktop portal at /settings/mobile shows a QR code containing:

```
vaultscan-mobile://pair?api=https://api.vaultscan.zaishield.com
                       &token=<short-lived-JWT>
                       &tenant=<UUID>
```

User opens the mobile app, taps "Scan QR" (next iteration — for now
LoginScreen accepts manual entry of the three values), and the app
exchanges the short-lived JWT for a longer-lived mobile session token
via `POST /api/v1/auth/mobile-pair`.

## CI

`.github/workflows/mobile.yml`:

- Every push: `npm run typecheck` runs `tsc --noEmit`.
- Every tag (`v*`): `eas build --profile production` for both iOS +
  Android. Artifacts uploaded; submission to stores via
  `eas submit --profile production` (manual gate via
  `workflow_dispatch` once a build is reviewed).

Required GitHub secrets:
- `EXPO_TOKEN` — service-account API token from the Expo dashboard
- `EXPO_APPLE_ID` / `EXPO_ASC_APP_ID` / `EXPO_APPLE_TEAM_ID` for
  App Store Connect submission

## Production checklist before first store submission

- [ ] Replace `assets/icon.png` / `splash.png` / `adaptive-icon.png`
      / `notification-icon.png` with real branded assets.
- [ ] In `app.json`, set `ios.bundleIdentifier` / `android.package` to
      the customer-facing bundle (currently `com.zaishield.vaultscan`).
- [ ] Generate the iOS APNs Auth Key (.p8) in Apple Developer Portal
      → Identifiers → Keys, set as backend's APNS PrivateKeyPEM.
- [ ] Set up the Firebase project for FCM, download the Service
      Account JSON, set as backend's FCM ServiceAccountJSON.
- [ ] Run `eas project:init` to mint a real EAS project ID, replace
      the placeholder in `app.json` extra.eas.projectId.
- [ ] App privacy nutrition labels filled in App Store Connect.
- [ ] Play Store data-safety form filled.
