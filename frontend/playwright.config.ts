// playwright.config.ts — E2E config.
//
// Two project flavors:
//   - chromium (default, every PR via CI)
//   - webkit + firefox enabled locally; CI uses chromium only to keep
//     PR time tight.
//
// The dev server is started via `webServer` so a single `npm run e2e`
// boots vite + runs every spec against it. The backend is NOT started
// here — specs mock the API via Playwright's `route.fulfill`. A
// separate integration-suite job covers the real-backend path.

import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './e2e/tests',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  reporter: [
    ['html', { open: 'never' }],
    ['list'],
  ],

  use: {
    baseURL: process.env.E2E_BASE_URL ?? 'http://127.0.0.1:5173',
    trace: 'on-first-retry',
    screenshot: 'only-on-failure',
    video: 'retain-on-failure',
  },

  projects: [
    { name: 'chromium', use: devices['Desktop Chrome'] },
    ...(process.env.E2E_FULL_MATRIX === '1'
      ? [
          { name: 'firefox', use: devices['Desktop Firefox'] },
          { name: 'webkit',  use: devices['Desktop Safari']  },
        ]
      : []),
  ],

  webServer: {
    command: 'npm run dev',
    url: 'http://127.0.0.1:5173',
    reuseExistingServer: !process.env.CI,
    timeout: 60_000,
  },
});
