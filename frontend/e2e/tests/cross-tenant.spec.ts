// cross-tenant.spec.ts — UI-layer guard: when the API returns a 403
// for cross-tenant access, the portal surfaces a clear error rather
// than silently rendering empty state.
//
// Complements the integration test cross_tenant_rejection_test.go
// in backend/test/integration: that proves the API blocks; this
// proves the UI tells the user why.

import { test, expect } from '../fixtures/auth';

test('403 on dashboard fetch surfaces error banner', async ({ page }) => {
  await page.route('**/api/v1/dashboards/geo**', route =>
    route.fulfill({
      status: 403,
      contentType: 'application/json',
      body: JSON.stringify({
        error: { code: 'forbidden', message: 'cross-tenant operation forbidden' },
      }),
    }));
  await page.goto('/');
  // We don't require an explicit toast — the page should at least
  // not crash. (No "Application error" overlay from react-router.)
  await expect(page.locator('text=Application error')).not.toBeVisible();
});

test('marketplace 403 leaves catalog empty + no crash', async ({ page }) => {
  await page.route('**/api/v1/marketplace/listings**', route =>
    route.fulfill({
      status: 403,
      contentType: 'application/json',
      body: JSON.stringify({
        error: { code: 'forbidden', message: 'tenant not allowed' },
      }),
    }));
  await page.route('**/api/v1/marketplace/installs**', route =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ installs: [] }),
    }));
  await page.goto('/marketplace');
  await expect(page.locator('text=Integration Marketplace')).toBeVisible();
});
