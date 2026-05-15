// dashboard.spec.ts — proves the dashboard renders end-to-end against
// a mocked backend. Catches:
//   - RequireAuth bypass regressions (session-seed wiring)
//   - AppShell crash on first paint
//   - Top-nav links missing / broken
//   - Branding bundle fetch handled gracefully when API returns 200

import { test, expect } from '../fixtures/auth';

test('dashboard loads with all top-nav sections', async ({ page }) => {
  await page.goto('/');
  await expect(page).not.toHaveURL(/\/login/);
  // The dashboard shows the branding-derived product name.
  await expect(page.locator('text=ZAISHIELD VAULTSCAN').first()).toBeVisible();
  // 07 SYSTEM is the section header we added when wiring §24/33/34.
  await expect(page.locator('text=07 SYSTEM').first()).toBeVisible();
  // Marketplace + Feedback + Mobile Portal nav links should be present.
  for (const label of ['Marketplace', 'Feedback', 'Mobile Portal']) {
    await expect(page.getByRole('link', { name: new RegExp(label, 'i') })).toBeVisible();
  }
});

test('signed-out user is redirected to login', async ({ browser }) => {
  // Fresh context with NO session seed.
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  await page.goto('/');
  await expect(page).toHaveURL(/\/login$/);
  await ctx.close();
});
