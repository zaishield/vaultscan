// marketplace.spec.ts — covers the §34 marketplace lifecycle in the
// portal: browse catalog, filter by category, install a listing whose
// schema requires config, uninstall.

import { test, expect } from '../fixtures/auth';

test('marketplace shows seeded listings + category filter', async ({ page }) => {
  await page.goto('/marketplace');
  await expect(page.locator('text=Slack — Incident Feed')).toBeVisible();
  await expect(page.locator('text=PagerDuty — Critical Alerts')).toBeVisible();

  // Click the `chat` category — only Slack listing should remain.
  await page.getByRole('button', { name: /^CHAT$/i }).click();
  await expect(page.locator('text=Slack — Incident Feed')).toBeVisible();
  await expect(page.locator('text=PagerDuty — Critical Alerts')).not.toBeVisible();
});

test('install Slack listing triggers configure form', async ({ page }) => {
  let installFired = false;
  await page.route('**/api/v1/marketplace/installs', async route => {
    if (route.request().method() === 'POST') {
      installFired = true;
      await route.fulfill({
        status: 201,
        contentType: 'application/json',
        body: JSON.stringify({
          install_id:     'I1',
          integration_id: 'INT1',
          state:          'pending_config',
        }),
      });
    } else {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ installs: [] }),
      });
    }
  });

  await page.goto('/marketplace');
  // Slack listing has a required `url` field → INSTALL opens config form.
  await page.locator('div').filter({ hasText: /Slack — Incident Feed/ }).first()
    .getByRole('button', { name: /INSTALL/i }).click();
  await expect(page.locator('text=Configure')).toBeVisible();

  await page.getByPlaceholder(/https:\/\/\.\.\./).fill('https://hooks.slack.example/x');
  await page.getByRole('button', { name: /^INSTALL$/ }).click();
  await expect.poll(() => installFired).toBeTruthy();
});
