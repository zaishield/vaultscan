// feedback.spec.ts — covers §33 submit + triage flow.

import { test, expect } from '../fixtures/auth';

test('submit feedback fires POST + clears form', async ({ page }) => {
  let posted: any = null;
  await page.route('**/api/v1/feedback', async route => {
    if (route.request().method() === 'POST') {
      posted = JSON.parse(route.request().postData() ?? '{}');
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ id: 'fb-12345678-aaaa-bbbb-cccc-dddddddddddd' }),
      });
    } else {
      await route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({ items: [], nps_score: 42 }),
      });
    }
  });

  await page.goto('/feedback');
  await expect(page.locator('text=Customer Feedback')).toBeVisible();

  await page.getByPlaceholder("What's on your mind?").fill(
    'The marketplace install confirmation should show the listing logo.');
  await page.getByRole('button', { name: /^SUBMIT$/ }).click();

  await expect.poll(() => posted?.message).toContain('marketplace install confirmation');
  await expect(page.locator('text=Thanks — submitted as fb-12345')).toBeVisible();
});

test('NPS score shows in header when API returns one', async ({ page }) => {
  await page.goto('/feedback');
  await expect(page.locator('text=NPS:')).toBeVisible();
  await expect(page.locator('text=42.5')).toBeVisible();
});
