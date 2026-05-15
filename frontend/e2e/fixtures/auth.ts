// auth.ts — shared Playwright fixtures.
//
// Most specs need a logged-in session against a mocked API. This file
// extends Playwright's test object with helpers that pre-stamp
// localStorage with a fake JWT + tenant ID so RequireAuth lets the
// app render, and registers a default API-mock layer that returns
// reasonable shapes for the hot read paths.

import { test as base, expect, Page } from '@playwright/test';

export const TENANT_ID = '11111111-1111-1111-1111-111111111111';
export const FAKE_TOKEN = 'eyJhbGciOiJIUzI1NiJ9.fake.token';

// Seed localStorage with a session zustand persists.
export async function seedSession(page: Page) {
  await page.addInitScript(([tenantId, token]) => {
    const state = {
      state: {
        token,
        tenantId,
        email:  'qa@vaultscan.test',
        roles:  ['zaishield_super_admin'],
      },
      version: 0,
    };
    localStorage.setItem('vaultscan-auth', JSON.stringify(state));
  }, [TENANT_ID, FAKE_TOKEN]);
}

// Install default API mocks. Specs override individual routes via
// page.route() before calling page.goto().
export async function installAPIMocks(page: Page) {
  await page.route('**/api/v1/branding**', route =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        branding: {
          product_name: 'ZAISHIELD VAULTSCAN',
          confidentiality_tag: 'CONFIDENTIAL // INTERNAL USE ONLY',
          logo_url: null,
          legal_footer: '© ZAISHIELD VAULTSCAN — playwright',
        },
      }),
    }));
  await page.route('**/api/v1/dashboards/geo**', route =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ nodes: [] }),
    }));
  await page.route('**/api/v1/marketplace/listings**', route =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({
        listings: [
          {
            id: 'L1', slug: 'slack-incident-feed',
            name: 'Slack — Incident Feed',
            publisher: 'ZAISHIELD', category: 'chat',
            description: 'Posts critical findings to Slack.',
            integration_type: 'slack',
            config_schema: {
              type: 'object', required: ['url'],
              properties: { url: { type: 'string', title: 'Webhook URL' } },
            },
            verified: true,
          },
          {
            id: 'L2', slug: 'pagerduty-critical-alerts',
            name: 'PagerDuty — Critical Alerts',
            publisher: 'ZAISHIELD', category: 'incident',
            description: 'Triggers a PD incident on critical findings.',
            integration_type: 'pagerduty',
            config_schema: { type: 'object', required: ['routing_key'] },
            verified: true,
          },
        ],
      }),
    }));
  await page.route('**/api/v1/marketplace/installs**', route =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ installs: [] }),
    }));
  await page.route('**/api/v1/feedback**', route =>
    route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ items: [], nps_score: 42.5 }),
    }));
}

// Composed fixture: auth-seeded + mocked API.
export const test = base.extend({
  page: async ({ page }, use) => {
    await seedSession(page);
    await installAPIMocks(page);
    await use(page);
  },
});

export { expect };
