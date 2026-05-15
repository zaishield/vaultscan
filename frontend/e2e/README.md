# Portal E2E Tests (Playwright)

Closes SEV-4.1 from the forensic report: 32 portal pages had no E2E
coverage. A regression in `RequireAuth` or `AppShell` could silently
break navigation, and the cross-tenant API guard tests didn't have a
UI-side counterpart proving the portal handles 403s without crashing.

## Layout

```
frontend/
├── playwright.config.ts        chromium-only by default; full matrix
│                               (chromium+firefox+webkit) on
│                               E2E_FULL_MATRIX=1
├── e2e/
│   ├── fixtures/
│   │   └── auth.ts             seedSession + installAPIMocks fixture;
│   │                           every spec gets a pre-authenticated
│   │                           page + default API mocks
│   └── tests/
│       ├── dashboard.spec.ts     top-nav renders; signed-out → /login
│       ├── marketplace.spec.ts   §34 catalog browse + install flow
│       ├── feedback.spec.ts      §33 submit form + NPS header
│       └── cross-tenant.spec.ts  403 from API → portal handles cleanly
```

## Running

```
cd frontend
npm install
npm run e2e:install     # one-time: download chromium
npm run e2e             # runs against `vite dev` it spawns itself
npm run e2e:headed      # see the browser
npm run e2e:debug       # step through with the inspector
```

## CI

`.github/workflows/e2e.yml`:

- Every push: chromium only (~2 min).
- Daily 05:13 UTC schedule: full matrix (chromium + firefox + webkit).
- Failures upload `playwright-report/` as an artifact (HTML report,
  screenshots, video on retry).

## How the mocks work

Specs use Playwright's `page.route()` to intercept API requests and
fulfill them with canned responses. The default mock layer (in
`fixtures/auth.ts`) covers the hot-read endpoints the AppShell + each
page poll on first paint; individual specs override specific routes.

This keeps E2E fast (~30s per spec, no backend boot) and deterministic
(no flaky DB seeds). A separate backend integration suite already
covers the real end-to-end path against Postgres.
