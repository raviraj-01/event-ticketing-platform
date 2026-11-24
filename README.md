# Ticketing app (name TBD)

A Node/Express app that serves the single-page frontend and API from the same server.

## Run Locally

1. Install Node.js 20 or newer.
2. Install dependencies:

```bash
npm install
```

3. Create your local environment file:

```bash
cp .env.example .env
```

On Windows PowerShell:

```powershell
Copy-Item .env.example .env
```

4. Fill in the required values in `.env`:

- `DATABASE_URL`
- `JWT_SECRET`

5. Start the app:

```bash
npm start
```

6. Open:

```text
http://localhost:3003
```

## Notes

- `.env` is intentionally not committed because it contains secrets.
- `node_modules` is intentionally not committed. Run `npm install` after cloning.
- The frontend lives in `public/` (the only folder the server publishes). It calls the API on the same origin.
- Android app: your backend's origin must be in `vybera-cordova/config.xml` `<access>` (`https://*.onrender.com` is there by default; the build checks this). `CORDOVA_API_BASE=https://your-backend npm run build:cordova` generates `vybera-cordova/www/` from `public/`, then `cd vybera-cordova && npx cordova build android`. Never edit `vybera-cordova/www/` by hand.
- Project notes, audit and decisions: `CLAUDE.md`.

## Your existing data

Starting the app runs the schema migrations, which add tables, columns, functions and indexes. Neither the migrations nor startup change or delete rows that already exist (the one write is creating the first super admin when `SUPERADMIN_EMAIL` has no account yet). One-off repairs are manual:

```
npm run db:fixups             # dry run: prints what would change, changes nothing
npm run db:fixups -- --apply  # recount event counters, move legacy super admins
```

Before the first start on a database that already has accounts, run `npm run report-duplicates` (read-only). Migration 0019 makes emails (ignoring case) and verified buyer phones unique; if the report lists duplicates, that migration refuses to run and changes nothing until they are resolved.

## Demo data (fresh database)

```
npm run migrate
npm run seed-demo                                   # admin email = SMTP_USER with +demo-admin
npm run seed-demo -- --admin-email=you+admin@x.com  # or choose it
```

Creates an admin, an approved organizer, a free and a paid live event, a staff member with 10 tickets of the paid event, and a buyer with a verified phone. Insert-only: existing rows are kept as they are, so running it again is safe. The passwords are written to `demo-credentials.local.txt` (git-ignored), never printed. Admin login still needs the emailed 6-digit code.

Admin login is not on the public sign-in form: open `http://localhost:3003/admin` (bookmark it; same as `/#admin`). Signing out of the admin panel returns there. The 6-digit admin code is emailed, so use an admin whose inbox you can read. Your own super admin: set `SUPERADMIN_EMAIL` and `SUPERADMIN_PASSWORD` in `.env` and restart (created once, only if that email has no super admin yet). Without SMTP and with `ADMIN_OTP_DEV_MODE=true` (never in production) the code is shown on screen instead.

Checking a new `.env` against an old one without showing any value: `node scripts/compare-env.js .env path/to/old.env`.

## Deploy (e.g. Render)

1. Create a PostgreSQL database and set every variable from `.env.example` in the host's environment (never commit `.env`).
2. Set `APP_BASE_URL` to the public https URL (used for PayU return URLs and email links).
3. **Set `TRUST_PROXY_HOPS=1` on Render** (or the number of reverse proxies in front of the app). Without it every visitor appears to have the proxy's IP, so all per-IP rate limits (OTP, login, orders) would be shared by everyone. Locally keep it `0`, otherwise clients could fake their IP with an `X-Forwarded-For` header.
4. Serve the app over **https** (Render does). Session cookies are `Secure` when `APP_BASE_URL` starts with `https://`, and browsers drop them on plain http in production.
5. If the frontend is served from another origin, list it in `CORS_ORIGINS`. The Android app's WebView origin `https://localhost` is allowed by default.
6. Start command: `npm start`. Pending database migrations in `migrations/` run automatically before the server accepts requests.
7. **PayU webhook:** in the PayU dashboard add a webhook for payment success/failure pointing to `https://<your-host>/payments/payu/webhook`. It is optional (the server also asks PayU every 5 minutes about orders whose browser never came back), but it confirms those payments within seconds. To check by hand: `npm run payu:reconcile` (or `npm run payu:reconcile -- <txnid>`).

## Tests

`npm test` runs ESLint (`npm run lint`), then starts a throwaway real PostgreSQL (embedded-postgres, downloaded on first `npm install`) and the real server, then runs the integration tests in `test/`.

## Code layout

`server.js` only starts the app (migrations → data fix-ups → listen). The app is built in `src/app.js`; routes live in `src/routes/` (one file per area), business logic and SQL in `src/services/`, shared middleware in `src/middleware/`, database setup in `src/db/`, small helpers in `src/utils/`. Schema changes go in `migrations/`.

## Health Check

After starting the server, this URL should return database status:

```text
http://localhost:3003/health
```

## Future work (out of scope for the current release)

Feature freeze from 2026-11-22: everything below waits for a later release.
Details and file references for each item are in `CLAUDE.md` (Issues log, Decisions).

**Features**
- **Staff resale** ("staff buys inventory from the organizer and resells it"): disabled in the UI and API. Needs a decision on how the staff member pays the organizer up front and who pays out the resale money.
- **Refunds** (M9): no refund flow yet. Orders paid after their seats sold out are listed for admins as "needs refund" and must be refunded manually in the PayU dashboard. Then add an admin "mark refunded" action (D21). Admin totals already exclude refunded bookings.
- **Coupons**: the checkout coupon box is hidden; coupons need server-side storage and validation in `POST /orders`.
- **Editing an event**: organizers cannot edit an event yet. Any edit to price or date must send the event back to `pending` (D20); existing orders keep their own price.
- **Share-link regeneration** (D25): staff and their organizer can make a new link; the old one stops earning commission.
- **Organizer email verification** (rest of H12): confirm an organizer owns the email they apply with.
- **Uploads straight to storage**: presigned R2 uploads instead of base64 files inside JSON (the reason two routes still accept large bodies, M11).
- **Strict script CSP**: move the page's inline `<script>` blocks and `onclick` handlers into files so the CSP can drop `'unsafe-inline'` (M15).

**Waiting on data or accounts (not code)**
- Android device test (H15) and the real PayU test-mode checkout: `docs/ANDROID-DEVICE-CHECKLIST.md`, `docs/PAYU-TEST.md`.
- Restrict the Firebase web API key to your domains / app in the Google Cloud console (L7).
