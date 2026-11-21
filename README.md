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

## Deploy (e.g. Render)

1. Create a PostgreSQL database and set every variable from `.env.example` in the host's environment (never commit `.env`).
2. Set `APP_BASE_URL` to the public https URL (used for PayU return URLs and email links).
3. **Set `TRUST_PROXY_HOPS=1` on Render** (or the number of reverse proxies in front of the app). Without it every visitor appears to have the proxy's IP, so all per-IP rate limits (OTP, login, orders) would be shared by everyone. Locally keep it `0`, otherwise clients could fake their IP with an `X-Forwarded-For` header.
4. Serve the app over **https** (Render does). Session cookies are `Secure` when `APP_BASE_URL` starts with `https://`, and browsers drop them on plain http in production.
5. If the frontend is served from another origin, list it in `CORS_ORIGINS`. The Android app's WebView origin `https://localhost` is allowed by default.
6. Start command: `npm start`. Pending database migrations in `migrations/` run automatically before the server accepts requests.

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
- **Refunds**: no refund flow yet. Orders paid after their seats sold out are listed for admins as "needs refund" and must be refunded manually in the PayU dashboard. Then add an admin "mark refunded" action (D21), and exclude refunded bookings from the admin snapshot totals (M8, M9).
- **Coupons**: the checkout coupon box is hidden; coupons need server-side storage and validation in `POST /orders`.
- **Editing an event**: organizers cannot edit an event yet. Any edit to price or date must send the event back to `pending` (D20); existing orders keep their own price.
- **Share-link regeneration** (D25): staff and their organizer can make a new link; the old one stops earning commission.
- **Admin data in pages**: split `/admin/snapshot` into per-tab endpoints with totals computed on the server, then page them (M4). The admin UI currently sums the full lists in the browser.
- **Request IDs in logs**, so an error a user reports can be found in the server log (M5).

**Hardening still open** (see the Issues log in `CLAUDE.md`)
- No "global scanner": admin-created staff must be assigned to an event to scan it (D22, M18).
- Database constraints: foreign key from bookings to events, `CHECK`s on qty/price, case-insensitive unique emails (M3).
- Same answer whether or not an account exists, on every login and lookup route (M6).
- Development OTP fallback only behind an explicit `OTP_DEV_MODE` flag (M7); signup OTP token single use (M17).
- Small global JSON body limit; larger only on authenticated upload routes (M11).
- Remove the APK Google token relay (M12); password policy of 8+ characters everywhere (M13); `helmet` + CSP (M15).
- Finance PIN: explicit set-up flow and attempt limit (M16); admin vs super admin permission matrix (M19).
- `/qr` endpoint limits (L1); input validation on event and assignment fields (L5); restrict the Firebase API key (L7); frontend clean-up of dead code and browser-only admin controls (L8, L9).
