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

## Deploy (e.g. Render)

1. Create a PostgreSQL database and set every variable from `.env.example` in the host's environment (never commit `.env`).
2. Set `APP_BASE_URL` to the public https URL (used for PayU return URLs and email links).
3. **Set `TRUST_PROXY_HOPS=1` on Render** (or the number of reverse proxies in front of the app). Without it every visitor appears to have the proxy's IP, so all per-IP rate limits (OTP, login, orders) would be shared by everyone. Locally keep it `0`, otherwise clients could fake their IP with an `X-Forwarded-For` header.
4. Serve the app over **https** (Render does). Session cookies are `Secure` when `APP_BASE_URL` starts with `https://`, and browsers drop them on plain http in production.
5. If the frontend is served from another origin, list it in `CORS_ORIGINS`. The Android app's WebView origin `https://localhost` is allowed by default.
6. Start command: `npm start`. Pending database migrations in `migrations/` run automatically before the server accepts requests.

## Tests

`npm test` starts a throwaway real PostgreSQL (embedded-postgres, downloaded on first `npm install`) and the real server, then runs the integration tests in `test/`.

## Health Check

After starting the server, this URL should return database status:

```text
http://localhost:3003/health
```

## Future work (out of scope for the current release)

- **Staff resale** ("staff buys inventory from the organizer and resells it"): disabled in the UI and API. Needs a decision on how the staff member pays the organizer up front and who pays out the resale money.
- **Refunds**: no refund flow yet. Orders paid after their seats sold out are listed for admins as "needs refund" and must be refunded manually in the PayU dashboard.
- **Coupons**: the checkout coupon box is hidden; coupons need server-side storage and validation in `POST /orders`.
