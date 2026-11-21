# Project: <name TBD — currently "BLAK Tickets" (UI) / "VYBERA" (code, repo, package)>

> Working rules for any session: read this file first. Never print, read aloud or commit secrets; never touch `.env`.
> One issue per change → explain → change → test → update this file → commit (`fix(area): ...`).
> DB changes go in migrations, not startup `ALTER`s. Frontend changes go into every HTML copy until they are consolidated (see M14).
> Never delete data, drop tables or delete tracked files without asking Ravi. If intended behaviour is unclear, ask.
> **Never use credentials from any other project.** This repo runs only on Ravi's own test accounts.
> **Never push to or touch the old remotes** (`blak`, `change`, `origin`, `raviraj` in the old `VYBERA/` folder). They belong to the collaborator.

**Repo:** `ticketing-app/` is a fresh repo (2026-11-21) with clean history, created by copying the old `VYBERA/` working tree without `.git` or `.env`. The old folder is left untouched. Ravi will add his own GitHub remote.

**Current phase:** Phase 2 (fixes) in progress, in the order agreed under "Decisions from Ravi".

---

## Overview

An event ticketing platform for India: buyers discover events and book tickets (PayU or manual UPI), creators (organizers) run events and staff, staff sell tickets offline and scan QR codes at the gate, and admins approve creators and moderate the platform.

**Roles**
| Role | Table | How they log in | JWT payload |
|---|---|---|---|
| Buyer | `users` | `/login` (email/phone + password), `/auth/google` (Google ID token), `/social-login` (unverified, see C3) | `{sub, email}` (no `scope`) |
| Creator | `creator_accounts` | `/creator/login`; needs `kyc_status='Approved'` | `{sub, email, scope:'creator'}` |
| Staff | `staff_accounts` | `/staff/login` (login ID / email / phone) | `{sub, staffId, creatorId, scope:'staff'}` (no email) |
| Admin | `admin_accounts` | `/admin/login` | `{sub, email, scope:'admin', adminType:'admin'}` |
| Super admin | `super_admin_accounts` (separate table) | `/admin/login` (checked first) | `{sub, email, scope:'admin', adminType:'super'}` |

Purpose tokens use the same secret: `{scope:'password-reset', email}` (TTL `PASSWORD_RESET_TTL_MINUTES`, default 10) and `{scope:'signup-phone-otp', identifier}` (10 min). All login tokens last **30 days** (`server.js:168`).

**Main flows (as implemented today)**
- Buyer: signup → phone OTP (Twilio Verify) → `/signup` → browse `/events` → pick tier → PayU (`/payments/payu/initiate` → PayU → `/payments/payu/success`) **or** manual UPI ("I have paid" + UTR) → the browser itself calls `POST /bookings` → ticket with QR (`VYBERA-TICKET|bookingId|eventId|qrToken`).
- Creator: `/creator/applications` (+ KYC docs: pan/aadhaar/gst/bank) → super admin verifies every document and approves → `/creator/login` → `/creator/events` (goes **live immediately**, no event approval) → `/creator/staff` + `/creator/staff/:id/assignments` (allocates tier inventory to staff) → `/creator/analytics`, `/creator/finance/unlock` (4-digit PIN).
- Staff: `/staff/login` → `/staff/dashboard` → `/staff/sales` (cash/"online" sale, creates a booking) → `/bookings/scan` → `/staff/withdrawals`.
- Admin: `/admin/snapshot` (everything) → approve/reject creators & KYC docs (super only) → event status → user/staff status → admin accounts (super only).

## Tech stack

Verified against the code on 2026-11-21:
- **Backend:** one file, `server.js` (4,585 lines). Node (local v25.9; README says ≥20), Express 5.2, `pg` Pool, `bcrypt`, hand-written HS256 JWT on Node `crypto` (`server.js:161-202`), `nodemailer`, `qrcode`, `google-auth-library` (added in uncommitted work). Twilio Verify is called through raw `fetch` (no SDK). PayU uses a form post + SHA-512 hash. **Cloudflare R2** storage uses a hand-written SigV4 presigner (`server.js:598-671`), with a fallback to local disk `uploads/`.
- **Frontend:** plain HTML + inline JS, no build step.
  - `public/index.html` (~12,800 lines) is the **only** frontend source (web + APK), served at `/` (see "Frontend consolidation"). The legacy `VYBERA.html` and `prev` were deleted.
  - Firebase JS SDK v10 is loaded from the gstatic CDN in `firebaseconfig.js`. The `firebase` npm dependency is not used by the server.
- **Android:** Cordova (`cordova-android` 15, target SDK 36), app id `com.vybera.app`. Plugins: inappbrowser, customurlscheme (`vybera://`), googleplus, android-permissions.
  - `vybera-cordova/www/` is **generated** (git-ignored) by `CORDOVA_API_BASE=https://… npm run build:cordova`, then `cd vybera-cordova && npx cordova build android`.
  - **Source of truth:** backend = `server.js`, frontend = `public/`.
- **Hosting:** Render (`https://vybera.onrender.com`, referenced in the HTML and `config.xml`).
- **Tests:** none. `npm test` only runs `node --check`.

## How to run locally

1. Node 20+, PostgreSQL (local or hosted).
2. `npm install`
3. Copy `.env.example` to `.env` and fill it in. **Required:** `DATABASE_URL`, `JWT_SECRET` (the server exits without them).
4. `npm start` → http://localhost:3003. `GET /health` checks the DB.
5. Schema = SQL files in `migrations/` (node-pg-migrate). The server runs pending migrations automatically **before** it starts listening; `npm run migrate` runs them by hand. Applied migrations are recorded in table `pgmigrations`.
6. **New DB change = new file** `migrations/NNNN_description.sql` with `-- Up Migration` / `-- Down Migration` sections. Never edit an applied migration, and never add startup `ALTER`s.

**Environment variables read by the code** (names only):
`PORT, APP_BASE_URL, JWT_SECRET, DATABASE_URL, SUPERADMIN_EMAIL, SUPERADMIN_PASSWORD, R2_ENDPOINT, R2_BUCKET, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, GOOGLE_CLIENT_ID, TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN, TWILIO_VERIFY_SERVICE_SID, TWILIO_VERIFY_CHANNEL, SMTP_SERVICE, SMTP_HOST, SMTP_PORT, SMTP_SECURE, SMTP_USER, SMTP_PASS, SMTP_FROM, PASSWORD_RESET_TTL_MINUTES, PAYU_KEY, PAYU_SALT, PAYU_ENV`.
`.env.example` also lists `R2_ACCOUNT_ID`, which is unused. The local `.env` contains `PAYU_TEST_MODE`, which no code reads (`PAYU_ENV` is what selects test or production).

### External accounts / keys you need (create your own test credentials)
Ravi creates **all** of these himself. None of the client's live values are used here. `.env.example` lists the same items as a checklist. Items marked **(client)** are currently hardcoded in the repo with the client's identifiers and must be replaced with your own before you test them.

| # | Create | Where | Fills |
|---|---|---|---|
| 1 | PostgreSQL database (local install, Docker `postgres:16`, or a free Neon/Render DB) | — | `DATABASE_URL` |
| 2 | JWT secret | `node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"` | `JWT_SECRET` |
| 3 | Twilio trial account + Verify service | twilio.com → Verify → Services | `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_VERIFY_SERVICE_SID` (trial can only text verified numbers) |
| 4 | PayU **test** merchant | PayU dashboard → test mode key/salt | `PAYU_KEY`, `PAYU_SALT`, `PAYU_ENV=test` |
| 5 | SMTP sender (a Gmail account with an app password, or Mailtrap for safe testing) | — | `SMTP_*` |
| 6 | Cloudflare R2 bucket + API token. **Required to test creator applications** (KYC documents are stored only in R2, never in public `uploads/`); event banners fall back to local disk without it. | Cloudflare → R2 | `R2_ENDPOINT`, `R2_BUCKET`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY` |
| 7 | Google Cloud OAuth **web** client ID **(client)** | Use the *"Web client (auto created by Google Service)"* of **your Firebase project** (Google Cloud console → Credentials). Firebase popup tokens, GIS and the Android googleplus plugin are all issued for this client, and `/auth/google` only accepts tokens whose audience is this ID. | `GOOGLE_CLIENT_ID` |
| 8 | Google OAuth **Android** client ID **(client)** | same; needs your APK signing SHA-1 | `vybera-cordova/config.xml` `GoogleSignInClientId` |
| 9 | Firebase project **(client)**: `firebaseconfig.js` holds the client's Firebase web config | Firebase console | `firebaseconfig.js` `firebaseConfig` |
| 10 | Super admin login for your dev DB | your choice | `SUPERADMIN_EMAIL`, `SUPERADMIN_PASSWORD` |

Reference: what each variable does.
| Service | Used for | Env / config | Notes |
|---|---|---|---|
| PostgreSQL | all data | `DATABASE_URL` | SSL turned on automatically unless the URL contains `localhost` (`server.js:80`) |
| JWT secret | signing all tokens | `JWT_SECRET` | generate it yourself, e.g. `node -e "console.log(require('crypto').randomBytes(48).toString('hex'))"` |
| Twilio Verify | signup phone OTP (+91 only) | `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_VERIFY_SERVICE_SID`, `TWILIO_VERIFY_CHANNEL` | a trial account can only text verified numbers |
| PayU (India) | online payments | `PAYU_KEY`, `PAYU_SALT`, `PAYU_ENV=test` | test endpoint `https://test.payu.in/_payment` |
| SMTP (e.g. a Gmail app password) | password-reset email | `SMTP_SERVICE` or `SMTP_HOST`, `SMTP_PORT`, `SMTP_SECURE`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM`, `APP_BASE_URL` | |
| Cloudflare R2 | KYC docs, banners, profile images, ticket JSON | `R2_ENDPOINT`, `R2_BUCKET`, `R2_ACCESS_KEY_ID`, `R2_SECRET_ACCESS_KEY` | KYC, banner and profile uploads **require** R2; other uploads fall back to `uploads/` |
| Google OAuth (web client) | `/auth/google` ID-token login | `GOOGLE_CLIENT_ID` | |
| Google OAuth (Android client) | Cordova googleplus plugin | `vybera-cordova/config.xml` `GoogleSignInClientId` | |
| Firebase project | frontend Google popup sign-in | `firebaseconfig.js` (public web config) | restrict the API key in Google Cloud console |
| Super admin bootstrap | first super admin | `SUPERADMIN_EMAIL`, `SUPERADMIN_PASSWORD` | re-applied on **every** boot (see M1) |
| Render | hosting | — | |

## Architecture

```
server.js            config, JWT, middleware, R2 presign, routes, startup (migrate → initDb data fix-ups → listen)
migrations/          versioned SQL migrations (node-pg-migrate)
src/db/migrate.js    migration runner (used at startup and by npm run migrate)
public/index.html    live web SPA (was vybera_26.html; all roles in one page, "pages" toggled by showPage)
public/firebaseconfig.js  Firebase Google sign-in helper (ES module, CDN imports)
public/assets/       logos (BLAK Tickets)
public/              the ONLY folder served by express.static (H1)
uploads/             local file fallback (git-ignored, publicly served at /uploads)
scripts/build-cordova.js  generates vybera-cordova/www/ from public/
vybera-cordova/      Cordova Android project; www/ is generated, never edit it
```

**Request flow:** `cors` (reflects any origin) → a hand-written CORS/COOP middleware → `bodyParser.json({limit:'30mb'})` → `express.static(public/)` (fixed H1; previously the whole repo root) → routes. Auth is per-route middleware: `requireCreator`, `requireAdmin`, `requireSuperAdmin`, `requireStaff`, `requireBuyer`, `requireScanIdentity`, `requireProfileIdentity`. Tokens are sent as `Authorization: Bearer`. The frontend stores them in `localStorage` (`VYBERA_BUYER_TOKEN`, `VYBERA_CREATOR_TOKEN`, `VYBERA_STAFF_TOKEN`, `VYBERA_ADMIN_TOKEN`).

**Key tables** (created in `initDb`, `server.js:750-1071`):
- `users`: buyers. `email` UNIQUE (case-sensitive); `phone` not unique; `status` Active/Suspended.
- `bookings`: PK `id TEXT`, **chosen by the client**. Has `user_id` (FK → users), `event_id` (**no FK**), price/qty/total, `status`, `qr_token`, `scanned_at`, `staff_id`, `staff_ref`.
- `creator_accounts` (+ `finance_pin`) and `creator_kyc_documents` (document type, object key, verification status).
- `creator_events`: PK `EVT-…`. `tickets` is a **JSONB array of tiers** `{name, price, qty, perks}`, where `qty` = tier inventory still unallocated to staff. `capacity` is never enforced. `booking_count`/`revenue` are denormalised and recomputed after sales.
- `admin_accounts` and `super_admin_accounts` (separate tables; legacy "Super Admin" rows are migrated over on boot).
- `staff_accounts`: `creator_id` NULL means admin-created staff. Login identifiers: `staff_id` (unique), `email`, `phone` (both non-unique). `share_token`.
- `staff_assignments`: tier inventory allocated to staff. `allocation_mode` is `creator_quota` (staff earns a commission) or `staff_owned` (staff resells), with `commission_rate`, `purchase_price`, `resale_price`, `sold_count`.
- `staff_sales` and `staff_withdrawals`.
- `payment_transactions`: PK `txnid` (**client-chosen**). Holds the PayU status and a `verified` flag. Not linked to bookings by any constraint.
- **No indexes** beyond PKs/UNIQUEs (M2). Schema history: `migrations/` (`0001_baseline.sql` = the old startup schema, unchanged).

## Frontend consolidation (M14), done 2026-11-21
**Single source:** `public/index.html` (was `vybera_26.html`). The Cordova app's `vybera-cordova/www/` is **generated** by `npm run build:cordova` (`scripts/build-cordova.js`, requires `CORDOVA_API_BASE=https://…`). Never edit `www/` by hand.

**How platform differences are kept:**
- App-only CSS lives in `<style data-platform="app" media="not all">` blocks, placed at the same cascade position they had in the old Cordova file. The build script flips them to `media="all"`, so web styling is unchanged and the APK keeps its black/grey palette and mobile layout.
- App-only head scripts (`cordova.js`, `window.VYBERA_API_BASE`) are injected at the `<!-- CORDOVA_HEAD_INJECT … -->` marker.
- App-only JS stays behind `window.cordova` checks, so it is inert on web.

**Ported from the Cordova copy (now on both platforms):**
1. App palette (`--purple/--neon/--grey/--muted/--brick/--teal`) as an app-only `:root` override.
2. APK mobile layout CSS (`@media(max-width:700px)` block: bottom nav, creator nav, KPI grid, create-event, venue map, category grid), app-only.
3. Page/logo enter animations (`bltPageEnter`, `bltLogoEnter`), app-only.
4. Admin panel mobile CSS (admin modal contrast, tables, bottom-sheet modals), app-only.
5. PayU checkout inside InAppBrowser: `getPayUPendingBooking`, `handlePayUInAppResult`, `submitPayUFormInAppBrowser`, `submitCheckoutOnce`, plus the cordova branch in `submitPayUForm` (to be revisited in C4).
6. Creator dashboard KPI trend texts (real numbers instead of placeholders).
7. Admin: suspend/reinstate creator now **calls the API** (`admSetCreatorStatus`, `admReinstateCreator`). On web it previously changed only local state, which was a bug. `(admCreatorsList||[])` null-safety.
8. Admin: staff "pending" badge (yellow).
9. Admin: working permission toggles in the invite form (`_adminPerms`, `toggleAdminPerm`, `setAdminPermState`, role-aware `admShowRolePerms`).
10. Admin: `bindInviteCreateButton` defined before use and bound on `DOMContentLoaded` + `deviceready`.
11. Add-staff form: inline error box (`#addStaffError`, `setAddStaffError`), auto-generated temporary password, submit button disabled while saving.
12. Scanner: `#scannerLaunchOverlay`, `syncScannerViewportState`, Android camera permission request via `cordova.plugins.permissions`, WebView-specific messages.
13. Android back button: `closeActiveAppOverlay` + `handleCordovaBackButton` (`backbutton` event; only fires in Cordova).
14. Admin-login section comments changed from HTML `<!-- -->` to JS `//` inside the script block.

**Deliberately NOT ported:**
- Manual-UPI deep-link launch changes (`intent://pay…`, InAppBrowser `_system`): manual UPI is removed in C4 (decision D3).
- `console.log` lines that printed whole bookings (debug noise, leaks data to logcat).
- The APK's Google sign-in variant (system-browser polling of `/google-token/fetch`, `/social-login`, "local database sign-in" fallback): `/social-login` is removed in C3. The APK now runs the web code path until C3 replaces it with a verified ID-token flow.
- APK `firebaseconfig.js`: the web version is the source (superset). Both contain the **client's** Firebase/OAuth IDs (see branding list); the web copy's `oauthClientId` is truncated, so in-app Google OAuth via that helper is broken on both until C3.

**Verified:** inline scripts parse (0 syntax errors); web page loads with no console errors and the web palette; app blocks are off on web and switch the palette when enabled; the generated `www/index.html` differs from the old Cordova copy only in the items listed above.

## Key design decisions (existing, keep)

| Decision | Reason | Trade-off |
|---|---|---|
| `POST /bookings/scan` runs in a transaction with `SELECT … FOR UPDATE OF b`, checks the staff assignment, returns 403 (wrong event) / 409 (duplicate or refunded), and sets `scanned_at` | Two gates scanning the same QR at once: the second waits on the row lock, then sees `scanned_at` and gets 409. Only one entry. | Holds a row lock for the scan transaction (milliseconds). Whole booking (all qty) is admitted in one scan. |
| `qr_token = crypto.randomBytes(18)` (144 bits) | Unguessable, so a QR can't be forged even if the booking ID is known | Backfills in `/bookings/mine` use 24 bytes, which is inconsistent but harmless |
| Single-use reset links: version number in the token + compare-and-increment in one `UPDATE` | No token table needed; the row lock makes concurrent reuse impossible | Requesting a new link does not invalidate an older unused one until a reset succeeds (both carry the same version) |
| Versioned plain-SQL migrations run before `listen` | Every schema change is reviewable SQL with history; the app never serves requests on an old schema | Startup fails (by design) if a migration fails; a bad migration needs a new fixing migration |
| **Buying requires a logged-in buyer** (D9) | Simple ownership model: every order/ticket has a `user_id`, so C6 access control is one check | One extra step at checkout; softened by OTP signup and by returning the buyer to the same event + selection after login |
| **Orders hold seats for 15 minutes** (D10): event row locked (`SELECT … FOR UPDATE`) while counting `issued tickets + live holds + requested ≤ capacity` (and the tier pool) | Two buyers can never both get the last seat; nobody pays for a sold-out ticket | Lock serialises checkouts per event (milliseconds). Expired holds simply stop counting (no cron needed). A new checkout releases the same buyer's older hold for that event, so one user can't block an event with many open checkouts |
| **Late payment rule** (D10) | PayU can confirm after the hold expired | Re-check seats at callback time: room → `paid` + ticket; no room → `paid_needs_refund`, shown in Admin → Payments → Refunds; refund manually in the PayU dashboard until a refund flow exists |
| **Idempotent callbacks** | Gateways retry callbacks | Already-paid orders return success without re-issuing; unique index on `bookings.order_id` is the database-level guarantee |
| **Free tiers confirmed instantly** (D11) only when the DB price is 0 | No gateway needed for free events | Same inventory lock; max `FREE_TICKETS_PER_USER_PER_EVENT` (default 2) per user per event; `POST /orders` rate-limited per user and IP |
| **Referral credit via `share_token` only** (D12), fixed at order creation, paid out only when the order becomes paid | Nobody can credit an arbitrary staff member; no credit for failed payments | Must be active + assigned to that event and tier; self-referral (same email/phone) earns nothing; commission = subtotal × assignment `commission_rate`, stored as an `active` row that can later be `reversed` (refunds, M9) |
| **Server is the price authority** | Client-sent prices/totals were the root of C4 | Fee % / GST % / limits come from env and are published at `GET /config/public` so the UI shows the same numbers. Coupons are hidden until they exist server-side |
| **Postgres-backed fixed-window rate limiter** (`src/middleware/rateLimit.js`) | Works across restarts and multiple instances without Redis | Up to 2× limit around a window edge; fails open if the DB check errors. Needs `TRUST_PROXY_HOPS=1` on Render so `req.ip` is the real client |
| `requireAdmin` / `requireStaff` re-check account status in the DB on every request | A suspended account loses access immediately | One extra query per request |
| Twilio Verify issues a 10-minute, phone-bound signup token | The OTP state lives at Twilio; the server only signs "this phone was verified" | Token is reusable within 10 minutes (M17) |

## Issues log

Severity: **Critical** = exploitable now, money/accounts at stake. **High** = serious security/logic flaw. **Medium** = correctness/robustness/defence in depth. **Low** = hygiene.
"Ravi#" maps to the numbered known-issues list Ravi gave. All are confirmed by reading the code unless the row says otherwise.

### Critical
| ID | Sev | Area | File:line | Problem | Impact | Status | Fix summary | Commit |
|---|---|---|---|---|---|---|---|---|
| C1 | Critical | Secrets | original project (not this repo) | The original project's own git history contained a `.env`. | Not applicable to this repo. | Won't fix here (not ours) | This repo was started fresh without `.git` or `.env` and never contained a credential; the original project's owners handle their own secrets. | baseline |
| C2 | Critical | Auth | `server.js:4491`; UI `vybera_26.html:6744`, Cordova + `VYBERA.html` copies | Ravi#1. The legacy `POST /auth/reset-password` resets super admin → admin → staff → creator → buyer with only an identifier and a new password. Creator matching is by email, **name**, or **email prefix**. | Anyone can take over the super admin account. | Fixed | Deleted `POST /auth/reset-password`. UI: "Forgot password" asks only for an email → `/auth/forgot-password` (emailed link). New `openResetFromLink` reads `?reset_token=`, strips it from the URL, shows "Set new password" → `/auth/reset-password-by-token`. Tested: legacy route 404; valid token resets; forged token 400; super admin untouched; UI flow end to end. **Gap:** creators/staff/admins have no self-service reset now (Q4). Token reuse is H2. | see change log
| C3 | Critical | Auth | `server.js:4281`; UI `vybera_26.html:6941,6999` (`localGoogleSignInFallback` prompts for "your Google email") | `POST /social-login` issues a 30-day buyer token for **any email in the body**, with no Google verification. It also overwrites that user's name and `auth_provider`. | Account takeover of any buyer; attacker sees their tickets and QR codes. | Fixed | Deleted `POST /social-login`. Every Google path now sends a Google-signed ID token to `/auth/google`: Firebase popup/redirect (`credentialFromResult(...).idToken`), Cordova googleplus (`userData.idToken`, client ID from `/auth/google/client-config`), GIS. Removed: `localGoogleSignInFallback` (email prompt), Cordova Firebase-plugin branch, implicit access-token flow, cached-Firebase-session shortcut. APK InAppBrowser path checks the copied token via `/session`. `/auth/google`: invalid token → 401 (was 500 with library text); requires `email_verified === true`. Tested: `/social-login` 404, forged token 401, credential-less call makes no request. | see change log
| C4 | Critical | Payments/Bookings | `server.js:3544-3786`, `3431`; UI `vybera_26.html:3849` (UPI), `3918` (PayU), `4012` (`persistBooking`) | Ravi#2, worse than listed. `POST /bookings` has no auth and trusts the client for `id`, `price`, `total`, `qty`, `status`, `userId`, `bookedAt`. It has **no capacity or tier-inventory check at all**. `ON CONFLICT (id) DO UPDATE` lets anyone overwrite an existing booking's record and attach a staff member. Any `staffRef` credits a staff member with a sale and commission. The UI itself creates paid tickets after a typed "UTR" (manual UPI) or when the client-computed total is ≤0. `/payments/payu/initiate` takes `amount` and `txnid` from the client. | Free tickets for anyone, unlimited overselling, commission fraud, ticket tampering. | Fixed | Deleted `POST /bookings` and `/payments/payu/initiate`. New `POST /orders` (buyer login required): price from DB tier, inventory reserved under `SELECT … FOR UPDATE` on the event, 15-min hold, free tiers confirmed instantly with per-user limit, referral by `share_token` only. Tickets issued only by the verified PayU callback (`src/services/orders.js`). Manual UPI flow and the hardcoded personal UPI ID removed (D3). Guest fallback `guest@blaktickets.in` removed (D9). Tests: `test/orders.test.js` (18, real Postgres). | see change log
| C5 | Critical | Uploads/XSS | `server.js:1199` `/local-upload`, `1232` `/assets/upload`, `1180` `/r2/upload-url`, `3271` `/r2/ticket-record`, `63` static `/uploads` | All upload endpoints are **unauthenticated**. Any extension is accepted (e.g. `.html`), and files are served from `/uploads` on the app's own origin. `/assets/upload` with `purpose=profile` overwrites **any** user's avatar by `userId`/`email`. `/r2/upload-url` gives anyone a presigned PUT into your bucket. | Stored XSS on the app origin. A victim (e.g. an admin) opens the link, the script reads `localStorage` tokens, and the account is taken over. Also free file hosting and disk/bucket filling. | Fixed | Deleted unused unauthenticated `/local-upload`, `/assets/upload`, `/r2/upload-url`, `/r2/ticket-record`. `saveAsset` now requires `allowedTypes`: type detected from the file's magic bytes (JPEG/PNG/WebP; +PDF for KYC), 5 MB per file, extension taken from the detected type. KYC: one file per type, all validated before any upload, R2 only (503 if storage unavailable). Banner: may fall back to local disk (public image). `/uploads` served with `nosniff`. UI limits/`accept` updated to 5 MB. Tested: HTML-as-PNG 400, SVG 400, 6 MB 413, `.html` name stored as `.png`, no auth 401. **Note:** profile-photo upload has no UI and its endpoint is gone; add a proper authenticated route if wanted. Global 30 MB body limit is still M11. | see change log
| C6 | Critical | Bookings/Access | `server.js:3862`; booking IDs `vybera_26.html:3926` (`'BLT-'+Date.now()`) | Ravi#3. `GET /bookings/:id/ticket` has no auth and returns `qrPayload` + QR image. Online booking IDs are **millisecond timestamps**, so they can be enumerated. | Anyone can walk the ID space, download valid QR codes and get into events on other people's tickets. | Fixed | `GET /bookings/:id/ticket` now needs a login (`requireTicketViewer`, with DB status checks for buyer/creator/staff); one SQL query returns the row only to the owning buyer (`user_id`), the event's creator, or staff with an assignment for that event; everyone else gets the same 404 as a missing ID. `/bookings/mine` and `/profile/tickets` list by `user_id` only (no email matching) and need a buyer token. New booking IDs are random (`BKG-` + 24 hex, from C4). **Behaviour changes:** `?ticket=` share links open only for those three roles; legacy guest bookings (`user_id` NULL) are unreachable for buyers but still visible to the event's creator and assigned staff. Tests: `test/tickets.test.js` (8). | see change log

### High
| ID | Sev | Area | File:line | Problem | Impact | Status | Fix summary | Commit |
|---|---|---|---|---|---|---|---|---|
| H1 | High | Static files | `server.js:61-62` | `express.static(__dirname)` serves the whole project root: `/server.js`, `/prev`, `/package.json`, `/README.md`, `/VYBERA.html`, `/vybera-cordova/www/server.js`, … (`.env` is safe only because dotfiles are ignored by default). | Full backend source disclosure. Attackers read every route and query. **This CLAUDE.md would also be public once deployed**, so do not deploy it before H1 is fixed. | Fixed | Moved browser files to `public/` (`vybera_26.html` → `public/index.html`, `firebaseconfig.js`, `assets/`); `express.static(publicDir, {index:false})`; removed the `/VYBERA` mount and the explicit firebaseconfig route. Verified: source files, CLAUDE.md, `.env` → 404. | `d06d580` |
| H2 | High | Auth | `server.js:4454` | Ravi#4. Reset token is reusable for its whole TTL; it is a stateless JWT tied only to the email. | A leaked or forwarded link can be reused after you change your password. | Fixed | Migration `0003_users_password_version.sql`. The reset token carries `pv` (password_version); the reset is one `UPDATE … SET password_version = password_version + 1 WHERE … AND password_version = pv`, so a link works once, even under concurrent use. Tokens without `pv` are rejected. Tests: 3 in `test/auth.test.js`. (Session revocation on password change comes with H5's `token_version`.) | see change log
| H3 | High | OTP/Cost | `server.js:4052` (routes `4163-4168`, duplicated as `/otp/msg91/*`) | Ravi#5. No rate limit on OTP send. Partly mitigated: only `+91` numbers are accepted, and Twilio Verify has per-number limits plus Fraud Guard. | SMS pumping, Twilio bill, and spamming a victim's phone. | Fixed | Postgres rate limits: OTP send 3/10 min per phone + 10/hour per IP; OTP verify 10/10 min per phone; forgot-password 3/hour per email + 10/hour per IP (same abuse class: messages sent on demand). Removed unused `/otp/msg91/*` aliases. Tests: 4 in `test/auth.test.js`. Needs `TRUST_PROXY_HOPS=1` in production for real per-IP limits. | see change log
| H4 | High | Auth | `server.js:409` (also `requireScanIdentity` `543`, `requireProfileIdentity` `582`) | Ravi#6. `requireCreator` checks only the token, never `kyc_status` in the DB. | A suspended or rejected creator keeps full access (events, staff, finance, scanning) for up to 30 days. | Fixed | `requireCreator` and the creator branch of `requireScanIdentity` now check `creator_accounts.kyc_status = 'Approved'` on every request (`isCreatorApproved`). Tests: `test/auth.test.js` (suspended → 401 on creator routes and scan; pending/rejected → 401). | see change log
| H5 | High | Sessions | `server.js:168` (30-day default), tokens in `localStorage` (4 keys) | Ravi#7. Long-lived bearer tokens with no revocation, readable by any XSS (C5, H7, H8). | One XSS = a 30-day account takeover; logout and suspension don't revoke anything. | Open | 15-min access token + rotating refresh token (stored hashed) + `token_version`. **Pushback, see Q11:** httpOnly cookies work for the web app, but the Cordova app calls `vybera.onrender.com` cross-site, where Android WebView blocks third-party cookies by default. So Cordova needs a refresh token in secure storage + Bearer access token. | – |
| H6 | High | Admin | `server.js:2548`, `2700`, `1024-1070` | Ravi#8. Admin login has no rate limit, lockout, 2FA or audit log. Admin temporary passwords are 6 characters minimum and never force a change. | Brute force or credential stuffing on the most powerful accounts, and no record of who did what. | Open | Login rate limit + lockout, email OTP as the second factor, `admin_audit_log` table, re-enter the password for destructive actions. | – |
| H7 | High | XSS | `vybera_26.html:4317` (and many of its 161 `innerHTML` uses; `escapeHtml` is used in only ~25 places); e.g. `10874` staff-sale buyer name | Creator-supplied event fields (date, city, venue, status) and buyer names are concatenated into `innerHTML` without escaping. | A creator plants script in an event and it runs for every buyer who views it (steals tokens). | Open | Escape every interpolated value (or use `textContent`), plus a CSP. Do this after the HTML consolidation (M14). | – |
| H8 | High | XSS | `server.js:3392-3400` | `payuReturnHtml` puts POSTed fields (`udf1`, `txnid`, `error`…) inside `<script>` via `JSON.stringify`, which doesn't escape `</script>`. `/payments/payu/success` and `/failure` accept POSTs from any site. | Reflected XSS on the app origin through an auto-submitting form, which steals tokens. | Fixed | The PayU return page is gone: callbacks now 303-redirect to `/?payment=payu&order=<our id>`; no posted value is written into HTML. | see change log
| H9 | High | Payments | `server.js:3356`, `3451`, `3484` | `txnid` is client-supplied and the upsert overwrites an existing row (e.g. flipping a Success back to Pending). The success handler marks Success whenever the hash matches, without checking `status==='success'` or comparing the amount and txnid with what we initiated. Hash compare is not constant-time. | Payment records can be tampered with. Part of the C4 rewrite. | Fixed | Server-generated `txnid`; constant-time reverse-hash check plus key check; status must be `success`; amount must equal the order amount; only verified callbacks are written to `payment_transactions`; retries are idempotent (unique `bookings.order_id`). | see change log
| H10 | High | Money | `server.js:2429-2502`, `2003` | Ravi#9 (withdrawal double-spend): confirmed. The balance check (`staffWalletFor`) and the insert use separate pool queries with no transaction or lock, so N parallel requests each see the full balance. | Staff can withdraw more than they earned. | Open | Transaction + `SELECT … FOR UPDATE` on the staff row, recompute the balance inside it, then insert. **Also see Q5:** cash sales the staff already pocketed count as withdrawable balance. | – |
| H11 | High | Inventory | `server.js:3544` (online), `1906` (assignments), `1633` (capacity) | Ravi#9 (capacity race), worse than a race: online bookings never check or decrement tier inventory or `capacity`. Staff assignments do decrement tier `qty` under `FOR UPDATE` (OK). `capacity` is never validated against the sum of tier quantities. | Overselling. | Fixed | Online sales check event capacity (issued tickets + live holds) and the tier pool inside one transaction holding the event row lock. Mutation-tested: without `FOR UPDATE` the 8-buyers-1-seat test fails 3/3; with it, passes 3/3. | see change log
| H12 | High | Auth/IDOR | `server.js:4561` `/session`; `582` `requireProfileIdentity` → `3816` `/profile/tickets`, `3845` | `/session` checks no scope and looks up `users.id = sub`, so a creator or admin token with `sub=5` returns buyer #5's profile. `requireProfileIdentity` accepts **any** token with an email (creator, admin, even password-reset tokens) and returns all bookings for that email. Creator emails are never verified. | Someone can apply as a creator using a victim's email; once approved, they read the victim's tickets and QRs and other users' PII. | Open | `/session` and profile routes require a buyer token (`requireBuyer`); match bookings by `user_id`; verify creator email at application. | – |
| H13 | High | Auth | `server.js:1457-1495` | Creator login matches by email **or name or email prefix** (`john@a.com` ≈ `john@b.com`), still supports plaintext passwords, and returns `reason: creator_not_found/password_mismatch` + echoes `loginReceived`. | Ambiguous logins, account enumeration, and easier guessing across accounts. | Fixed | `/creator/login`: `WHERE LOWER(email) = $1` only; bcrypt hashes only (plaintext path removed); one generic 401 "Invalid email or password" (no `reason`/`loginReceived`); rate limits 20/10 min per IP and 10/10 min per email. Tests: 4 in `test/auth.test.js`. | see change log
| H14 | High | Privacy (KYC) | `server.js:3256` `/r2/media/*key`, `2919` snapshot | Any R2 object, including Aadhaar/PAN/bank KYC scans, is served to anyone who knows the key (no auth; keys are random but include the creator's email). `/admin/snapshot` sends KYC document data to **non-super** admins too. | Exposure of sensitive government-ID documents. | Open | Separate the public media route (banners/avatars) from a super-admin-only KYC route; strip documents from the snapshot for normal admins. | – |
| H15 | High | Cordova | `vybera-cordova/www/server.js`, `config.xml:42-52` | The APK bundles the full backend source (stale copy). `config.xml` has `<access origin="*">`, `allow-intent http://*`, and `allow-navigation` to `*.ngrok-free.dev` (a dev leftover). | Anyone can unzip the APK and read the backend; the WebView navigation policy is too loose. | Partly fixed | `www/server.js` deleted and `www/` is now generated from `public/`, so no backend source ships in the APK. **Still open:** tighten `config.xml` (`<access origin="*">`, `allow-intent http://*`, ngrok). | see change log
| H16 | High | CORS | `server.js:27-55` | Ravi#10. `origin: true` plus a second hand-written middleware both reflect **any** Origin. Harmless while tokens are Bearer headers, but it becomes **critical the moment cookies are introduced (H5)**. | Cross-site requests with credentials once cookies exist. | Open | Explicit allowlist (web origin, Cordova `https://localhost`), delete the duplicate middleware. Must ship together with H5. | – |

### Medium
| ID | Sev | Area | File:line | Problem | Impact | Status | Fix summary | Commit |
|---|---|---|---|---|---|---|---|---|
| M1 | Medium | DB/startup | `server.js:1024-1076` | `initDb()` runs **after** `app.listen` starts accepting requests (race on first boot). Every boot deletes `admin_accounts` rows with role 'Super Admin' and **overwrites the super admin password** from env. | Super admin password changes are silently reverted on restart; a startup DELETE runs against live data. | Partly fixed | Schema moved to `migrations/` and the server listens only after migrations succeed (no more request-before-table race). **Still open:** super-admin bootstrap overwrites the password from env on every boot and deletes legacy rows. | see change log
| M2 | Medium | DB perf | (no `CREATE INDEX` anywhere) | Ravi#9 (indexes): confirmed missing: `bookings(event_id)`, `bookings(user_id)`, `bookings(LOWER(buyer_email))`, `staff_assignments(staff_id, event_id)`, `staff_sales(staff_id)`, `staff_sales(booking_id)`, `creator_events(creator_id)`, `payment_transactions(booking_id)`. | Full table scans on every dashboard and analytics query. | Open | One migration adding them. | – |
| M3 | Medium | DB integrity | `server.js:752-1007`, `4338`, `2086` | `bookings.event_id` has no FK. No `CHECK (qty>0, price>=0)`. `status` columns are free text. Email UNIQUE is case-sensitive while lookups use `LOWER()`. `users.phone` is not unique (phone login bcrypt-compares *every* matching row). Staff email/phone are login identifiers but not unique (`LIMIT 1` picks an arbitrary one). | Inconsistent data, ambiguous logins, slow logins. | Open | Migration: FK, CHECKs, `UNIQUE (LOWER(email))`, decide phone uniqueness (Q). Check existing data first. | – |
| M4 | Medium | API | `/events` 1558, `/admin/snapshot` 2893, `/bookings/mine` 3788, `/profile/tickets` 3816, `/creator/staff` 1698, `/staff/dashboard` 2221 | Ravi#9 (pagination): no list endpoint paginates. The snapshot dumps **all** users, bookings, payments and staff in one response. Ticket lists render a QR PNG per booking per request. | Slow, memory-heavy, and exposes too much at once. | Open | `limit`/`cursor` params; split the snapshot into per-tab endpoints. | – |
| M5 | Medium | Errors | e.g. `1158`, `1195`, `1228`, `1291`, `1416`, `1694`, `2736`, `2862`, `3291`, `3476`, `3782`, `4104` | `err.message` (DB, R2, Twilio internals) is returned to clients. `uncaughtException` is swallowed and the process keeps running (`14-20`). | Leaks internals; the process can run on in a broken state. | Open | Phase 3 central error handler `{error}` + request-id logging; exit on uncaughtException. | – |
| M6 | Medium | Enumeration | `4351` vs `4361`, `2157` `/staff/lookup`, `2101` vs `2107`, `2182` `/staff/share/:token` (accepts email/phone) | Different messages or status codes reveal whether an account exists. There's a public staff lookup by email/phone. | Account discovery for targeted attacks. | Partly fixed | `/staff/lookup` removed (M20). **Still open:** `/login` 400 "User not found" vs "Invalid password"; `/staff/login` 404 vs 401; `/staff/share/:token` accepts email/phone. | – |
| M7 | Medium | OTP | `server.js:3998-4103` (**uncommitted** work) | The local-dev OTP fallback returns the OTP **in the API response** whenever `Host` contains "localhost", or when Twilio replies 401/403. Behind a reverse proxy that forwards `Host: localhost`, every user gets their OTP in the response. | Phone verification bypass in a misconfigured deployment. | Open | Gate it behind an explicit `OTP_DEV_MODE=true` and `NODE_ENV!=='production'`, never on Twilio errors. | – |
| M8 | Medium | Analytics | `1786` (fee 8%) vs `2539` (net = 94%), `2913`/`2929`/`3082` (no refunded filter), `1989`, staff_owned revenue | The platform fee is 8% in one place and 6% in another. Admin revenue doesn't exclude refunded bookings. `staff_owned` adds the purchase price to `creator_events.revenue`, which the next sale recompute overwrites, and creator gross counts the resale price instead. | Wrong numbers shown to creators and admins. | Open | One fee constant (Q7); one shared revenue query that excludes refunds; define staff_owned accounting (Q5). | – |
| M9 | Medium | Functionality | (10 reads of `'refunded'`, 0 writes) | No refund or cancel flow exists, even though analytics and scan code check `status='refunded'`. | Can't refund; analytics code paths are dead. | Open | Q8. | – |
| M10 | Medium | Functionality | `server.js:864` (`status DEFAULT 'live'`) | Events go live instantly; there is no admin approval step for events (only block/pause afterwards). | Doesn't match the expected "admin approves events" flow. | Open | Q6. | – |
| M11 | Medium | DoS | `server.js:56` | 30 MB JSON body limit on every route, including unauthenticated ones; files are uploaded as base64 inside JSON. | Memory exhaustion with a few parallel requests. | Open | Small global limit (e.g. 100 KB); a larger limit only on authenticated upload routes (or switch uploads to multipart/presigned). | – |
| M12 | Medium | Auth (APK) | `server.js:1092-1108`; `vybera_26.html:6962`, `7019-7040` | Google token relay: unauthenticated store/fetch of `{token, profile}` under any code; the APK accepts whatever it fetches. InAppBrowser `executeScript` reads `localStorage` from the browser tab. | Session-fixation style attacks; fragile login. | Open | Replace with the googleplus plugin `idToken` → `/auth/google`, then delete the relay. | – |
| M13 | Medium | Passwords | `4190` (buyer: no minimum), `4460`/`2700`/`1844` (6 characters) | Weak or inconsistent password policy; temporary passwords never have to be changed. | Weak accounts. | Open | Minimum 8 everywhere, `must_change_password` for temporary passwords. | – |
| M14 | Medium | Frontend | `vybera_26.html`, `vybera-cordova/www/index.html`, `VYBERA.html` | Three diverged copies. The Cordova copy has features web lacks (`admReinstateCreator`, admin permissions, InAppBrowser PayU, back button, `submitCheckoutOnce`); web has Google Identity Services, which Cordova lacks. `VYBERA.html` is dead but served. | Every fix must be made 2-3 times, and the copies drift apart. | Fixed | Merged into `public/index.html` + `scripts/build-cordova.js`; see "Frontend consolidation (M14)". | see change log
| M15 | Medium | Hardening | `server.js` (no `helmet`, no `trust proxy`) | No CSP, HSTS or `nosniff`. Without `trust proxy`, `req.protocol` is `http` behind Render (share URLs come out as `http://`), while PayU `surl` is hard-coded to `https` (breaks local testing). | Weaker browser defences; broken links. | Open | `helmet` + CSP, `app.set('trust proxy', 1)`, build URLs from `APP_BASE_URL`. | – |
| M16 | Medium | Finance PIN | `server.js:2504` | The first PIN anyone submits becomes the creator's finance PIN; it's 4 digits with no attempt limit. | Anyone holding a creator token can brute-force it in at most 10,000 tries. | Open | Set the PIN through an explicit flow, add an attempt limit and lockout. | – |
| M17 | Medium | Signup | `server.js:4036`, `4171` | The OTP token is reusable within 10 min, and the phone is not unique, so one OTP can create several accounts. | Fake account creation. | Open | One-time use (store a jti), decide phone uniqueness. | – |
| M18 | Medium | Scan rule | `server.js:3921` | Admin-created staff with no `creator_id` and no `primary_event_id` can scan tickets for **any** event. (Scan route is otherwise in the keep-as-is list.) | Possibly unintended global scanner. | Open | Q10. Don't change without your answer. | – |
| M20 | Medium | Auth/UI | `public/index.html` login (`doLogin`) | The single login form sends the typed email + password to `/admin/login`, `/staff/login`, `/staff/lookup` and `/creator/login` before `/login` (seen in the network log during the C4 smoke test). | A buyer's password is sent to every role's endpoint; it enables account enumeration, and it will trip admin lockout (H6) for normal buyers. Since H13 the creator step is rate-limited per IP, so many buyer logins behind one NAT can hit 429 on that step. | Fixed | Chose a role switch over a unified server `/login`: one email can legitimately exist in several role tables with different passwords, and admin login needs its own path for H6. Sign-in form has Buyer/Organizer/Staff/Admin; `doLogin()` sends exactly one request (`loginAsBuyer/Creator/Staff/Admin`). Removed the browser-only demo staff check, `staffAccountExists` and the `/staff/lookup` endpoint; hidden staff page now uses the API. "Forgot password" shows only for Buyer (Q4). Verified in the browser: each role → exactly one login request, wrong password → stays on login. | see change log
| M19 | Medium | Admin | `server.js:2875`, `3222` | Any admin can delete admin-created staff whose `created_by_admin_email` is NULL, and can suspend or activate any creator's staff. | Over-broad admin powers. | Open | Decide the admin vs super admin matrix (with H6). | – |

### Low
| ID | Sev | Area | File:line | Problem | Impact | Status | Fix summary | Commit |
|---|---|---|---|---|---|---|---|---|
| L1 | Low | Abuse | `server.js:1162` `/qr` | Ravi#10. Public endpoint renders any text as a QR (CPU, free QR service). It is only used for the staff share link (`vybera_26.html:2964`). | Minor abuse. | Open | Generate the share QR client-side or only for own share URLs; length cap + rate limit. | – |
| L2 | Low | Bug | `server.js:59` | Favicon route points to `assets/blak-tickets-logo.svg`; the file is actually `blak-ticket-logo.svg`. | 404 / error log on every page load. | Fixed | Path corrected while moving assets (part of the H1 commit). | `d06d580` |
| L3 | Low | Cleanup | `prev`, `VYBERA.html` | An old server copy and an old frontend copy are tracked and publicly served. | Confusion, source disclosure (H1). | Fixed | Deleted `prev` and `VYBERA.html` (approved D6). | see change log
| L4 | Low | JWT | `server.js:161-202` | Ravi#11. The hand-written JWT is actually implemented safely (fixed HS256, timing-safe compare, exp checked), but it has no `iss`/`aud`, and one secret serves session, reset and OTP tokens (only `scope` separates them). | Token-confusion risk (see H12). | Open | Switch to `jose` with `aud` per token type; do it together with H5. | – |
| L5 | Low | Validation | `1928`, `1594-1684` | Commission rate is unbounded (>100%). Event date and time are free text; lat/long, banner URL and visibility are unvalidated. | Bad data. | Open | Input validation on create endpoints. | – |
| L6 | Low | Repo hygiene | `.gitignore`, `.env.example` | `.env.local` / `.env.*` weren't ignored (fixed in Phase 0). `.env.example` lists the unused `R2_ACCOUNT_ID`. The local `.env` holds commented plaintext login credentials and an unused `PAYU_TEST_MODE`. The `firebase` npm dependency is unused. | Accidental secret commits. | Partly fixed | `.gitignore` updated. Ravi: remove the commented credentials from `.env`. | – |
| L7 | Low | Firebase | `firebaseconfig.js:16-23` | Public Firebase web config (normal), but the API key should be restricted to your domains/app. | Quota abuse. | Open | Restrict it in Google Cloud console (Ravi). | – |
| L8 | Low | Frontend debugging | `public/index.html:818` | Every `console.*` method is replaced with a no-op unless `window.VYBERA_DEBUG` is set. | Frontend errors are silently swallowed in production and during testing; bugs are harder to find. | Open | Remove the override, or keep `console.error` and send errors to a log endpoint. | – |

### Verified "keep as-is" items
- `POST /bookings/scan`: confirmed (transaction, `FOR UPDATE OF b`, assignment check, 403/409, `scanned_at`). Only M18 is questionable. `requireScanIdentity` inherits H4 for creators (no DB status check); the SQL already checks that staff are active.
- `qr_token` 18 random bytes: confirmed (24 in backfills).
- `requireAdmin` / `requireStaff` DB checks: confirmed. Note: `requireAdmin` upgrades a normal admin token to super if its email exists in `super_admin_accounts`. That's fine while the JWT secret is safe (C1).
- Twilio Verify flow: confirmed (only touched by M7/M17).

## Phase 2 order (agreed with Ravi 2026-11-21)
1. Fresh repo with clean history ✅ (`f915baf`)
2. Static-serving fix (H1): serve only `public/`; CLAUDE.md must never be public
3. C2 → C3 → C5 → C4 (with H9, H11) → C6
4. High items, then Medium/Low, then Phase 3 restructure + tests

Frontend consolidation (M14) happens before the first frontend-touching fix (C2), because otherwise every fix has to be made in 2-3 diverged copies.

## Decisions from Ravi (2026-11-21)
| # | Topic | Decision |
|---|---|---|
| D1 | Other projects' credentials (C1) | Never used here. Ravi creates his own DB, JWT secret, Twilio test account, PayU test keys and SMTP. |
| D2 | Git history | No force-push, don't touch the old remotes. Fresh repo, current working tree as the baseline commit; Ravi adds his own remote. |
| D3 | Manual UPI "I have paid" | **Remove.** Payments go only through the gateway (test mode); bookings are confirmed only by a verified callback. |
| D4 | Staff cash sales | Cash a staff member collects is **money owed to the organizer**, not withdrawable. Only earned commission is withdrawable. Track cash owed separately. |
| D5 | Platform fee | One constant `PLATFORM_FEE_PERCENT` (default 8), loaded from config; remove every hardcoded copy. |
| D6 | Frontend cleanup | `vybera_26.html` is the base. Port the Cordova-only features, list them here **before** deleting, then delete `VYBERA.html`, `prev`, `vybera-cordova/www/server.js`. The Cordova build copies from one frontend source. |
| D7 | Sessions | httpOnly cookies on web; short-lived Bearer access token + refresh token in secure storage on the APK; lock CORS to explicit origins in the same change. |
| D9 | Guest checkout | **Buying requires a buyer login.** Guests browse only. Remove the `guest@blaktickets.in` fallback everywhere. `user_id` always comes from the token. Ticket access (C6) = owning buyer, the event's creator, or staff assigned to the event; everyone else 404. Logged-out "Book" → login/OTP → back to the same event + selection. Existing guest bookings: keep the rows, but make them unreachable through the API. |
| D10 | Inventory | 15-minute hold at order creation, atomic (event row lock), expired holds stop counting, late-payment rule (re-check → `paid` or `paid_needs_refund`), idempotent callbacks, max qty per order (10), race test required. |
| D11 | Free tiers | Confirm instantly only when the DB price is 0; buyer login required; same atomic inventory check; status `paid`, amount 0, method `free`; per-user limit (default 2) per event; rate limit per user + IP; no platform fee; no commission. |
| D12 | Staff referral | `share_token` only, resolved at order creation; active + assigned to the event/tier; commission computed server-side, only when paid; no self-referral; reversal by status, never deletion; staff/creator can regenerate the token. |
| D13 | Coupons | Keep hidden at checkout for now. Server-side coupons are built **after all High items**. |
| D14 | Hold release | Approved: a new checkout releases the same buyer's earlier pending hold for that event. |
| D15 | Proxy | `TRUST_PROXY_HOPS` approved; documented in README → Deploy (Render = 1). |
| D16 | Legacy guest bookings | Visible to the event's creator and assigned staff (needed for scanning); hidden from buyers. Current C6 behaviour is correct. |
| D17 | Order of work after the Criticals | M20 → H7 → H5+H16 → H10 → H6 → H12/H14/H15 → server-side coupons → remaining Medium/Low. Every fix adds a 2-line Interview note. |
| D8 | Static files | Serve only a dedicated `public/` folder; CLAUDE.md is never public. |

Still open (ask when reached): password reset for non-buyers (old Q4), event approval before live (Q6), refunds in v1 (Q8), global scanner staff (Q10, M18), unique phone per buyer (Q12), staff_owned upfront payment (rest of Q5).

## Change log
| Date | Change | Why |
|---|---|---|
| 2026-11-21 | Created CLAUDE.md with the Phase 0 inventory and Phase 1 audit. Added `.env.*` (except `.env.example`) to `.gitignore`. | Ravi's audit request; prevent committing env variants. |
| 2026-11-21 | Fresh repo `ticketing-app/` (baseline `f915baf`), copied from the working tree without `.git`/`.env`. Scanned the copy: no live secret value is present in any file. | Remove `.env` from our history without rewriting the collaborator's remotes (D2). |
| 2026-11-21 | H1: only `public/` is served; app HTML is now `public/index.html` (alias `/vybera_26.html` kept). L2 favicon path fixed. | Source code and CLAUDE.md were publicly downloadable (D8). |
| 2026-11-21 | M20: sign-in form with a role switch; the password goes to one endpoint only; removed `/staff/lookup` and the demo staff login. | A buyer's password was sent to admin, staff and creator logins. |
| 2026-11-21 | H3: rate limits on OTP send/verify and forgot-password; removed `/otp/msg91/*` aliases. | SMS pumping and email/SMS bombing of victims. |
| 2026-11-21 | H2: single-use reset links via `users.password_version` (migration 0003). | A leaked reset link could be reused for its whole lifetime. |
| 2026-11-21 | H13: creator login by exact email only, bcrypt only, generic error, rate limited. | Name/email-prefix matching, account enumeration, plaintext passwords. |
| 2026-11-21 | H4: creator routes re-check approval status in the DB on every request. | Suspended creators kept access for up to 30 days. |
| 2026-11-21 | C6: ticket endpoint requires owner buyer / event creator / assigned staff (404 for everyone else); buyer ticket lists by `user_id` only; frontend sends the viewer's token; shared test fixtures `test/helpers/fixtures.js`. | QR payloads were public and guest tickets leaked via email matching. |
| 2026-11-21 | C4 (+H8, H9, H11): server-side orders (`POST /orders`, `GET /orders/:id`, PayU callbacks → 303 redirect), migration `0002_orders.sql` (orders, `bookings.order_id`, `staff_sales.status/order_id`, `rate_limit_hits`), `src/services/{orders,payu}.js`, `src/middleware/rateLimit.js`, `src/utils/events.js`. Frontend: login-gated checkout with resume-after-login, server-confirmed tickets only, manual UPI removed, availability from server, refunds-needed list for admins. 18 integration tests. | Free/forged tickets, overselling, commission fraud, payment tampering (D9-D12). |
| 2026-11-21 | Versioned SQL migrations (node-pg-migrate 9). `0001_baseline.sql` holds the old startup schema verbatim; startup is now migrate → data fix-ups → listen. Added `embedded-postgres` (dev) for real-Postgres integration tests. | Ravi's rule: DB changes as migrations (needed by C4); M1 startup race. |
| 2026-11-21 | C5: deleted 4 unauthenticated upload routes; all uploads validated by magic bytes, 5 MB cap, safe extensions; KYC R2-only; `/uploads` nosniff. | Anyone could host HTML on our domain (token theft) or overwrite avatars. |
| 2026-11-21 | C3: removed `/social-login`; all Google sign-in paths send a verified Google ID token to `/auth/google`; forged tokens get 401. | Anyone could log in as any buyer by sending their email. |
| 2026-11-21 | C2: removed the unverified legacy reset route; UI uses the emailed token flow (new reset-link handler). | Anyone could reset any account, including super admin. |
| 2026-11-21 | Deleted `VYBERA.html`, `prev`, `vybera-cordova/www/server.js`; untracked generated `vybera-cordova/www/` and git-ignored it. | D6; stops backend source shipping in the APK (H15) and stops copies drifting (M14). |
| 2026-11-21 | M14: Cordova-only features merged into `public/index.html`; `scripts/build-cordova.js` generates `vybera-cordova/www/`. | One frontend source, so every fix is made once (D6). |
| 2026-11-21 | `.env.example` rewritten as a checklist of Ravi's own test accounts (dropped the unused `R2_ACCOUNT_ID`); CLAUDE.md records decisions D1-D8. | C1 / D1. |

## Before calling the project done (Ravi's acceptance list)
- [ ] Real PayU **test-mode** checkout end to end (Ravi's own test merchant key/salt).
- [ ] Android build installed and tested on a real device (`npm run build:cordova` → `cordova build android`).
- [ ] Rename/rebrand (Ravi gives the name; see "Branding/cleanup to do").

## Open questions for Ravi
(Answered ones moved to "Decisions from Ravi".)
- Q14. PayU requires a phone number. Google-only buyers may have none; we send the placeholder `9999999999`. Collect a phone before checkout instead?
- Q15. Share-token regeneration (D12) needs a UI button and an endpoint. Should staff do it, the creator, or both?
- Q4. **Password reset for non-buyers** once the legacy route is gone: creators → same email-token flow; staff → reset by their creator/admin; admins → by super admin; super admin → DB/CLI only. OK?
- Q5b. In `staff_owned` mode, does staff pay the creator the purchase price upfront? Who pays commission withdrawals (platform or creator)?
- Q6. Should creator events need **admin approval** before going live?
- Q8. Are **refunds** needed for v1? Who triggers them, and should they go through the PayU refund API?
- Q10. Should admin-created staff with no event be able to scan **any** event (M18)?
- Q12. Phone number unique per buyer account?

## Branding/cleanup to do (don't rename until Ravi picks a name)
- **Names:** "BLAK Tickets" (server.js ×13, vybera_26.html ×51, Cordova index ×49, VYBERA.html ×14, config.xml ×3, Cordova package.json). "VYBERA"/"Vybera" (≈170-250 per HTML file, package name, repo name, README, `localStorage` keys `VYBERA_*`, `window.VYBERA_API_BASE`).
- **QR prefix:** `VYBERA-TICKET` (`server.js:3403`, `3886`). Renaming breaks already-issued tickets unless scan accepts both prefixes during a transition.
- **Domains/emails:** `vybera.onrender.com` (HTML, `config.xml`), `vybera.in` / `support@vybera.in` (`config.xml`, `VYBERA.html`), `superadmin@blaktickets.in` (default, `server.js:1025`), `guest@blaktickets.in` (`server.js:3460`), `blaktickets` in the HTML (×5).
- **App identity:** Cordova id `com.vybera.app`, URL scheme `vybera://`, display name, Firebase project `vybera` (`firebaseconfig.js`), Google client IDs (`config.xml`, `.env`).
- **Payment identity:** a personal UPI ID and payee name are hardcoded at `vybera_26.html:3808-3809` (and the Cordova copy). These are a real person's payment details; replace with config.
- **Logos:** `assets/blak-ticket-logo.{svg,jpeg}`, `blak-ticket-name.{svg,jpeg}`, `balk-ticket-logo-2.jpeg` (typo), Cordova `resources/` icons + splash, `www/assets/` copies. Hardcoded HTML pages in `server.js:1111` (Google success) and `3392` (PayU return), and the reset email template `4404-4436`.
- **Documents:** no privacy/T&C/press/blog PDFs exist in the repo. The signup "Terms" and "Privacy" are non-clickable text (`vybera_26.html:825`), so there is nothing to link yet.
- **Dead files:** deleted 2026-11-21 (`prev`, `VYBERA.html`, `vybera-cordova/www/server.js`).

## Interview notes
_(One entry per fixed issue: a 2-line explanation to say out loud.)_

- **H1 static files:** "The server used `express.static` on the project root, so anyone could download `server.js` and internal docs. I moved browser files into a `public/` folder and serve only that, so the attack surface is an explicit allowlist instead of everything on disk."
- **M14 one frontend source:** "We had a web HTML and an APK HTML that had drifted by about 900 lines, so every fix had to be made twice. I merged them into one file. Platform-only CSS sits in a disabled style block that the Cordova build script switches on, so both platforms look the same as before but there's a single place to fix bugs."
- **C2 legacy password reset:** "There was an endpoint that changed any account's password if you just knew the email, including the super admin's. I deleted it and made the UI use the proper flow: we email a short-lived signed link, and only someone holding that link can set a new password."
- **C3 unverified social login:** "The Google login endpoint trusted whatever email the browser sent, so you could log in as anyone. Now the browser must send the ID token Google signed, and the server verifies Google's signature and that the token was issued for our client ID before creating a session."
- **C5 upload validation:** "Uploads had no login and no type check, so someone could upload an HTML file that ran as a page on our domain and stole tokens. I removed the unused upload routes, and the remaining ones check the file's real first bytes against an allowlist, cap the size, and pick the file extension themselves instead of trusting the browser."
- **C4 server-side orders:** "The browser used to send the price and say 'I paid', and the server believed it. Now the browser only says which ticket and how many; the server reads the price from the database, reserves seats under a row lock so two people can't buy the last seat, and only issues the ticket when PayU's signed callback is verified."
- **H11 overselling / race condition:** "I lock the event row with SELECT … FOR UPDATE, count sold tickets plus 15-minute holds, and insert the order in the same transaction. I proved the test is real by removing the lock: the eight-buyers-one-seat test then fails every time."
- **C6 ticket access:** "The ticket endpoint returned the QR code to anyone who knew the booking ID, and old IDs were just timestamps. Now one SQL query returns the ticket only if you're its buyer, the event's creator or assigned staff; everyone else gets the same 404 as a missing ticket, so you can't even tell which IDs exist."
- **H4 creator status check:** "The creator middleware only checked that the token was signed, so a suspended creator kept working for 30 days. Now every creator request also checks the account is still approved in the database, the same as we already did for admins and staff."
- **H13 creator login:** "Creator login matched by email, by name or by the part before the @, and told you whether the account existed. Now it's an exact email match, bcrypt only, one generic error for every failure, and a rate limit per IP and per email."
- **H2 single-use reset link:** "The reset link was a stateless token, so it worked again and again until it expired. I added a password_version column, put the version in the link, and the reset is one UPDATE that only matches the current version and increments it. The first use wins and every reuse finds nothing to update."
- **H3 OTP rate limit:** "Anyone could make our server send unlimited SMS codes, which costs money and can spam a victim. I added a Postgres-backed limiter: three OTPs per phone per ten minutes and ten per IP per hour, and the same idea for password-reset emails."
- **M20 one login endpoint:** "The login form sent whatever you typed to the admin, staff, creator and buyer endpoints one after another, so a buyer's password reached the admin login. Now you pick your role and the password goes to exactly one endpoint; I chose this over a server-side 'guess the role' login because one email can exist in several roles with different passwords."
