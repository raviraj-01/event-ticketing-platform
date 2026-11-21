# VYBERA

VYBERA is a Node/Express app that serves the single-page frontend and API from the same server.

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
- Android app: `CORDOVA_API_BASE=https://your-backend npm run build:cordova` generates `vybera-cordova/www/` from `public/`, then `cd vybera-cordova && npx cordova build android`. Never edit `vybera-cordova/www/` by hand.
- Project notes, audit and decisions: `CLAUDE.md`.

## Health Check

After starting the server, this URL should return database status:

```text
http://localhost:3003/health
```
# Blak-tickets
