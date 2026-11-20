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
- The frontend calls the API on the same origin when served from `http://localhost:3003`.
- If you open the HTML file directly, browser login/API calls will still try `http://localhost:3003`, so keep the Node server running.

## Health Check

After starting the server, this URL should return database status:

```text
http://localhost:3003/health
```
# Blak-tickets
