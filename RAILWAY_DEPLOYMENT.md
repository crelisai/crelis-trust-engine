# Deploying the Crelis Trust Engine to Railway

A step-by-step guide for deploying this repo to [Railway](https://railway.app).
Everything Railway needs is already in the repo:

| File | Purpose |
|---|---|
| `requirements.txt` | Pinned production dependencies (fastapi, uvicorn, pydantic) |
| `requirements-dev.txt` | Test tooling — NOT installed in production |
| `Procfile` | Start command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT` |
| `railway.json` | Build/deploy config: health check on `/health`, auto-restart on failure |
| `.python-version` | Pins Python 3.12 so Railway builds with the version we tested |

CORS is already configured for `https://crelis.ai`, `https://www.crelis.ai`,
and `https://demo.crelis.ai` (plus localhost dev servers). Additional origins
can be granted later via the `CORS_EXTRA_ORIGINS` env var — no code change.

---

## Step 1 — Push the latest code to GitHub

Railway deploys from your GitHub repo, so make sure `main` is up to date:

```bat
git status
git push origin main
```

## Step 2 — Create the Railway project

1. Go to **https://railway.app** and sign in **with your GitHub account**
   (the `crelisai` org account that owns the repo).
2. Click **New Project** → **Deploy from GitHub repo**.
3. If asked, click **Configure GitHub App** and grant Railway access to the
   `crelisai/crelis-trust-engine` repository.
4. Select **crelisai/crelis-trust-engine**.
5. Railway detects Python automatically, reads `railway.json` + `Procfile`,
   and starts the first build. Wait for the build log to end with
   `Deploy complete`.

## Step 3 — Generate the public URL

1. Open the service → **Settings** tab → **Networking** section.
2. Click **Generate Domain**.
3. You'll get a URL like `https://crelis-trust-engine-production.up.railway.app`.

## Step 4 — Verify the deployment

Open these in your browser (replace with your actual Railway URL):

1. **Health check** — `https://<your-app>.up.railway.app/health`
   Expected response:
   ```json
   {"status":"ok","engine":"Crelis Trust Engine","version":"0.1.0","policies_loaded":5}
   ```
2. **Interactive docs** — `https://<your-app>.up.railway.app/docs`
   Use "Try it out" on `POST /trust/evaluate` with the example payload.

Railway itself also pings `/health` (configured in `railway.json`) — if the
engine ever stops answering, Railway restarts it automatically.

## Step 5 — (Optional) Custom domain `api.crelis.ai`

1. Service → **Settings** → **Networking** → **Custom Domain**.
2. Enter `api.crelis.ai`.
3. Railway shows you a CNAME record. Add it in your DNS provider
   (wherever crelis.ai's DNS lives — e.g. Cloudflare/Namecheap):
   `CNAME api → <value Railway shows>`.
4. Wait for DNS to propagate (minutes to an hour). Railway provisions HTTPS
   automatically.

## Step 6 — Point the demo frontend at the API

In the demo site's code, set the API base URL to the Railway URL
(or `https://api.crelis.ai` once Step 5 is done). The browser will be allowed
to call it because CORS already grants `demo.crelis.ai` and `crelis.ai`.

If you ever need to allow another origin (e.g. a staging site), add an env var
in Railway — **Variables** tab:

```
CORS_EXTRA_ORIGINS=https://staging.crelis.ai
```

and redeploy. Comma-separate multiple origins.

---

## Things to know (v0.1 limitations in production)

* **The audit log is in-memory.** Every redeploy or restart clears it, and if
  Railway ever runs more than one instance they won't share a log. Fine for a
  demo; v0.2's database persistence fixes this.
* **No authentication yet.** The API is publicly callable once deployed. For a
  demo that's acceptable, but don't point real systems at it until v0.2 adds
  API keys.
* **Single worker.** The Procfile runs one uvicorn worker, which is right for
  the in-memory design (multiple workers would each keep their own audit log).

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| Build fails on dependencies | Check the build log; the pins in `requirements.txt` were verified against Python 3.12 — confirm `.python-version` was committed. |
| `Application failed to respond` | Check **Deployments → View Logs**. The start command must bind `0.0.0.0:$PORT` (the Procfile already does). |
| Health check fails, deploy rolls back | `/health` must return 200 — run `pytest` locally; if green, check the deploy logs for import errors. |
| Browser console shows CORS error | The calling site's origin isn't in the allow-list — add it via `CORS_EXTRA_ORIGINS` (exact scheme + host, no trailing slash). |
