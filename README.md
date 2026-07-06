# IOC Analyzer

Paste an IP, domain, file hash, or URL and get a VirusTotal scan report plus a short
analyst-style summary from an LLM (via OpenRouter).

Two independent apps in one repo:

- `backend/` — FastAPI (Python), serves the REST API on `:8000`
- `frontend/` — Next.js 14 App Router (React), UI on `:3000`, talks only to the backend
  (never touches VirusTotal/OpenRouter directly — keys stay server-side)

## Getting started

### Backend

```bash
cd backend
python3 -m venv venv && source venv/bin/activate   # first time only
pip install -r requirements.txt
cp .env.example .env   # then fill in VT_API_KEY, OPENROUTER_API_KEY

fastapi dev app/main.py --port 8000       # recommended, autoreload
# or: python -m uvicorn app.main:app --reload --port 8000
```

Must run from `backend/` — imports resolve as `app.main`; running from elsewhere fails
with `ModuleNotFoundError: No module named 'app'`.

- Swagger UI: http://127.0.0.1:8000/docs
- Verify API keys are valid: `curl http://localhost:8000/health/check-keys`

### Frontend

```bash
cd frontend
npm install
npm run dev      # dev server on :3000
```

## Architecture

Request flow: `frontend/lib/api.js` → FastAPI router → service module → external API
(VirusTotal / OpenRouter) → JSON back → React component renders it.

### Backend (`backend/app/`)

- `main.py` — creates the `FastAPI()` instance, adds CORS, mounts the routers.
- `config.py` — loads `VT_API_KEY`, `OPENROUTER_API_KEY`, `OPENROUTER_MODEL` from
  `backend/.env`. Missing keys fail fast at import time.
- `routers/` — thin HTTP layer, one file per feature:
  - `analyze.py` — single-IOC endpoints (`/analyze`, `/analyze/ip/{ip}`,
    `/analyze/domain/{domain}`, `/analyze/hash/{hash}`, `/analyze/url`,
    `/analyze/report/{ioc}`).
  - `bulk.py` — `/bulk` (full analysis, up to 10 IOCs) and `/bulk/triage`
    (verdicts only, up to 20 IOCs).
  - `health.py` — `/health`, `/health/stats`, `/health/check-keys`.
- `services/` — external API clients, no HTTP awareness:
  - `virustotal.py` — detects IOC type, fetches the VT report, parses stats into a
    verdict (`malicious` / `suspicious` / `clean`).
  - `openrouter.py` — builds a SOC-analyst prompt and returns the model's summary.

### Frontend (`frontend/`)

- `lib/api.js` — the only place that knows the backend's base URL and endpoint shapes.
- `components/ThreatDashboard.jsx` — main page: single-IOC input, tab switcher, session
  stats, lookup history.
- `components/BulkAnalyzer.jsx` — paste many IOCs, triage vs. full mode.
- `components/ThreatCard.jsx` — renders one result: verdict badge, detection bar,
  metadata, AI summary.

## Notes

- Secrets (`backend/.env`, `frontend/.env.local`) are gitignored; never hardcode API keys.
- `NEXT_PUBLIC_API_URL` (frontend) defaults to `http://localhost:8000` if unset.
- No test suite or linter is configured in this repo yet.
