# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project overview

IOC (Indicator of Compromise) analyzer: paste an IP, domain, file hash, or URL; the backend
queries VirusTotal for a scan report and asks an LLM (via OpenRouter) for a short
analyst-style summary. Two independent apps in one repo:

- `backend/` — FastAPI (Python), serves the REST API on :8000
- `frontend/` — Next.js 14 App Router (React), UI on :3000, talks only to the backend
  (never touches VirusTotal/OpenRouter directly — keys stay server-side)

## Commands

### Backend

    cd backend
    python3 -m venv venv && source venv/bin/activate   # first time only
    pip install -r requirements.txt
    cp .env.example .env   # then fill in VT_API_KEY, OPENROUTER_API_KEY

    fastapi dev app/main.py --port 8000       # recommended, autoreload
    # or: python -m uvicorn app.main:app --reload --port 8000

Must run from `backend/` — imports resolve as `app.main`; running from elsewhere fails
with `ModuleNotFoundError: No module named 'app'`.

- Swagger UI: http://127.0.0.1:8000/docs
- Verify API keys are valid: `curl http://localhost:8000/health/check-keys`

No test suite or linter is configured in this repo yet.

### Frontend

    cd frontend
    npm install
    npm run dev      # dev server on :3000
    npm run build
    npm run start

## Architecture

Request flow: `frontend/lib/api.js` → FastAPI router → service module → external API
(VirusTotal / OpenRouter) → JSON back → React component renders it.

### Backend layers (`backend/app/`)

- `main.py` — creates the single `FastAPI()` instance, adds CORS (allows `localhost:3000`),
  mounts the three routers.
- `config.py` — `Settings` (pydantic-settings) loads `VT_API_KEY`, `OPENROUTER_API_KEY`,
  `OPENROUTER_MODEL` from `backend/.env`, resolved relative to this file so it works
  regardless of cwd. Missing keys fail fast at import time.
- `routers/` — thin HTTP layer, one file per feature. Each handler: parse input → call a
  service → return JSON.
  - `analyze.py` — single-IOC endpoints (`/analyze`, `/analyze/ip/{ip}`,
    `/analyze/domain/{domain}`, `/analyze/hash/{hash}`, `/analyze/url` (POST, since URLs
    break path params), `/analyze/report/{ioc}` for the raw VT payload). Shared pipeline
    lives in `_investigate()`: fetch VT report → parse stats → bump health counters →
    get LLM summary.
  - `bulk.py` — `/bulk` (up to 10 IOCs, full analysis incl. LLM) and `/bulk/triage`
    (up to 20 IOCs, verdicts only, no LLM). Both fan out with `asyncio.gather`; each IOC
    is wrapped in try/except so one failure doesn't sink the batch.
  - `health.py` — `/health` (liveness), `/health/stats` (in-memory session counters,
    reset on restart), `/health/check-keys` (pings VT and OpenRouter with the configured
    keys). Exposes `increment(verdict)`, called by `analyze.py`/`bulk.py` after each lookup.
- `services/` — no HTTP awareness, just external API clients, called by routers.
  - `virustotal.py` — `detect_type()` regex-guesses ip/hash/url/domain; `fetch_report()`
    hits the matching VT v3 endpoint; URLs are identified by a URL-safe base64 id, and a
    never-before-seen URL gets submitted via POST once before the GET is retried.
    `parse_stats()` turns the raw VT stats into a verdict (`malicious` if >10 engines
    flag it, `suspicious` if any malicious or >5 suspicious, else `clean` — thresholds
    are arbitrary, tune to taste).
  - `openrouter.py` — `get_summary()` builds a SOC-analyst prompt from the VT stats and
    posts it to OpenRouter's chat completions endpoint, returns the model's text.

### Frontend (`frontend/`)

Next.js App Router, all interactive components are client components (`"use client"`).

- `lib/api.js` — the only place that knows the backend's base URL and endpoint shapes;
  every component calls through here.
- `components/ThreatDashboard.jsx` — main page: single-IOC input, tab switcher
  (single/bulk), session stats, lookup history.
- `components/BulkAnalyzer.jsx` — paste many IOCs (newline/comma separated), triage vs.
  full mode.
- `components/ThreatCard.jsx` — renders one result: verdict badge, detection bar,
  metadata, AI summary. Used both full-size and in a `compact` variant for lists.

## Notes

- Secrets (`backend/.env`, `frontend/.env.local`) are gitignored; never hardcode API keys.
- `NEXT_PUBLIC_API_URL` (frontend) defaults to `http://localhost:8000` if unset.
- `HOW_IT_WORKS.md` and `PRESENTATION_CHEATSHEET.md` in the repo root have more
  narrative/teaching-oriented explanations of the same architecture.
