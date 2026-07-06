# How This Project Works

This is an **IOC (Indicator of Compromise) analyzer**: you paste an IP, domain, file hash, or URL, and the app checks it against **VirusTotal**, then asks an **AI model** (via OpenRouter) to write a short analyst-style summary.

The stack is split into two apps:

| Part | Tech | Runs on | Job |
|------|------|---------|-----|
| **Backend** | FastAPI (Python) | `http://localhost:8000` | Talks to VirusTotal + OpenRouter, exposes a REST API |
| **Frontend** | Next.js (React) | `http://localhost:3000` | UI — forms, results cards, bulk scan |

---

## Quick start

### 1. Backend (FastAPI)

```bash
cd backend

# First time only — create and activate the virtual environment
python3 -m venv venv
source venv/bin/activate          # Windows: venv\Scripts\activate
pip install -r requirements.txt

# Copy secrets (you need real API keys)
cp .env.example .env
# Edit .env with your VirusTotal and OpenRouter keys

# Start the API (must run from the backend/ folder)
fastapi dev app/main.py --port 8000
```

**Alternative (same thing under the hood):**

```bash
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

`fastapi dev` is the recommended way — it auto-finds your app, enables reload, and still uses uvicorn internally.

Or from the repo root:

```bash
chmod +x scripts/run-backend.sh
./scripts/run-backend.sh
```

**Why `cd backend` first?**  
Python imports the app as `app.main`. That only works when your current directory is `backend/`. Starting from the wrong folder gives `ModuleNotFoundError: No module named 'app'`.

**Interactive API docs:** open [http://127.0.0.1:8000/docs](http://127.0.0.1:8000/docs) — FastAPI generates this automatically from your route functions.

### 2. Frontend (Next.js)

```bash
cd frontend
npm install
npm run dev
```

Open [http://localhost:3000](http://localhost:3000).

---

## Project layout

```
ioc_fastapi/
├── backend/                    ← FastAPI lives here
│   ├── .env                    ← API keys (never commit this)
│   ├── .env.example            ← Template for .env
│   ├── requirements.txt        ← Python dependencies
│   ├── venv/                   ← Virtual environment (local only)
│   └── app/
│       ├── main.py             ← Creates the FastAPI app, wires routers
│       ├── config.py           ← Reads .env into typed settings
│       ├── routers/            ← HTTP endpoints grouped by feature
│       │   ├── analyze.py      ← Single IOC lookups
│       │   ├── bulk.py         ← Many IOCs at once
│       │   └── health.py       ← Liveness, stats, key checks
│       └── services/           ← External API clients (no HTTP routes here)
│           ├── virustotal.py   ← VirusTotal API
│           └── openrouter.py   ← OpenRouter / LLM
├── frontend/                   ← Next.js UI
│   ├── app/                    ← Pages (App Router)
│   ├── components/             ← React UI pieces
│   └── lib/api.js              ← fetch() wrapper for the backend
└── scripts/
    ├── run-backend.sh
    └── run-frontend.sh
```

---

## FastAPI — the mental model

FastAPI is a **web framework**: it maps HTTP requests (method + URL + body) to Python functions and returns JSON.

Think of it in four layers:

```
Browser / frontend
       ↓  HTTP (GET /analyze?ioc=8.8.8.8)
┌──────────────────────────────────────┐
│  main.py          App + CORS + mount │
│  routers/*.py     Route handlers     │  ← “What URL does what?”
│  services/*.py    Business logic     │  ← “Call VirusTotal, call LLM”
│  config.py        Settings from .env │
└──────────────────────────────────────┘
       ↓
VirusTotal API, OpenRouter API
```

### 1. The application object — `app/main.py`

```python
app = FastAPI(title="Threat Intel API", version="1.0.0")
```

This is the single FastAPI instance. Everything attaches to it:

- **CORS middleware** — browsers block cross-origin requests by default. The frontend on `:3000` must be allowed to call the API on `:8000`.
- **Routers** — groups of related endpoints, each with a URL prefix.
- **Root route** — `@app.get("/")` for a simple health message.

### 2. Routers — `app/routers/*.py`

A **router** is a mini-app of endpoints. We split them so `analyze.py` doesn’t become a 500-line file.

```python
router = APIRouter()

@router.get("")
async def analyze(ioc: str):
    ...
```

In `main.py`:

```python
app.include_router(analyze.router, prefix="/analyze", tags=["analyze"])
```

So `analyze()` is reachable at **`GET /analyze?ioc=...`**.

**Why `async def`?**  
While waiting on VirusTotal or OpenRouter over the network, FastAPI can handle other requests instead of blocking a thread. Our handlers use `httpx` async clients for that.

### 3. Request and response shapes — Pydantic

FastAPI uses **Pydantic** models to validate JSON bodies and document the API.

Example from `analyze.py`:

```python
class UrlPayload(BaseModel):
    url: str
```

For `POST /analyze/url`, FastAPI:

1. Parses the JSON body
2. Validates it matches `UrlPayload`
3. Passes `payload.url` into your function
4. If validation fails, returns **422** with a clear error (automatic)

Query params work too — `async def analyze(ioc: str)` means `?ioc=` is required on `GET /analyze`.

### 4. Settings — `app/config.py`

Secrets live in `.env`, not in code:

```
VT_API_KEY=...
OPENROUTER_API_KEY=...
OPENROUTER_MODEL=...
```

`Settings` (from `pydantic-settings`) loads these once at import time:

```python
settings = Settings()
# settings.vt_api_key, settings.openrouter_api_key, ...
```

The path to `.env` is resolved relative to `config.py`, so it still works if you start uvicorn from a script.

### 5. Services — `app/services/*.py`

Services are **plain Python modules** — no `@router`, no HTTP. Routers call them.

This keeps routes thin (“parse input, call service, return JSON”) and makes VirusTotal/OpenRouter logic easy to test or reuse.

---

## File-by-file: what each part does

### `app/main.py`

| Piece | Purpose |
|-------|---------|
| `FastAPI(...)` | Creates the app; title/version show up in `/docs` |
| `CORSMiddleware` | Allows the Next.js dev server to call the API |
| `include_router(...)` | Mounts `/analyze`, `/bulk`, `/health` route groups |
| `@app.get("/")` | Simple “API is running” ping |

### `app/config.py`

Loads environment variables into a typed `Settings` object. If a required key is missing, the app fails fast at startup with a clear Pydantic error instead of failing mid-request.

### `app/routers/health.py`

| Endpoint | What it does |
|----------|----------------|
| `GET /health` | `{ "status": "ok" }` — is the process alive? |
| `GET /health/stats` | Session counters: total / malicious / suspicious / clean |
| `GET /health/check-keys` | Pings VirusTotal and OpenRouter with your keys |

`_stats` is an in-memory dict — it resets when you restart the server. Fine for demos; use Redis in production if you need persistence.

`increment(verdict)` is called from analyze/bulk routes after each successful lookup.

### `app/routers/analyze.py`

Single-IOC analysis.

| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/analyze?ioc=` | GET | Auto-detect type, full report + AI summary |
| `/analyze/ip/{ip}` | GET | IP + country, ASN, owner |
| `/analyze/domain/{domain}` | GET | Domain + registrar, categories |
| `/analyze/hash/{hash}` | GET | File hash + name, size, magic |
| `/analyze/url` | POST | URL lookup (body: `{ "url": "..." }`) |
| `/analyze/report/{ioc}` | GET | Raw VirusTotal data, no LLM |

Shared helper `_investigate()`:

1. `fetch_report()` → VirusTotal JSON  
2. `parse_stats()` → verdict, detection counts, tags  
3. `increment()` → bump session stats  
4. `get_summary()` → LLM paragraph  

### `app/routers/bulk.py`

| Endpoint | Purpose |
|----------|---------|
| `POST /bulk` | Up to **10** IOCs, parallel, **with** AI summaries |
| `POST /bulk/triage` | Up to **20** IOCs, parallel, **verdicts only** (faster) |

Uses `asyncio.gather()` to run many lookups at the same time. Each IOC is wrapped in try/except so one failure doesn’t kill the whole batch.

### `app/services/virustotal.py`

| Function | Purpose |
|----------|---------|
| `detect_type(ioc)` | Regex guess: ip / hash / url / domain |
| `fetch_report(ioc, type)` | HTTP GET to VirusTotal v3 API |
| `parse_stats(vt_data)` | Turn engine counts into `malicious` / `suspicious` / `clean` |

**URL quirk:** VirusTotal doesn’t use the raw URL in the path. It uses a **URL-safe base64 id** (no `=` padding). If a URL was never scanned, we `POST` it to VirusTotal first, then fetch again.

Raises `HTTPException(404)` if the IOC isn’t in VirusTotal — FastAPI turns that into a proper JSON error for the frontend.

### `app/services/openrouter.py`

| Function | Purpose |
|----------|---------|
| `get_summary(ioc, type, stats)` | Builds a SOC-style prompt, POSTs to OpenRouter chat completions, returns 2–3 sentences |

Uses the model name from `OPENROUTER_MODEL` in `.env`.

---

## Request flow (single IOC)

Example: user types `8.8.8.8` and clicks Analyze.

```
1. frontend/lib/api.js
   fetch("http://localhost:8000/analyze?ioc=8.8.8.8")

2. FastAPI → analyze.analyze(ioc="8.8.8.8")
   detect_type → "ip"

3. virustotal.fetch_report("8.8.8.8", "ip")
   GET https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8

4. virustotal.parse_stats(vt_json)
   → { verdict: "clean", malicious: 0, total: 70, ... }

5. health.increment("clean")

6. openrouter.get_summary(...)
   POST https://openrouter.ai/api/v1/chat/completions

7. Return JSON:
   {
     "ioc": "8.8.8.8",
     "type": "ip",
     "verdict": "clean",
     "detections": "0/70",
     "summary": "This IP appears to be..."
   }

8. ThreatCard.jsx renders verdict color, bar, and summary text
```

---

## Frontend (short overview)

Not FastAPI, but useful context:

| File | Role |
|------|------|
| `frontend/lib/api.js` | All backend calls — one `request()` helper |
| `frontend/components/ThreatDashboard.jsx` | Main page: single IOC tab, stats, history |
| `frontend/components/BulkAnalyzer.jsx` | Paste many IOCs, triage vs full mode |
| `frontend/components/ThreatCard.jsx` | Result card: verdict, detection bar, AI text |

The frontend is a **client** of your FastAPI API. It never talks to VirusTotal or OpenRouter directly — keys stay on the server.

---

## Environment variables

| Variable | Where to get it |
|----------|-----------------|
| `VT_API_KEY` | [VirusTotal](https://www.virustotal.com/gui/my-apikey) |
| `OPENROUTER_API_KEY` | [OpenRouter](https://openrouter.ai/keys) |
| `OPENROUTER_MODEL` | Any model id OpenRouter supports (free tier models work) |

Optional frontend variable:

| Variable | Default |
|----------|---------|
| `NEXT_PUBLIC_API_URL` | `http://localhost:8000` |

---

## Common problems

### “ModuleNotFoundError: No module named 'app'”

You started the server from the wrong directory. Fix:

```bash
cd backend
source venv/bin/activate
fastapi dev app/main.py --port 8000
```

Or use `./scripts/run-backend.sh`.

### “ValidationError” on startup (missing env vars)

`.env` is missing or incomplete. Copy `backend/.env.example` → `backend/.env` and add real keys.

### venv “doesn’t work” / wrong packages

Recreate it:

```bash
cd backend
rm -rf venv
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Always **activate** before `pip install` or running the server:

```bash
source venv/bin/activate   # prompt should show (venv)
which python               # should point inside backend/venv/
```

### Frontend can’t reach API

1. Backend running on port 8000?  
2. CORS allows `http://localhost:3000` (already set in `main.py`)  
3. Check keys: `GET http://localhost:8000/health/check-keys`

### URL lookups return 404

New URLs may need a moment after the first submit to VirusTotal. Retry after a few seconds.

---

## API reference (cheat sheet)

| Method | Path | Body / params |
|--------|------|----------------|
| GET | `/` | — |
| GET | `/health` | — |
| GET | `/health/stats` | — |
| GET | `/health/check-keys` | — |
| GET | `/analyze?ioc=` | query: `ioc` |
| GET | `/analyze/ip/{ip}` | path: IP |
| GET | `/analyze/domain/{domain}` | path: domain |
| GET | `/analyze/hash/{hash}` | path: hash |
| POST | `/analyze/url` | `{ "url": "https://..." }` |
| GET | `/analyze/report/{ioc}` | path: any IOC |
| POST | `/bulk` | `{ "iocs": ["...", "..."] }` max 10 |
| POST | `/bulk/triage` | `{ "iocs": ["...", "..."] }` max 20 |

---

## What you might add next

- **Rate limiting** — VirusTotal free tier has daily caps  
- **Caching** — Redis for repeated lookups  
- **Auth** — API keys so the backend isn’t public  
- **Tests** — `pytest` + `httpx.AsyncClient` against FastAPI’s `TestClient`  
- **Docker** — one `docker compose up` for backend + frontend  

---

## Summary

**FastAPI** is the brain: it defines routes, validates input with Pydantic, calls VirusTotal and OpenRouter in async service modules, and returns JSON. **Routers** organize endpoints; **services** hold the real work; **config** holds secrets. The **Next.js frontend** is just a pretty remote control for that API.

If you only remember three things:

1. Run the backend from **`backend/`** with the **venv activated**.  
2. Open **`/docs`** to explore every endpoint interactively.  
3. Follow a request: **router → service → external API → JSON back**.
