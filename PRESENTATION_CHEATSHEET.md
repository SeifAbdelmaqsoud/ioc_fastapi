# Presentation Cheat Sheet — FastAPI + React (This Project)

Use this when explaining your IOC Threat Intel app to your teacher.

---

## Part 1: What does "24/74 engines" mean?

When the website shows **24/74** under **Detections**:

| Number | Meaning |
|--------|---------|
| **24** | How many antivirus/security **engines flagged this IOC as malicious** |
| **74** | How many engines **scanned it in total** on VirusTotal |

**Real-world analogy:** Imagine 74 security experts each look at the same IP, domain, URL, or file hash. 24 say "this looks bad," and the rest say harmless, suspicious, undetected, or timed out.

**Where it comes from in your code:**

1. VirusTotal returns scan stats like `{ malicious: 24, harmless: 50, undetected: 0, ... }`
2. Backend (`virustotal.py`) builds `"detections": "24/74"` — malicious count / total engines
3. Frontend (`ThreatCard.jsx`) displays `result.detections` in the header

**The colored bar below** ("Engine coverage") shows the same data visually:
- Red = malicious share
- Orange = suspicious share
- Green/gray = clean or undetected share

**The verdict badge** (MALICIOUS / SUSPICIOUS / CLEAN) is your app's own rule, not VirusTotal's:

```
malicious  → more than 10 engines flagged it
suspicious → 1+ malicious OR more than 5 suspicious
clean      → everything else
```

**One sentence for your teacher:**  
*"24/74 means 24 out of 74 VirusTotal security vendors marked this indicator as malicious — it's a crowd-sourced threat score, not a single antivirus result."*

---

## Part 2: Project architecture (30-second pitch)

```
User types IOC in browser (React / Next.js)
        ↓
frontend/lib/api.js  →  fetch("http://localhost:8000/analyze?ioc=...")
        ↓
FastAPI backend  →  VirusTotal API (scan data)
                  →  OpenRouter API (AI summary)
        ↓
JSON response  →  ThreatCard shows verdict + detections + summary
```

**Two apps, one product:**
- **Backend (FastAPI):** holds API keys, talks to external services, returns JSON
- **Frontend (React):** UI only — never touches secret keys

---

## Part 3: FastAPI cheat sheet (what YOU used)

### Core idea
FastAPI maps **HTTP requests** → **Python functions** → **JSON responses**.

### The app object — `app/main.py`

```python
app = FastAPI(title="Threat Intel API", version="1.0.0")
```

Everything attaches to this one `app`.

### Routes (endpoints)

```python
@app.get("/")                    # GET request
def root(): return {"message": "..."}

@router.get("")                  # GET /analyze?ioc=8.8.8.8
async def analyze(ioc: str): ...

@router.post("/url")             # POST with JSON body
async def analyze_url(payload: UrlPayload): ...
```

| Decorator | HTTP method | Example in project |
|-----------|-------------|-------------------|
| `@router.get("")` | GET | `/analyze?ioc=...` |
| `@router.get("/ip/{ip}")` | GET | path param `{ip}` |
| `@router.post("")` | POST | `/bulk` with JSON body |

### Routers — split endpoints by feature

```python
# main.py
app.include_router(analyze.router, prefix="/analyze", tags=["analyze"])
app.include_router(bulk.router,    prefix="/bulk",    tags=["bulk"])
app.include_router(health.router,  prefix="/health",  tags=["health"])
```

**Why:** keeps code organized — analyze, bulk, and health live in separate files.

### Async handlers

```python
async def analyze(ioc: str):
    vt_data = await fetch_report(ioc, ioc_type)   # waits on network without blocking
```

**Say to teacher:** *"While waiting for VirusTotal, the server can handle other requests."*

### Pydantic — validate input automatically

```python
class UrlPayload(BaseModel):
    url: str

class BulkPayload(BaseModel):
    iocs: list[str]
```

FastAPI reads JSON → checks shape → gives you typed Python objects. Bad input → **422 error** automatically.

### Settings from `.env` — `config.py`

```python
class Settings(BaseSettings):
    vt_api_key: str
    openrouter_api_key: str
```

**Say to teacher:** *"Secrets stay in environment variables, not in source code."*

### HTTPException — return proper errors

```python
raise HTTPException(status_code=404, detail="IOC not found in VirusTotal")
```

Frontend receives JSON `{ "detail": "..." }` instead of a crash.

### CORS — let the frontend call the API

```python
app.add_middleware(CORSMiddleware, allow_origins=["http://localhost:3000"], ...)
```

Browsers block cross-origin requests by default. CORS tells the browser: *"requests from :3000 to :8000 are allowed."*

### Services layer — business logic without HTTP

```
routers/analyze.py  →  calls  →  services/virustotal.py
                              →  services/openrouter.py
```

**Say to teacher:** *"Routes handle HTTP; services handle the actual work. That's separation of concerns."*

### Key FastAPI files in YOUR project

| File | Role |
|------|------|
| `app/main.py` | Creates app, CORS, registers routers |
| `app/config.py` | Loads API keys from `.env` |
| `app/routers/analyze.py` | Single IOC endpoints |
| `app/routers/bulk.py` | Batch scan + `asyncio.gather` |
| `app/routers/health.py` | Liveness, stats, key check |
| `app/services/virustotal.py` | VirusTotal HTTP client |
| `app/services/openrouter.py` | LLM summary |

### Run the server

```bash
cd backend && source venv/bin/activate
fastapi dev app/main.py --port 8000
```

Auto docs: **http://127.0.0.1:8000/docs**

---

## Part 4: React cheat sheet (what YOU used)

### Core idea
React builds UI as **components** — reusable pieces that re-render when **state** changes.

### `"use client"` — Next.js App Router

```jsx
"use client";
```

Top of `ThreatDashboard.jsx`, `BulkAnalyzer.jsx`, `ThreatCard.jsx`.

**Meaning:** this component runs in the **browser** (can use `useState`, clicks, `fetch`). Without it, the file would be a server component.

### Components in YOUR project

| Component | File | Job |
|-----------|------|-----|
| `Home` | `app/page.jsx` | Page shell — renders dashboard |
| `ThreatDashboard` | `components/ThreatDashboard.jsx` | Main UI: input, tabs, history |
| `ThreatCard` | `components/ThreatCard.jsx` | Shows one scan result |
| `BulkAnalyzer` | `components/BulkAnalyzer.jsx` | Paste many IOCs, bulk scan |

### Props — pass data parent → child

```jsx
<ThreatCard result={data} />
<ThreatCard result={item} compact />
```

Child receives `result` and optional `compact` flag.

### State — data that changes over time

```jsx
const [ioc, setIoc]         = useState("");      // text input value
const [result, setResult]   = useState(null);    // latest scan
const [loading, setLoading] = useState(false);   // show "Scanning..."
const [error, setError]     = useState(null);    // error message
```

**Flow:** user clicks Analyze → `setLoading(true)` → API call → `setResult(data)` → React re-draws `ThreatCard`.

### useEffect — run code on page load

```jsx
useEffect(() => {
  getStats().then(setStats);
  checkKeys().then(setApiStatus);
}, []);   // empty [] = run once when page mounts
```

Loads session stats and API key status when dashboard opens.

### Event handlers

```jsx
onClick={analyze}
onChange={(e) => setIoc(e.target.value)}
onKeyDown={(e) => e.key === "Enter" && analyze()}
```

### Conditional rendering

```jsx
{loading && <span>Scanning...</span>}
{error && <div>{error}</div>}
{result && <ThreatCard result={result} />}
{tab === "single" && <>...</>}
{tab === "bulk" && <BulkAnalyzer />}
```

### Lists

```jsx
{history.map((item, i) => (
  <ThreatCard key={i} result={item} compact />
))}
```

### API layer — `lib/api.js`

```jsx
export const analyzeIOC = (ioc) =>
  request(`/analyze?ioc=${encodeURIComponent(ioc)}`);

export const bulkTriage = (iocs) =>
  request("/bulk/triage", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ iocs }),
  });
```

**Say to teacher:** *"All backend calls go through one file — components don't hardcode URLs everywhere."*

### fetch pattern

```jsx
const res = await fetch(`${BASE}${path}`, options);
if (!res.ok) throw new Error(...);
return res.json();
```

This is how the frontend talks to FastAPI.

---

## Part 5: End-to-end flow (good for a demo)

1. User enters `8.8.8.8` → clicks **Analyze**
2. `ThreatDashboard.analyze()` calls `analyzeIOC("8.8.8.8")`
3. `GET http://localhost:8000/analyze?ioc=8.8.8.8`
4. FastAPI `analyze()` → `detect_type` → `"ip"`
5. `fetch_report` → VirusTotal → raw JSON
6. `parse_stats` → `{ verdict, detections: "0/74", ... }`
7. `get_summary` → OpenRouter → 2–3 sentence text
8. JSON returned → `setResult(data)` → `ThreatCard` renders verdict + **0/74** + summary

---

## Part 6: Vocabulary for your presentation

| Term | Plain English |
|------|---------------|
| **IOC** | Indicator of Compromise — IP, domain, URL, or file hash tied to a threat |
| **REST API** | Backend speaks HTTP + JSON; frontend sends requests, gets data back |
| **Endpoint** | One URL + method, e.g. `GET /analyze` |
| **Router** | Group of related endpoints in one file |
| **Async/await** | Wait on slow network calls without freezing the server |
| **Pydantic** | Validates request data before your code runs |
| **Component** | Reusable UI block in React |
| **State** | Data that changes and triggers UI updates |
| **Props** | Inputs passed into a component |
| **CORS** | Browser security rule; middleware fixes it for local dev |
| **VirusTotal engines** | Many AV vendors scanning the same IOC; count = consensus |

---

## Part 7: Likely teacher questions + short answers

**Q: Why FastAPI?**  
A: Automatic API docs, fast async support, built-in validation with Pydantic, easy to build JSON APIs.

**Q: Why separate frontend and backend?**  
A: API keys stay on the server; UI can be swapped or mobile apps can reuse the same API.

**Q: What is 24/74?**  
A: 24 security vendors marked it malicious out of 74 that scanned it on VirusTotal.

**Q: Where does the AI summary come from?**  
A: OpenRouter — we send VirusTotal stats in a prompt and get back analyst-style text.

**Q: What happens on bulk scan?**  
A: `asyncio.gather` runs many lookups in parallel; triage mode skips AI for speed.

**Q: How do you know the API is working?**  
A: `GET /health` and `/health/check-keys` — green dots on the dashboard.

---

## Part 8: File map (memorize this slide)

```
BACKEND (FastAPI)                    FRONTEND (React / Next.js)
─────────────────                    ─────────────────────────
app/main.py        → app entry       app/page.jsx        → home page
app/routers/*      → HTTP routes     components/*        → UI pieces
app/services/*     → external APIs   lib/api.js          → fetch wrapper
app/config.py      → .env keys       app/layout.jsx      → page wrapper
.env               → secrets         .env.local          → API URL (optional)
```

---

## Part 9: Commands to demo live

```bash
# Terminal 1 — backend
cd backend && source venv/bin/activate && fastapi dev app/main.py --port 8000

# Terminal 2 — frontend
cd frontend && npm run dev

# Browser
http://localhost:3000          → your app
http://127.0.0.1:8000/docs     → Swagger UI (shows every endpoint)
```

**Demo IOCs:**
- `8.8.8.8` — clean IP (Google DNS)
- `1.1.1.1` — clean IP (Cloudflare)
- Paste a known-bad hash from VirusTotal docs if you need a malicious example

---

*Good luck with your presentation.*
