from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.routers import analyze, bulk, health

app = FastAPI(
    title="Threat Intel API",
    version="1.0.0",
    description="Look up IOCs via VirusTotal and get AI-written analyst summaries.",
)

# Next.js dev server runs on :3000, this needs to be reachable from the browser
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://127.0.0.1:3000",
    ],
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(analyze.router, prefix="/analyze", tags=["analyze"])
app.include_router(bulk.router, prefix="/bulk", tags=["bulk"])
app.include_router(health.router, prefix="/health", tags=["health"])


@app.get("/")
def root():
    return {"message": "Threat Intel API is running"}
