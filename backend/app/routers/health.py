import httpx
from fastapi import APIRouter

from app.config import settings

router = APIRouter()

# in-memory only, resets on restart - fine for a demo, swap for redis if this needs to persist
_stats = {"total": 0, "malicious": 0, "suspicious": 0, "clean": 0}


def increment(verdict: str) -> None:
    _stats["total"] += 1
    if verdict in _stats:
        _stats[verdict] += 1


async def _ping(url: str, headers: dict[str, str]) -> str:
    try:
        async with httpx.AsyncClient() as client:
            r = await client.get(url, headers=headers, timeout=8.0)
        return "ok" if r.status_code == 200 else f"error {r.status_code}"
    except Exception as e:
        return f"unreachable: {e}"


@router.get("")
def health():
    return {"status": "ok", "version": "1.0.0"}


@router.get("/stats")
def stats():
    return _stats


@router.get("/check-keys")
async def check_keys():
    vt_status = await _ping(
        "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8",
        headers={"x-apikey": settings.vt_api_key},
    )
    or_status = await _ping(
        "https://openrouter.ai/api/v1/models",
        headers={"Authorization": f"Bearer {settings.openrouter_api_key}"},
    )
    return {"virustotal": vt_status, "openrouter": or_status}
