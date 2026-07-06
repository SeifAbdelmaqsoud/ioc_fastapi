import asyncio
from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.routers.health import increment
from app.services.openrouter import get_summary
from app.services.virustotal import detect_type, fetch_report, parse_stats

router = APIRouter()


class BulkPayload(BaseModel):
    iocs: list[str] = Field(..., min_length=1, examples=[["8.8.8.8", "evil.com"]])


def _count_verdicts(results: list[dict]) -> dict[str, int]:
    return {
        "malicious": sum(1 for r in results if r.get("verdict") == "malicious"),
        "suspicious": sum(1 for r in results if r.get("verdict") == "suspicious"),
        "clean": sum(1 for r in results if r.get("verdict") == "clean"),
    }


async def _analyze_one(ioc: str) -> dict[str, Any]:
    try:
        ioc_type = detect_type(ioc)
        vt_data = await fetch_report(ioc, ioc_type)
        stats = parse_stats(vt_data)
        increment(stats["verdict"])
        summary = await get_summary(ioc, ioc_type, stats)
        return {"ioc": ioc, "type": ioc_type, **stats, "summary": summary, "error": None}
    except Exception as e:
        return {"ioc": ioc, "error": str(e)}


async def _triage_one(ioc: str) -> dict[str, Any]:
    # skips the LLM call to keep this fast and cheap
    try:
        ioc_type = detect_type(ioc)
        vt_data = await fetch_report(ioc, ioc_type)
        stats = parse_stats(vt_data)
        increment(stats["verdict"])
        return {
            "ioc": ioc,
            "type": ioc_type,
            "verdict": stats["verdict"],
            "detections": stats["detections"],
            "malicious": stats["malicious"],
            "suspicious": stats["suspicious"],
            "total": stats["total"],
            "error": None,
        }
    except Exception as e:
        return {"ioc": ioc, "error": str(e)}


@router.post("")
async def bulk_analyze(payload: BulkPayload):
    iocs = payload.iocs[:10]  # cap it, LLM calls aren't free
    results = await asyncio.gather(*[_analyze_one(ioc) for ioc in iocs])
    counts = _count_verdicts(results)

    return {
        "total": len(results),
        **counts,
        "results": results,
    }


@router.post("/triage")
async def bulk_triage(payload: BulkPayload):
    iocs = payload.iocs[:20]
    results = await asyncio.gather(*[_triage_one(ioc) for ioc in iocs])
    counts = _count_verdicts(results)

    return {
        "total": len(results),
        **counts,
        "results": results,
    }
