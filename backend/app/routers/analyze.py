from typing import Any

from fastapi import APIRouter
from pydantic import BaseModel, Field

from app.routers.health import increment
from app.services.openrouter import get_summary
from app.services.virustotal import detect_type, fetch_report, parse_stats

router = APIRouter()


class UrlPayload(BaseModel):
    url: str = Field(..., min_length=4, examples=["https://example.com/path"])


async def _investigate(ioc: str, ioc_type: str) -> tuple[dict, dict, dict]:
    vt_data = await fetch_report(ioc, ioc_type)
    stats = parse_stats(vt_data)
    increment(stats["verdict"])
    summary = await get_summary(ioc, ioc_type, stats)
    attrs = vt_data.get("data", {}).get("attributes", {})
    return stats, summary, attrs


@router.get("")
async def analyze(ioc: str):
    ioc = ioc.strip()
    ioc_type = detect_type(ioc)
    stats, summary, _ = await _investigate(ioc, ioc_type)
    return {"ioc": ioc, "type": ioc_type, **stats, "summary": summary}


@router.get("/ip/{ip}")
async def analyze_ip(ip: str):
    stats, summary, attrs = await _investigate(ip, "ip")
    return {
        "ioc": ip,
        "type": "ip",
        "country": attrs.get("country", "unknown"),
        "asn": attrs.get("asn"),
        "as_owner": attrs.get("as_owner"),
        **stats,
        "summary": summary,
    }


@router.get("/domain/{domain}")
async def analyze_domain(domain: str):
    stats, summary, attrs = await _investigate(domain, "domain")
    categories = list(attrs.get("categories", {}).values())[:4]
    return {
        "ioc": domain,
        "type": "domain",
        "registrar": attrs.get("registrar"),
        "created": attrs.get("creation_date"),
        "categories": categories,
        **stats,
        "summary": summary,
    }


@router.get("/hash/{file_hash}")
async def analyze_hash(file_hash: str):
    stats, summary, attrs = await _investigate(file_hash, "hash")
    return {
        "ioc": file_hash,
        "type": "hash",
        "file_name": attrs.get("meaningful_name") or attrs.get("name"),
        "file_type": attrs.get("type_description"),
        "file_size": attrs.get("size"),
        "magic": attrs.get("magic"),
        **stats,
        "summary": summary,
    }


@router.post("/url")
async def analyze_url(payload: UrlPayload):
    # POST, not GET - urls can contain slashes/query strings that break path params
    url = payload.url.strip()
    stats, summary, attrs = await _investigate(url, "url")
    return {
        "ioc": url,
        "type": "url",
        "final_url": attrs.get("last_final_url"),
        "title": attrs.get("title"),
        "http_status": attrs.get("last_http_response_code"),
        **stats,
        "summary": summary,
    }


@router.get("/report/{ioc}")
async def full_report(ioc: str):
    ioc = ioc.strip()
    ioc_type = detect_type(ioc)
    vt_data = await fetch_report(ioc, ioc_type)
    attrs = vt_data.get("data", {}).get("attributes", {})

    engines: dict[str, Any] = attrs.get("last_analysis_results", {})
    flagged_engines = {
        name: result
        for name, result in engines.items()
        if result.get("category") in ("malicious", "suspicious")
    }

    return {
        "ioc": ioc,
        "type": ioc_type,
        "stats": attrs.get("last_analysis_stats", {}),
        "flagged_engines": flagged_engines,
        "tags": attrs.get("tags", []),
        "raw_attributes": attrs,
    }
