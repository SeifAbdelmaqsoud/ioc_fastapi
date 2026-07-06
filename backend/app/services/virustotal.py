import base64
import re

import httpx
from fastapi import HTTPException

from app.config import settings

VT_BASE = "https://www.virustotal.com/api/v3"
VT_HEADERS = {"x-apikey": settings.vt_api_key}


def detect_type(ioc: str) -> str:
    ioc = ioc.strip()

    if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ioc):
        return "ip"
    if re.match(r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$", ioc, re.IGNORECASE):
        return "hash"
    if ioc.startswith("http://") or ioc.startswith("https://"):
        return "url"
    return "domain"


def _url_to_vt_id(url: str) -> str:
    # VT ids urls by a url-safe base64 hash, no padding
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


async def _get(client: httpx.AsyncClient, url: str) -> httpx.Response:
    return await client.get(url, headers=VT_HEADERS, timeout=15.0)


async def _submit_url(client: httpx.AsyncClient, url: str) -> None:
    r = await client.post(
        f"{VT_BASE}/urls",
        headers=VT_HEADERS,
        data={"url": url},
        timeout=15.0,
    )
    if r.status_code not in (200, 201):
        raise HTTPException(
            status_code=r.status_code,
            detail="VirusTotal could not queue this URL for scanning",
        )


async def fetch_report(ioc: str, ioc_type: str) -> dict:
    endpoints = {
        "ip": f"{VT_BASE}/ip_addresses/{ioc}",
        "domain": f"{VT_BASE}/domains/{ioc}",
        "hash": f"{VT_BASE}/files/{ioc}",
        "url": f"{VT_BASE}/urls/{_url_to_vt_id(ioc)}",
    }

    async with httpx.AsyncClient() as client:
        r = await _get(client, endpoints[ioc_type])

        # brand new urls 404 until we submit them for a scan once
        if ioc_type == "url" and r.status_code == 404:
            await _submit_url(client, ioc)
            r = await _get(client, endpoints[ioc_type])

    if r.status_code == 404:
        raise HTTPException(
            status_code=404,
            detail=f"IOC not found in VirusTotal: {ioc}",
        )
    if r.status_code != 200:
        raise HTTPException(
            status_code=r.status_code,
            detail="VirusTotal API error",
        )

    return r.json()


def parse_stats(vt_data: dict) -> dict:
    attrs = vt_data.get("data", {}).get("attributes", {})
    stats = attrs.get("last_analysis_stats", {})

    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    total = sum(stats.values()) if stats else 0
    tags = attrs.get("tags", [])

    # arbitrary thresholds, adjust to taste
    if malicious > 10:
        verdict = "malicious"
    elif malicious > 0 or suspicious > 5:
        verdict = "suspicious"
    else:
        verdict = "clean"

    return {
        "verdict": verdict,
        "malicious": malicious,
        "suspicious": suspicious,
        "total": total,
        "detections": f"{malicious}/{total}",
        "tags": tags[:6],
    }
