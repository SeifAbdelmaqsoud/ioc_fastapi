import httpx
from fastapi import HTTPException

from app.config import settings

OR_URL = "https://openrouter.ai/api/v1/chat/completions"
OR_HEADERS = {"Authorization": f"Bearer {settings.openrouter_api_key}"}


async def get_summary(ioc: str, ioc_type: str, stats: dict) -> str:
    prompt = f"""You are a SOC analyst reviewing a VirusTotal scan.

IOC: {ioc}
Type: {ioc_type}
Malicious detections: {stats["malicious"]}/{stats["total"]}
Suspicious detections: {stats["suspicious"]}/{stats["total"]}
Tags: {", ".join(stats["tags"]) or "none"}

Write 2-3 sentences covering:
1. What this IOC likely is and its threat level
2. What it may be associated with (malware family, campaign, infrastructure)
3. Recommended action for a security team

Be direct. No bullet points. No headers."""

    async with httpx.AsyncClient() as client:
        r = await client.post(
            OR_URL,
            headers=OR_HEADERS,
            json={
                "model": settings.openrouter_model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 200,
            },
            timeout=30.0,
        )

    if r.status_code != 200:
        raise HTTPException(
            status_code=502,
            detail=f"OpenRouter error ({r.status_code}): {r.text[:200]}",
        )

    data = r.json()
    try:
        return data["choices"][0]["message"]["content"].strip()
    except (KeyError, IndexError, TypeError):
        raise HTTPException(
            status_code=502,
            detail="OpenRouter returned an unexpected response shape",
        )
