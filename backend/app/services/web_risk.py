import httpx
from backend.app.config import get_settings

class WebRiskClient:
    endpoint = "https://webrisk.googleapis.com/v1/threatMatches:find"
    async def lookup(self, url: str) -> tuple[bool | None, list[str]]:
        key = get_settings().google_web_risk_api_key
        if not key: return None, []
        params = [("key", key), ("uri", url), ("threatTypes", "MALWARE"), ("threatTypes", "SOCIAL_ENGINEERING"), ("threatTypes", "UNWANTED_SOFTWARE")]
        try:
            async with httpx.AsyncClient(timeout=4) as client:
                response = await client.get(self.endpoint, params=params); response.raise_for_status()
                matches = response.json().get("matches", [])
                return bool(matches), [match.get("threatType", "UNKNOWN") for match in matches]
        except httpx.HTTPError:
            return None, []
