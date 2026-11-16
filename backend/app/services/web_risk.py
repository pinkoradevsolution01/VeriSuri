import httpx
from backend.app.config import get_settings

class WebRiskClient:
    """Server-side Google Web Risk Lookup API client.

    The API key is never exposed to the browser. A ``None`` result means that
    Web Risk could not make a determination, not that a URL is safe.
    """

    endpoint = "https://webrisk.googleapis.com/v1/uris:search"

    @property
    def configured(self) -> bool:
        return bool(get_settings().google_web_risk_api_key)

    async def lookup(self, url: str) -> tuple[bool | None, list[str]]:
        key = get_settings().google_web_risk_api_key
        if not key: return None, []
        params = [("key", key), ("uri", url), ("threatTypes", "MALWARE"), ("threatTypes", "SOCIAL_ENGINEERING"), ("threatTypes", "UNWANTED_SOFTWARE")]
        try:
            async with httpx.AsyncClient(timeout=4) as client:
                response = await client.get(self.endpoint, params=params)
                response.raise_for_status()
                threat = response.json().get("threat")
                if not threat:
                    return False, []
                return True, list(threat.get("threatTypes", []))
        except httpx.HTTPError:
            return None, []
