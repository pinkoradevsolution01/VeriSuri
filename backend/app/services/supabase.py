import hashlib
import httpx
from datetime import UTC, datetime
from dataclasses import dataclass
from backend.app.config import get_settings


@dataclass(frozen=True)
class WebRiskQuota:
    allowed: bool
    plan: str
    daily_limit: int
    used_today: int
    remaining_today: int
    reason: str

@dataclass(frozen=True)
class WebRiskAuthorization:
    allowed: bool
    reason: str

class SupabaseRepository:
    def __init__(self) -> None:
        config = get_settings(); self.url = config.supabase_url; self.key = config.supabase_service_role_key
    @property
    def enabled(self) -> bool: return bool(self.url and self.key)
    @staticmethod
    def identifier_hash(value: str) -> str: return hashlib.sha256(value.strip().lower().encode()).hexdigest()
    async def report_count(self, entity_type: str, value: str) -> int | None:
        if not self.enabled: return None
        headers = {"apikey": self.key or "", "Authorization": f"Bearer {self.key or ''}", "Prefer": "count=exact"}
        params = {"select": "id", "entity_type": f"eq.{entity_type}", "entity_hash": f"eq.{self.identifier_hash(value)}", "status": "eq.confirmed"}
        async with httpx.AsyncClient(timeout=5) as client:
            response = await client.get(f"{self.url}/rest/v1/reported_entities", headers=headers, params=params); response.raise_for_status()
            return int(response.headers.get("content-range", "*/0").split("/")[-1])

    async def user_id_from_access_token(self, access_token: str | None) -> str | None:
        if not self.enabled or not access_token:
            return None
        headers = {"apikey": self.key or "", "Authorization": f"Bearer {access_token}"}
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.get(f"{self.url}/auth/v1/user", headers=headers)
                if response.status_code != 200:
                    return None
                return response.json().get("id")
        except httpx.HTTPError:
            return None

    async def consume_web_risk_quota(self, user_id: str) -> WebRiskQuota | None:
        if not self.enabled:
            return None
        headers = {"apikey": self.key or "", "Authorization": f"Bearer {self.key or ""}"}
        payload = {"p_user_id": user_id, "p_free_monthly_budget": get_settings().free_web_risk_monthly_budget}
        try:
            async with httpx.AsyncClient(timeout=6) as client:
                response = await client.post(f"{self.url}/rest/v1/rpc/consume_web_risk_quota", headers=headers, json=payload)
                response.raise_for_status()
                row = response.json()
                row = row[0] if isinstance(row, list) else row
                return WebRiskQuota(
                    allowed=bool(row["allowed"]), plan=str(row["plan"]), daily_limit=int(row["daily_limit"]),
                    used_today=int(row["used_today"]), remaining_today=int(row["remaining_today"]), reason=str(row["reason"]),
                )
        except (httpx.HTTPError, KeyError, TypeError, ValueError):
            return None

    async def authorize_web_risk_scan(self, user_id: str, url: str) -> WebRiskAuthorization | None:
        if not self.enabled:
            return None
        headers = {"apikey": self.key or "", "Authorization": f"Bearer {self.key or ''}"}
        payload = {"p_user_id": user_id, "p_url_hash": self.identifier_hash(url)}
        try:
            async with httpx.AsyncClient(timeout=6) as client:
                response = await client.post(f"{self.url}/rest/v1/rpc/authorize_web_risk_scan", headers=headers, json=payload)
                response.raise_for_status()
                row = response.json(); row = row[0] if isinstance(row, list) else row
                return WebRiskAuthorization(allowed=bool(row["allowed"]), reason=str(row["reason"]))
        except (httpx.HTTPError, KeyError, TypeError, ValueError):
            return None

    async def published_alerts(self) -> list[dict] | None:
        if not self.enabled: return None
        headers = {"apikey": self.key or "", "Authorization": f"Bearer {self.key or ''}"}
        now = datetime.now(UTC).isoformat()
        params = {
            "select": "id,title,summary,severity,published_at,source_name,source_url,affected_platform,region,review_at,expires_at",
            "published": "eq.true", "status": "eq.verified", "review_at": f"gt.{now}", "expires_at": f"gt.{now}",
            "order": "published_at.desc", "limit": "20",
        }
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.get(f"{self.url}/rest/v1/fraud_alerts", headers=headers, params=params); response.raise_for_status()
                return response.json()
        except httpx.HTTPError:
            # Never substitute unverified advisory content if the source is unavailable.
            return []
