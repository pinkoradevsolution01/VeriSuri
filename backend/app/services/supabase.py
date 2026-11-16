import hashlib
import httpx
from backend.app.config import get_settings

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
