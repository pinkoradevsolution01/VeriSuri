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

@dataclass(frozen=True)
class ExternalThreatObservation:
    source_name: str
    source_url: str
    evidence_status: str

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

    async def external_url_observation(self, canonical_url: str) -> ExternalThreatObservation | None:
        """Return a moderator-curated, expiring reported-source observation."""
        if not self.enabled:
            return None
        headers = {"apikey": self.key or "", "Authorization": f"Bearer {self.key or ''}"}
        params = {"select": "source_name,source_url,evidence_status", "canonical_url": f"eq.{canonical_url}", "evidence_status": "in.(reported,confirmed)", "expires_at": f"gt.{datetime.now(UTC).isoformat()}", "limit": "1"}
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                response = await client.get(f"{self.url}/rest/v1/external_threat_observations", headers=headers, params=params)
                response.raise_for_status()
                rows = response.json()
                if not rows:
                    return None
                row = rows[0]
                return ExternalThreatObservation(source_name=str(row["source_name"]), source_url=str(row["source_url"]), evidence_status=str(row["evidence_status"]))
        except (httpx.HTTPError, KeyError, TypeError, ValueError):
            return None

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

    async def submit_scam_report(self, user_id: str, report: dict) -> str:
        """Store a pending report with the service role after authenticating its owner.

        This deliberately uses only the original report tables first, so a report can
        be submitted even when an older Supabase project has not yet run optional
        structured-report migrations. The identifier is never stored in plain text.
        """
        if not self.enabled:
            raise RuntimeError("Secure report storage is not configured.")
        headers = {
            "apikey": self.key or "",
            "Authorization": f"Bearer {self.key or ''}",
            "Content-Type": "application/json",
            "Prefer": "return=representation",
        }
        report_payload = {
            "reporter_id": user_id,
            "narrative": report["narrative"].strip(),
            "incident_at": report.get("incident_at") or None,
        }
        try:
            async with httpx.AsyncClient(timeout=10) as client:
                created = await client.post(f"{self.url}/rest/v1/scam_reports", headers=headers, json=report_payload)
                created.raise_for_status()
                rows = created.json()
                if not rows or not rows[0].get("id"):
                    raise RuntimeError("Secure report storage did not return a report ID.")
                report_id = str(rows[0]["id"])

                entity = {
                    "report_id": report_id,
                    "entity_type": report["entity_type"],
                    "entity_hash": self.identifier_hash(report["entity_value"]),
                    "entity_last4": report["entity_value"].strip()[-4:],
                }
                entity_response = await client.post(f"{self.url}/rest/v1/reported_entities", headers=headers, json=entity)
                entity_response.raise_for_status()

                # Enrich projects that have the structured-report migration. An
                # older project still keeps the safe, moderation-only core report.
                structured = {
                    "scam_type": report["scam_type"],
                    "payment_provider": report["payment_provider"],
                    "amount_range": report["amount_range"],
                    "incident_channel": report["incident_channel"],
                    "redacted_evidence": report.get("redacted_evidence") or None,
                    "privacy_notice_version": report["privacy_notice_version"],
                    "training_consent": report["training_consent"],
                }
                await client.patch(f"{self.url}/rest/v1/scam_reports?id=eq.{report_id}", headers={**headers, "Prefer": "return=minimal"}, json=structured)

                # Consent is opt-in. If the training queue migration is present,
                # retain the separate redacted sample for moderator approval only.
                # A missing optional table must never prevent the scam report itself.
                if report.get("training_consent") and report.get("redacted_training_sample"):
                    await client.post(
                        f"{self.url}/rest/v1/training_examples",
                        headers={**headers, "Prefer": "return=minimal"},
                        json={
                            "report_id": report_id,
                            "reporter_id": user_id,
                            "text_redacted": report["redacted_training_sample"].strip(),
                            "label": 1,
                            "consent_version": report["privacy_notice_version"],
                        },
                    )

                # Audit logging exists in the base schema. It contains no raw
                # identifier, message, or evidence.
                await client.post(
                    f"{self.url}/rest/v1/audit_logs",
                    headers={**headers, "Prefer": "return=minimal"},
                    json={"actor_id": user_id, "action": "report_submitted", "resource_type": "scam_report", "resource_id": report_id, "metadata": {"entity_type": report["entity_type"], "training_consent": report["training_consent"]}},
                )
                return report_id
        except httpx.HTTPStatusError as error:
            status = error.response.status_code
            if status in (401, 403):
                raise RuntimeError("Secure report storage rejected this request. Check the Supabase service-role key on the API deployment.") from error
            raise RuntimeError("Secure report storage is temporarily unavailable. Please try again shortly.") from error
        except (httpx.HTTPError, ValueError, KeyError) as error:
            raise RuntimeError("Secure report storage is temporarily unavailable. Please try again shortly.") from error

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
