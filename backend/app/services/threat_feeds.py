"""Zero-fee threat-feed intelligence for URL assessments.

The feeds are refreshed on the server and never exposed to the browser.  A
feed match is evidence, not a guarantee that every other URL is safe.
"""

from __future__ import annotations

import asyncio
import bz2
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit, urlunsplit

import httpx

from backend.app.config import get_settings


PHISHTANK_URL = "https://data.phishtank.com/data/{app_key}/online-valid.json.bz2"
CERT_POLSKA_URL = "https://hole.cert.pl/domains/v2/domains.txt"


@dataclass(frozen=True)
class ThreatFeedResult:
    signals: list[str]
    score: int
    source: str


def normalise_url(raw_url: str) -> tuple[str, str]:
    """Return a host and a comparable URL without fragments or credentials."""
    candidate = raw_url.strip()
    parsed = urlsplit(candidate if "://" in candidate else f"https://{candidate}")
    host = (parsed.hostname or "").lower().rstrip(".")
    try:
        port = f":{parsed.port}" if parsed.port else ""
    except ValueError:
        port = ""
    path = parsed.path or "/"
    comparable = urlunsplit((parsed.scheme.lower(), f"{host}{port}", path, parsed.query, ""))
    return host, comparable


class ThreatFeedClient:
    """In-memory cache for PhishTank verified URLs and CERT Polska domains."""

    def __init__(self) -> None:
        self._phishtank_urls: set[str] = set()
        self._cert_domains: set[str] = set()
        self._updated_at: datetime | None = None
        self._refresh_lock = asyncio.Lock()
        self._last_errors: list[str] = []

    @property
    def phishtank_configured(self) -> bool:
        return bool(get_settings().phishtank_app_key)

    @property
    def status(self) -> dict[str, bool]:
        return {
            "cert_polska_configured": True,
            "phishtank_configured": self.phishtank_configured,
            "zero_fee_feed_cache_ready": bool(self._cert_domains or self._phishtank_urls),
        }

    async def lookup(self, raw_url: str) -> ThreatFeedResult:
        await self._refresh_if_stale()
        host, comparable = normalise_url(raw_url)
        signals: list[str] = []
        score = 0

        if comparable in self._phishtank_urls:
            signals.append("PhishTank matched a verified online phishing URL")
            score = max(score, 96)
        if host and any(host == domain or host.endswith(f".{domain}") for domain in self._cert_domains):
            signals.append("CERT Polska matched a known dangerous domain")
            score = max(score, 94)

        if signals:
            return ThreatFeedResult(signals, score, "zero-fee-threat-feeds+python-rules")
        if self._cert_domains or self._phishtank_urls:
            return ThreatFeedResult([], 0, "zero-fee-threat-feeds+python-rules")
        return ThreatFeedResult(
            ["Live threat feeds could not be refreshed; local Python rules were used"],
            0,
            "python-rules",
        )

    async def _refresh_if_stale(self) -> None:
        settings = get_settings()
        ttl = timedelta(minutes=settings.threat_feed_refresh_minutes)
        if self._updated_at and datetime.now(UTC) - self._updated_at < ttl:
            return
        async with self._refresh_lock:
            if self._updated_at and datetime.now(UTC) - self._updated_at < ttl:
                return
            await self._refresh()

    async def _refresh(self) -> None:
        settings = get_settings()
        errors: list[str] = []
        cert_domains: set[str] | None = None
        phishtank_urls: set[str] | None = None
        try:
            async with httpx.AsyncClient(timeout=20, follow_redirects=True) as client:
                cert_response = await client.get(CERT_POLSKA_URL)
                cert_response.raise_for_status()
                cert_domains = {
                    line.strip().lower().rstrip(".")
                    for line in cert_response.text.splitlines()
                    if line.strip() and not line.lstrip().startswith("#")
                }
                if settings.phishtank_app_key:
                    phishtank_response = await client.get(PHISHTANK_URL.format(app_key=settings.phishtank_app_key))
                    phishtank_response.raise_for_status()
                    records = json.loads(bz2.decompress(phishtank_response.content))
                    phishtank_urls = {
                        normalise_url(record["url"])[1]
                        for record in records
                        if isinstance(record, dict) and isinstance(record.get("url"), str)
                    }
        except (httpx.HTTPError, OSError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as error:
            errors.append(type(error).__name__)

        # Keep the last known-good data if one source is temporarily unavailable.
        if cert_domains is not None:
            self._cert_domains = cert_domains
        if phishtank_urls is not None:
            self._phishtank_urls = phishtank_urls
        self._last_errors = errors
        self._updated_at = datetime.now(UTC)
