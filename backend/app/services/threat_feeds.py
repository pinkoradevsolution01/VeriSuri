"""Zero-fee threat-feed intelligence for URL assessments.

The feeds are refreshed on the server and never exposed to the browser.  A
feed match is evidence, not a guarantee that every other URL is safe.
"""

from __future__ import annotations

import asyncio
import bz2
import json
from collections import deque
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from urllib.parse import urlsplit, urlunsplit

import httpx

from backend.app.config import get_settings


PHISHTANK_URL = "https://data.phishtank.com/data/{app_key}/online-valid.json.bz2"
CERT_POLSKA_URL = "https://hole.cert.pl/domains/v2/domains.txt"
PHISHDESTROY_CHECK_URL = "https://api.destroy.tools/v1/check"


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
    """Server-side intelligence from PhishDestroy, CERT Polska, and PhishTank."""

    def __init__(self) -> None:
        self._phishtank_urls: set[str] = set()
        self._cert_domains: set[str] = set()
        self._updated_at: datetime | None = None
        self._refresh_lock = asyncio.Lock()
        self._phishdestroy_lock = asyncio.Lock()
        self._phishdestroy_cache: dict[str, tuple[datetime, int, list[str]]] = {}
        self._phishdestroy_requests: deque[datetime] = deque()
        self._last_errors: list[str] = []

    @property
    def phishtank_configured(self) -> bool:
        return bool(get_settings().phishtank_app_key)

    @property
    def phishdestroy_enabled(self) -> bool:
        return get_settings().enable_phishdestroy

    @property
    def status(self) -> dict[str, bool]:
        return {
            "cert_polska_configured": True,
            "cert_polska_cache_ready": bool(self._cert_domains),
            "phishdestroy_enabled": self.phishdestroy_enabled,
            "phishdestroy_cache_ready": bool(self._phishdestroy_cache),
            "phishtank_configured": self.phishtank_configured,
            "zero_fee_feed_cache_ready": bool(self._cert_domains or self._phishtank_urls),
        }

    async def lookup(self, raw_url: str) -> ThreatFeedResult:
        await self._refresh_if_stale()
        host, comparable = normalise_url(raw_url)
        signals: list[str] = []
        score = 0

        phishdestroy_score, phishdestroy_signals = await self._check_phishdestroy(host)
        score = max(score, phishdestroy_score)
        signals.extend(phishdestroy_signals)

        if comparable in self._phishtank_urls:
            signals.append("PhishTank matched a verified online phishing URL")
            score = max(score, 96)
        if host and any(host == domain or host.endswith(f".{domain}") for domain in self._cert_domains):
            signals.append("CERT Polska matched a known dangerous domain")
            score = max(score, 94)

        if signals:
            return ThreatFeedResult(signals, score, "phishdestroy+cert-polska+python-rules")
        if self._cert_domains or self._phishtank_urls or self.phishdestroy_enabled:
            return ThreatFeedResult([], 0, "phishdestroy+cert-polska+python-rules")
        return ThreatFeedResult(
            ["Live threat feeds could not be refreshed; local Python rules were used"],
            0,
            "python-rules",
        )

    async def _check_phishdestroy(self, host: str) -> tuple[int, list[str]]:
        """Check only a normalized hostname; never send URL paths or query strings."""
        if not host or not self.phishdestroy_enabled:
            return 0, []
        settings = get_settings()
        now = datetime.now(UTC)
        cached = self._phishdestroy_cache.get(host)
        if cached and now - cached[0] < timedelta(minutes=settings.phishdestroy_cache_minutes):
            return cached[1], cached[2]

        async with self._phishdestroy_lock:
            cached = self._phishdestroy_cache.get(host)
            now = datetime.now(UTC)
            if cached and now - cached[0] < timedelta(minutes=settings.phishdestroy_cache_minutes):
                return cached[1], cached[2]
            cutoff = now - timedelta(minutes=1)
            while self._phishdestroy_requests and self._phishdestroy_requests[0] < cutoff:
                self._phishdestroy_requests.popleft()
            if len(self._phishdestroy_requests) >= settings.phishdestroy_requests_per_minute:
                return 0, []
            self._phishdestroy_requests.append(now)
            try:
                async with httpx.AsyncClient(timeout=5) as client:
                    response = await client.get(PHISHDESTROY_CHECK_URL, params={"domain": host})
                    response.raise_for_status()
                    payload = response.json()
            except (httpx.HTTPError, ValueError):
                return 0, []

            score, signals = 0, []
            reported_score = payload.get("risk_score")
            if isinstance(reported_score, int):
                reported_score = max(0, min(reported_score, 100))
            else:
                reported_score = 0
            if payload.get("threat") is True:
                severity = payload.get("severity")
                detail = f" ({severity.lower()} severity)" if isinstance(severity, str) else ""
                signals.append(f"PhishDestroy matched a listed phishing or scam domain{detail}")
                score = max(85, reported_score)
            elif payload.get("suspicious") is True:
                signals.append("PhishDestroy found suspicious domain indicators")
                score = min(55, max(20, reported_score))
            self._phishdestroy_cache[host] = (now, score, signals)
            return score, signals

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
