"""Server-side URL intelligence. It never sends the user browser to a submitted link."""
from __future__ import annotations
import asyncio, ipaddress, re, socket
from datetime import UTC, datetime
from urllib.parse import urlsplit, urlunsplit
import httpx
from backend.app.schemas import LinkIntelligence

OFFICIAL_DOMAINS = ("gcash.com", "maya.ph", "bpi.com.ph", "bdo.com.ph", "metrobank.com.ph", "unionbankph.com")
URL_IN_TEXT = re.compile(r"https?://[^\s<>\"']+|www\.[^\s<>\"']+", re.IGNORECASE)

def normalise_copied_url(value: str) -> str:
    """Turn common safe-copy/defanged URL forms into a parsable URL string."""
    clean = value.strip()
    clean = re.sub(r"(?i)\b(https?)\s*\\+\s*:\s*", r"\1:", clean)
    clean = re.sub(
        r"(?i)\b(hxxps?)\s*:\s*//",
        lambda match: "https://" if match.group(1).casefold() == "hxxps" else "http://",
        clean,
    )
    return clean.replace("[.]", ".")

def extract_url(value: str) -> tuple[str, bool]:
    """Accept a pasted URL or extract one safely from a copied message."""
    raw = normalise_copied_url(value)
    match = URL_IN_TEXT.search(raw)
    if match:
        candidate = match.group(0).rstrip(".,;:!)]}'\"")
        return candidate, candidate != raw
    return raw, False

def is_official_domain(host: str) -> bool:
    return any(host == domain or host.endswith(f".{domain}") for domain in OFFICIAL_DOMAINS)

def normalize_url(value: str) -> tuple[str, str]:
    raw = normalise_copied_url(value)
    try:
        parsed = urlsplit(raw if "://" in raw else f"https://{raw}")
    except ValueError:
        return "", ""
    scheme = parsed.scheme.lower() or "https"
    if scheme not in {"http", "https"}:
        return "", ""
    host = (parsed.hostname or "").lower().rstrip(".")
    try: host = host.encode("idna").decode("ascii")
    except UnicodeError: pass
    try:
        port_number = parsed.port
    except ValueError:
        return "", ""
    port = f":{port_number}" if port_number and port_number not in (80, 443) else ""
    return host, urlunsplit((scheme, f"{host}{port}", parsed.path or "/", parsed.query, ""))

def intelligence_risk_signals(intelligence: LinkIntelligence) -> tuple[list[str], int]:
    """Score passive destination evidence without claiming an unknown URL is safe."""
    signals: list[str] = []
    score = 0
    if not intelligence.canonical_host:
        return signals, score
    if not intelligence.official_domain and intelligence.domain_age_days is not None:
        if intelligence.domain_age_days < 30:
            signals.append("Domain registration evidence suggests a very new domain (under 30 days old)")
            score = max(score, 42)
        elif intelligence.domain_age_days < 90:
            signals.append("Domain registration evidence suggests a recently registered domain (under 90 days old)")
            score = max(score, 25)
    if intelligence.redirect_hosts and any(host != intelligence.canonical_host for host in intelligence.redirect_hosts):
        signals.append("Server-side redirect inspection changed the destination host")
        score = max(score, 35)
    return signals, score

async def _public_host(host: str) -> bool:
    if not host or host == "localhost": return False
    try:
        records = await asyncio.to_thread(socket.getaddrinfo, host, None)
        return bool(records) and all(ipaddress.ip_address(record[4][0]).is_global for record in records)
    except (OSError, ValueError): return False

async def inspect_url(raw_url: str) -> LinkIntelligence:
    host, canonical = normalize_url(raw_url)
    official = is_official_domain(host)
    notes: list[str] = ["Canonical URL was normalized on the server; the submitted link was not opened in your browser."]
    if host.startswith("xn--"): notes.append("Internationalized (punycode) domain detected; inspect the destination carefully.")
    if official: notes.append("Host matches VeriSuri's official-domain allowlist.")
    redirects: list[str] = []
    registered_on: str | None = None
    age_days: int | None = None
    if not await _public_host(host):
        notes.append("Destination is not a public resolvable host; server-side redirect checks were not performed.")
        return LinkIntelligence(canonical_host=host or None, official_domain=official, redirect_hosts=redirects, notes=notes)
    current = canonical
    try:
        async with httpx.AsyncClient(timeout=4, follow_redirects=False, headers={"User-Agent": "VeriSuri-Link-Safety/1.0"}) as client:
            rdap = await client.get(f"https://rdap.org/domain/{host}")
            if rdap.status_code == 200:
                for event in rdap.json().get("events", []):
                    if event.get("eventAction") == "registration" and isinstance(event.get("eventDate"), str):
                        registered = datetime.fromisoformat(event["eventDate"].replace("Z", "+00:00"))
                        registered_on = registered.date().isoformat()
                        age_days = max(0, (datetime.now(UTC) - registered.astimezone(UTC)).days)
                        notes.append(f"Domain registration evidence: approximately {age_days} day(s) old.")
                        break
            for _ in range(4):
                response = await client.head(current)
                location = response.headers.get("location")
                if not location or response.status_code not in (301, 302, 303, 307, 308): break
                next_url = str(httpx.URL(current).join(location)); next_host, _ = normalize_url(next_url)
                if not await _public_host(next_host): notes.append("A redirect pointed to a non-public destination and was not followed."); break
                redirects.append(next_host); current = next_url
            if redirects: notes.append(f"Server-side redirect inspection found {len(redirects)} redirect hop(s).")
    except (httpx.HTTPError, ValueError): notes.append("Redirect or domain-registration evidence could not be inspected safely at this time.")
    return LinkIntelligence(canonical_host=host, official_domain=official, redirect_hosts=redirects, domain_registered_on=registered_on, domain_age_days=age_days, notes=notes)
