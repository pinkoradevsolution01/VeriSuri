"""Server-side URL intelligence. It never sends the user browser to a submitted link."""
from __future__ import annotations
import asyncio, ipaddress, re, socket, ssl
from datetime import UTC, datetime
from urllib.parse import urlsplit, urlunsplit
import httpx
from backend.app.schemas import LinkIntelligence

# Provider-owned domains only. Review this registry before each production
# release; an allowlist match is helpful evidence, never a safety guarantee.
OFFICIAL_PROVIDER_DOMAINS: dict[str, tuple[str, ...]] = {
    "GCash": ("gcash.com",), "Maya": ("maya.ph",), "BDO": ("bdo.com.ph",),
    "BPI": ("bpi.com.ph",), "Metrobank": ("metrobank.com.ph",), "UnionBank": ("unionbankph.com",),
    "GoTyme Bank": ("gotyme.com.ph",), "Security Bank": ("securitybank.com",), "LANDBANK": ("landbank.com",),
    "Globe": ("globe.com.ph",), "Smart / TNT": ("smart.com.ph",), "DITO": ("dito.ph",),
}
OFFICIAL_DOMAINS = tuple(domain for domains in OFFICIAL_PROVIDER_DOMAINS.values() for domain in domains)
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

def official_provider_for_host(host: str) -> str | None:
    return next((provider for provider, domains in OFFICIAL_PROVIDER_DOMAINS.items() if any(host == domain or host.endswith(f".{domain}") for domain in domains)), None)

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
    if intelligence.dns_public_resolvable is False:
        signals.append("Destination does not resolve only to public DNS addresses")
        score = max(score, 75)
    if intelligence.tls_certificate_valid is False:
        signals.append("HTTPS certificate could not be validated server-side")
        score = max(score, 55)
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

async def _public_addresses(host: str) -> list[str]:
    if not host or host == "localhost": return []
    try:
        records = await asyncio.to_thread(socket.getaddrinfo, host, None)
        addresses = sorted({record[4][0] for record in records})
        return addresses if addresses and all(ipaddress.ip_address(address).is_global for address in addresses) else []
    except (OSError, ValueError): return []

async def _public_host(host: str) -> bool:
    return bool(await _public_addresses(host))

def _inspect_tls_certificate(host: str, addresses: list[str]) -> tuple[bool | None, str | None]:
    """Validate only a TLS handshake to an already-public resolved address."""
    context = ssl.create_default_context()
    for address in addresses:
        try:
            with socket.create_connection((address, 443), timeout=4) as connection:
                with context.wrap_socket(connection, server_hostname=host) as secure_connection:
                    certificate = secure_connection.getpeercert()
                    expires = certificate.get("notAfter")
                    expires_on = datetime.strptime(expires, "%b %d %H:%M:%S %Y %Z").date().isoformat() if expires else None
                    return True, expires_on
        except ssl.SSLCertVerificationError:
            return False, None
        except (OSError, ssl.SSLError, ValueError):
            continue
    return None, None

async def inspect_url(raw_url: str) -> LinkIntelligence:
    host, canonical = normalize_url(raw_url)
    official = is_official_domain(host)
    provider = official_provider_for_host(host)
    notes: list[str] = ["Canonical URL was normalized on the server; the submitted link was not opened in your browser."]
    if host.startswith("xn--"): notes.append("Internationalized (punycode) domain detected; inspect the destination carefully.")
    if official: notes.append(f"Host matches VeriSuri's official {provider} domain allowlist.")
    redirects: list[str] = []
    registered_on: str | None = None
    age_days: int | None = None
    addresses = await _public_addresses(host)
    if not addresses:
        notes.append("Destination is not a public resolvable host; server-side redirect checks were not performed.")
        return LinkIntelligence(canonical_host=host or None, official_domain=official, official_provider=provider, redirect_hosts=redirects, dns_public_resolvable=False, notes=notes)
    notes.append("Destination resolves to public DNS addresses; no page content was downloaded.")
    tls_valid: bool | None = None
    tls_expires_on: str | None = None
    if canonical.startswith("https://"):
        tls_valid, tls_expires_on = await asyncio.to_thread(_inspect_tls_certificate, host, addresses)
        if tls_valid is True:
            notes.append("HTTPS certificate was validated server-side; this does not prove the site is trustworthy.")
        elif tls_valid is False:
            notes.append("HTTPS certificate could not be validated server-side.")
        else:
            notes.append("HTTPS certificate evidence was unavailable at this time.")
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
    return LinkIntelligence(canonical_host=host, official_domain=official, official_provider=provider, redirect_hosts=redirects, domain_registered_on=registered_on, domain_age_days=age_days, dns_public_resolvable=True, tls_certificate_valid=tls_valid, tls_certificate_expires_on=tls_expires_on, notes=notes)
