import re
from urllib.parse import urlparse
from backend.app.services.url_intelligence import is_official_domain

SCAM_PATTERNS: list[tuple[re.Pattern[str], str, int]] = [
    (re.compile(r"\b(verify|verification|validate)\b.{0,35}\b(account|gcash|maya|bank)\b", re.I), "Requests account verification", 22),
    (re.compile(r"\b(urgent|immediately|now na|asap|within \d+ (minutes|hours))\b", re.I), "Uses urgency to pressure the recipient", 17),
    (re.compile(r"\b(otp|one[- ]time password|mpin|password|pin)\b", re.I), "Requests a secret credential", 30),
    (re.compile(r"\b(you won|prize|cashback|refund|claim now)\b", re.I), "Uses a prize or refund lure", 15),
    (re.compile(r"\b(click|tap|open)\b.{0,45}\b(link|here)\b", re.I), "Directs the recipient to a link", 14),
    (re.compile(r"\b(beripikahin|i-verify|kumpirmahin)\b.{0,40}\b(account|gcash|maya|bangko)\b", re.I), "Requests Filipino account verification", 22),
    (re.compile(r"\b(ipadala|ibigay|send)\b.{0,35}\b(otp|pin|mpin|password)\b", re.I), "Requests an OTP or secret in Filipino/Taglish", 30),
    (re.compile(r"\b(agad|ngayon na|madaliin|asap|within \d+ (minuto|oras))\b", re.I), "Uses Filipino/Taglish urgency", 17),
    (re.compile(r"\b(nanalo|napanalunan|premyo|libreng pera|cashback)\b", re.I), "Uses a Filipino prize or reward lure", 15),
    (re.compile(r"\b(i-click|pindutin|buksan)\b.{0,45}\b(link|dito)\b", re.I), "Directs the recipient to a link in Filipino/Taglish", 14),
]
SUSPICIOUS_TLDS = {"xyz", "top", "click", "live", "shop", "site", "info", "buzz"}
BRAND_TERMS = {"gcash", "maya", "bpi", "bdo", "metrobank", "unionbank", "paymaya"}
URL_SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "is.gd", "cutt.ly", "shorturl.at", "tiny.one"}
URL_LURE_TERMS = {"login", "verify", "verification", "secure", "activate", "claim", "reward", "credit", "limit", "otp"}

def _edit_distance(left: str, right: str) -> int:
    """Small dependency-free edit-distance helper for host-label lookalikes."""
    previous = list(range(len(right) + 1))
    for index, character in enumerate(left, 1):
        current = [index]
        for column, other in enumerate(right, 1):
            current.append(min(previous[column] + 1, current[-1] + 1, previous[column - 1] + (character != other)))
        previous = current
    return previous[-1]

def _brand_lookalike(hostname: str) -> str | None:
    translation = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "@": "a"})
    for label in hostname.split(".")[:-1]:
        for candidate in filter(None, re.split(r"[-_]", label.casefold())):
            compact = candidate.translate(translation)
            for brand in BRAND_TERMS:
                if compact and candidate != brand and _edit_distance(compact, brand) <= 1:
                    return brand
    return None

def message_evidence(text: str) -> tuple[list[str], int, list[tuple[int, int, str, str]]]:
    signals, score, highlights = [], 0, []
    for pattern, signal, weight in SCAM_PATTERNS:
        match = pattern.search(text)
        if match:
            signals.append(signal); score += weight
            highlights.append((match.start(), match.end(), match.group(0), signal))
    url_match = re.search(r"https?://\S+", text, re.I)
    if url_match:
        signals.append("Contains an external URL"); score += 8
        highlights.append((url_match.start(), url_match.end(), url_match.group(0), "Contains an external URL"))
    if text.count("!") >= 3 or sum(c.isupper() for c in text) > max(10, len(text) * .45): signals.append("Uses unusually forceful formatting"); score += 7
    return signals, min(score, 100), highlights


def message_signals(text: str) -> tuple[list[str], int]:
    signals, score, _ = message_evidence(text)
    return signals, score

def url_signals(raw_url: str) -> tuple[list[str], int]:
    try:
        parsed = urlparse(raw_url if "://" in raw_url else f"https://{raw_url}")
        _ = parsed.port
    except ValueError:
        return ["The URL has no valid hostname"], 90
    hostname = (parsed.hostname or "").lower()
    try: hostname = hostname.encode("idna").decode("ascii")
    except UnicodeError: pass
    signals, score = [], 0
    if not hostname: return ["The URL has no valid hostname"], 90
    if parsed.scheme != "https": signals.append("Does not use HTTPS"); score += 22
    if "@" in raw_url: signals.append("Uses an @ symbol that can disguise the destination"); score += 35
    if hostname.replace(".", "").isdigit() or re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", hostname): signals.append("Uses an IP address instead of a trusted domain"); score += 30
    labels = hostname.split(".")
    if len(labels) > 4: signals.append("Uses an unusually deep subdomain"); score += 14
    if labels and labels[-1] in SUSPICIOUS_TLDS: signals.append("Uses a higher-risk domain ending"); score += 15
    if any(term in hostname for term in BRAND_TERMS) and not is_official_domain(hostname): signals.append("May imitate a Philippine financial brand"); score += 38
    if "-" in hostname and any(term in hostname for term in BRAND_TERMS): signals.append("Uses a brand name in a hyphenated domain"); score += 15
    lookalike = _brand_lookalike(hostname)
    if lookalike and not is_official_domain(hostname):
        signals.append(f"Domain label closely resembles the {lookalike.upper()} brand")
        score += 34
    if hostname in URL_SHORTENERS or any(hostname.endswith(f".{domain}") for domain in URL_SHORTENERS):
        signals.append("Uses a URL shortener that hides the final destination")
        score += 14
    lowered_path = f"{parsed.path}?{parsed.query}".casefold()
    if not is_official_domain(hostname) and any(term in lowered_path for term in URL_LURE_TERMS):
        signals.append("URL path or query contains account or reward lure terms")
        score += 12
    if len(raw_url) > 220:
        signals.append("Uses an unusually long URL that can conceal its destination")
        score += 10
    if parsed.query and re.search(r"(?:^|[?&])(redirect|redirect_uri|return_url|target|url)=", parsed.query, re.I):
        signals.append("Contains a redirect parameter that can obscure the final destination")
        score += 8
    return signals, min(score, 100)
