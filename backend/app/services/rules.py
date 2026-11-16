import re
from urllib.parse import urlparse

SCAM_PATTERNS: list[tuple[re.Pattern[str], str, int]] = [
    (re.compile(r"\b(verify|verification|validate)\b.{0,35}\b(account|gcash|maya|bank)\b", re.I), "Requests account verification", 22),
    (re.compile(r"\b(urgent|immediately|now na|asap|within \d+ (minutes|hours))\b", re.I), "Uses urgency to pressure the recipient", 17),
    (re.compile(r"\b(otp|one[- ]time password|mpin|password|pin)\b", re.I), "Requests a secret credential", 30),
    (re.compile(r"\b(you won|prize|cashback|refund|claim now)\b", re.I), "Uses a prize or refund lure", 15),
    (re.compile(r"\b(click|tap|open)\b.{0,45}\b(link|here)\b", re.I), "Directs the recipient to a link", 14),
]
SUSPICIOUS_TLDS = {"xyz", "top", "click", "live", "shop", "site", "info", "buzz"}
BRAND_TERMS = {"gcash", "maya", "bpi", "bdo", "metrobank", "unionbank", "paymaya"}

def message_signals(text: str) -> tuple[list[str], int]:
    signals, score = [], 0
    for pattern, signal, weight in SCAM_PATTERNS:
        if pattern.search(text): signals.append(signal); score += weight
    if re.search(r"https?://\S+", text, re.I): signals.append("Contains an external URL"); score += 8
    if text.count("!") >= 3 or sum(c.isupper() for c in text) > max(10, len(text) * .45): signals.append("Uses unusually forceful formatting"); score += 7
    return signals, min(score, 100)

def url_signals(raw_url: str) -> tuple[list[str], int]:
    parsed = urlparse(raw_url if "://" in raw_url else f"https://{raw_url}")
    hostname = (parsed.hostname or "").lower()
    signals, score = [], 0
    if not hostname: return ["The URL has no valid hostname"], 90
    if parsed.scheme != "https": signals.append("Does not use HTTPS"); score += 22
    if "@" in raw_url: signals.append("Uses an @ symbol that can disguise the destination"); score += 35
    if hostname.replace(".", "").isdigit() or re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", hostname): signals.append("Uses an IP address instead of a trusted domain"); score += 30
    labels = hostname.split(".")
    if len(labels) > 4: signals.append("Uses an unusually deep subdomain"); score += 14
    if labels and labels[-1] in SUSPICIOUS_TLDS: signals.append("Uses a higher-risk domain ending"); score += 15
    official = ("gcash.com", "maya.ph", "bpi.com.ph", "bdo.com.ph", "metrobank.com.ph", "unionbankph.com")
    if any(term in hostname for term in BRAND_TERMS) and not hostname.endswith(official): signals.append("May imitate a Philippine financial brand"); score += 38
    if "-" in hostname and any(term in hostname for term in BRAND_TERMS): signals.append("Uses a brand name in a hyphenated domain"); score += 15
    return signals, min(score, 100)
