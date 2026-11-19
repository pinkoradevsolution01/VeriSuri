from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from backend.app.config import get_settings
from backend.app.schemas import AlertItem, Assessment, LinkRequest, MessageRequest, PaymentRequest, ReportLookupRequest, ScamReportCreate
from backend.app.services.detector import HybridDetector, build_assessment
from backend.app.services.rules import url_signals
from backend.app.services.supabase import SupabaseRepository
from backend.app.services.threat_feeds import ThreatFeedClient
from backend.app.services.web_risk import WebRiskClient
from backend.app.services.url_intelligence import inspect_url

detector, repository, web_risk, threat_feeds = HybridDetector(), SupabaseRepository(), WebRiskClient(), ThreatFeedClient()
app = FastAPI(title="VeriSuri Detection API", version="1.0.0", docs_url="/api/docs", openapi_url="/api/openapi.json")
app.add_middleware(CORSMiddleware, allow_origins=get_settings().origins, allow_credentials=True, allow_methods=["GET", "POST"], allow_headers=["*"])

@app.get("/api/v1/health")
async def health() -> dict[str, str | bool]:
    return {
        "status": "ok",
        "engine": detector.version,
        "model_release_approved": detector.model_release_approved,
        "web_risk_configured": web_risk.configured,
        "web_risk_enabled": web_risk.enabled,
        "supabase_report_matching_configured": repository.enabled,
        **threat_feeds.status,
    }

@app.post("/api/v1/analyze/message", response_model=Assessment)
async def analyze_message(payload: MessageRequest) -> Assessment: return detector.analyze(payload.text)

@app.post("/api/v1/analyze/link", response_model=Assessment)
async def analyze_link(payload: LinkRequest, request: Request) -> Assessment:
    signals, score = url_signals(payload.url)
    intelligence = await inspect_url(payload.url)
    if intelligence.redirect_hosts:
        signals.append(f"Server-side redirect chain: {' → '.join(intelligence.redirect_hosts)}")
    if not intelligence.official_domain and intelligence.canonical_host and intelligence.canonical_host.startswith("xn--"):
        signals.append("Uses a punycode domain that can imitate familiar characters"); score = max(score, 55)
    feed_result = await threat_feeds.lookup(payload.url)
    signals.extend(feed_result.signals)
    score = max(score, feed_result.score)
    unsafe, threat_types = None, []
    source = feed_result.source
    # Google Web Risk remains implemented for a later billing-enabled release.
    # The zero-fee feeds and Python engine are the default starting architecture.
    if web_risk.enabled:
        token = request.headers.get("authorization", "").removeprefix("Bearer ").strip()
        user_id = await repository.user_id_from_access_token(token)
        if not user_id:
            signals.append("Sign in to use subscription URL scans; local URL rules were used")
        else:
            authorization = await repository.authorize_web_risk_scan(user_id, payload.url)
            if authorization is None:
                signals.append("URL-scan safety service is unavailable; local URL rules were used")
            elif not authorization.allowed:
                signals.append(f"{authorization.reason}. Local URL rules were used")
            else:
                quota = await repository.consume_web_risk_quota(user_id)
                if quota is None:
                    signals.append("URL-scan quota service is unavailable; local URL rules were used")
                elif not quota.allowed:
                    signals.append(f"{quota.reason}. Local URL rules were used")
                else:
                    unsafe, threat_types = await web_risk.lookup(payload.url)
                    if unsafe is None:
                        signals.append("Google Web Risk is unavailable; zero-fee feeds and local Python rules were used")
                    else:
                        source = "google-web-risk+zero-fee-threat-feeds+python-rules"
                        signals.append(f"{quota.plan.title()} plan: {quota.remaining_today} of {quota.daily_limit} Google Web Risk scans remain today")
    if unsafe: signals.append(f"Google Web Risk matched: {', '.join(threat_types)}"); score = max(score, 92)
    assessment = build_assessment(score, signals, detector.version, source, "link", payload.url)
    assessment.link_intelligence = intelligence
    return assessment

async def lookup_entity(identifier: str, entity_type: str, context: str) -> Assessment:
    count = await repository.report_count(entity_type, identifier)
    if count is None: return build_assessment(0, ["Community report matching will activate after Supabase is configured"], detector.version, "community-report-pending", context, identifier)
    if count: return build_assessment(min(95, 62 + count * 8), [f"Matched {count} confirmed community report(s)"], detector.version, "supabase-report-matching", context, identifier)
    return build_assessment(0, ["No confirmed community reports matched this identifier"], detector.version, "supabase-report-matching", context, identifier)

@app.post("/api/v1/check/payment", response_model=Assessment)
async def check_payment(payload: PaymentRequest) -> Assessment: return await lookup_entity(payload.identifier, payload.provider, "payment")

@app.post("/api/v1/reports/lookup", response_model=Assessment)
async def report_lookup(payload: ReportLookupRequest) -> Assessment: return await lookup_entity(payload.identifier, payload.entity_type, "report")

@app.post("/api/v1/reports", status_code=501)
async def create_report(payload: ScamReportCreate) -> dict[str, str]:
    raise HTTPException(status_code=501, detail="Connect Supabase Auth before enabling report submission.")

@app.get("/api/v1/alerts", response_model=list[AlertItem])
async def alerts() -> list[AlertItem]:
    live = await repository.published_alerts()
    if live is not None:
        return live
    return []
