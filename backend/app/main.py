from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from backend.app.config import get_settings
from backend.app.schemas import AlertItem, Assessment, LinkRequest, MessageRequest, PaymentRequest, ReportLookupRequest, ScamReportCreate
from backend.app.services.detector import HybridDetector, build_assessment
from backend.app.services.rules import url_signals
from backend.app.services.supabase import SupabaseRepository
from backend.app.services.web_risk import WebRiskClient

detector, repository, web_risk = HybridDetector(), SupabaseRepository(), WebRiskClient()
app = FastAPI(title="VeriSuri Detection API", version="1.0.0", docs_url="/api/docs", openapi_url="/api/openapi.json")
app.add_middleware(CORSMiddleware, allow_origins=get_settings().origins, allow_credentials=True, allow_methods=["GET", "POST"], allow_headers=["*"])

@app.get("/api/v1/health")
async def health() -> dict[str, str]: return {"status": "ok", "engine": detector.version}

@app.post("/api/v1/analyze/message", response_model=Assessment)
async def analyze_message(payload: MessageRequest) -> Assessment: return detector.analyze(payload.text)

@app.post("/api/v1/analyze/link", response_model=Assessment)
async def analyze_link(payload: LinkRequest) -> Assessment:
    signals, score = url_signals(payload.url)
    unsafe, threat_types = await web_risk.lookup(payload.url)
    if unsafe: signals.append(f"Google Web Risk matched: {', '.join(threat_types)}"); score = max(score, 92)
    elif unsafe is None: signals.append("Google Web Risk is unavailable; local URL rules were used")
    return build_assessment(score, signals, detector.version, "google-web-risk+url-rules" if unsafe is not None else "url-rules")

async def lookup_entity(identifier: str, entity_type: str) -> Assessment:
    count = await repository.report_count(entity_type, identifier)
    if count is None: return build_assessment(0, ["Community report matching will activate after Supabase is configured"], detector.version, "community-report-pending")
    if count: return build_assessment(min(95, 62 + count * 8), [f"Matched {count} confirmed community report(s)"], detector.version, "supabase-report-matching")
    return build_assessment(0, ["No confirmed community reports matched this identifier"], detector.version, "supabase-report-matching")

@app.post("/api/v1/check/payment", response_model=Assessment)
async def check_payment(payload: PaymentRequest) -> Assessment: return await lookup_entity(payload.identifier, payload.provider)

@app.post("/api/v1/reports/lookup", response_model=Assessment)
async def report_lookup(payload: ReportLookupRequest) -> Assessment: return await lookup_entity(payload.identifier, payload.entity_type)

@app.post("/api/v1/reports", status_code=501)
async def create_report(payload: ScamReportCreate) -> dict[str, str]:
    raise HTTPException(status_code=501, detail="Connect Supabase Auth before enabling report submission.")

@app.get("/api/v1/alerts", response_model=list[AlertItem])
async def alerts() -> list[AlertItem]:
    return [AlertItem(id="sample-gcash", title="New GCash phishing alert", summary="Verify account notices only in the official GCash app.", severity="high", published_at="2026-11-16T00:00:00Z"), AlertItem(id="sample-bpi", title="Bank impersonation scam", summary="Do not provide OTPs in response to unsolicited messages.", severity="medium", published_at="2026-11-15T00:00:00Z")]
