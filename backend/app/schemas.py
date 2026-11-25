from enum import Enum
from uuid import UUID
import re

from pydantic import BaseModel, Field, model_validator


class RiskLevel(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"


class AssessmentExplanation(BaseModel):
    """One human-readable reason contributing to an assessment."""
    category: str
    label: str
    detail: str
    source: str


class HighlightedSignal(BaseModel):
    start: int
    end: int
    text: str
    label: str
    source: str


class LinkIntelligence(BaseModel):
    canonical_host: str | None = None
    official_domain: bool = False
    official_provider: str | None = None
    redirect_hosts: list[str] = []
    domain_registered_on: str | None = None
    domain_age_days: int | None = None
    dns_public_resolvable: bool | None = None
    tls_certificate_valid: bool | None = None
    tls_certificate_expires_on: str | None = None
    notes: list[str] = []


class Assessment(BaseModel):
    score: int = Field(ge=0, le=100)
    level: RiskLevel
    verdict: str
    summary: str
    signals: list[str] = []
    explanations: list[AssessmentExplanation] = []
    highlights: list[HighlightedSignal] = []
    calibrated_scam_probability: int | None = None
    confidence_basis: str | None = None
    evidence_confidence: str = "limited"
    verification_required: bool = True
    verification_message: str = "Independent verification through an official channel is required before acting."
    link_intelligence: LinkIntelligence | None = None
    recommendation_title: str
    recommendations: list[str]
    engine_version: str
    source: str


class MessageRequest(BaseModel):
    text: str = Field(min_length=3, max_length=6000)


class LinkRequest(BaseModel):
    url: str = Field(min_length=5, max_length=2048)


class PaymentRequest(BaseModel):
    identifier: str = Field(min_length=3, max_length=180)
    provider: str = Field(pattern="^(gcash|maya|bank)$")

    @model_validator(mode="after")
    def validate_payment_identifier(self):
        compact = re.sub(r"[\s-]", "", self.identifier)
        if self.provider in {"gcash", "maya"}:
            digits = compact.removeprefix("+")
            valid = bool(re.fullmatch(r"(?:63|0)?9\d{9}", digits))
            if not valid:
                raise ValueError(f"Enter a valid Philippine mobile number for {self.provider.title()}, such as 0917 123 4567.")
        elif not re.fullmatch(r"\d{6,30}", compact):
            raise ValueError("Enter a valid bank account number using 6–30 digits.")
        return self


class ReportLookupRequest(BaseModel):
    identifier: str = Field(min_length=3, max_length=180)
    entity_type: str = Field(pattern="^(gcash|maya|bank|phone|url)$")


class ScamReportCreate(BaseModel):
    entity_type: str = Field(pattern="^(gcash|maya|bank|phone|url|social)$")
    entity_value: str = Field(min_length=3, max_length=500)
    narrative: str = Field(min_length=20, max_length=6000)
    incident_at: str | None = None
    scam_type: str = Field(default="other", pattern="^(phishing|investment|marketplace|impersonation|loan|romance|job|delivery|other)$")
    payment_provider: str = Field(default="not_applicable", pattern="^(gcash|maya|bank|card|crypto|not_applicable)$")
    amount_range: str = Field(default="not_stated", pattern="^(under_1000|1000_4999|5000_19999|20000_99999|100000_plus|not_stated)$")
    incident_channel: str = Field(default="other", pattern="^(sms|messaging_app|social_media|email|call|website|marketplace|other)$")
    redacted_evidence: str | None = Field(default=None, max_length=6000)
    privacy_notice_version: str = Field(min_length=1, max_length=80)
    acknowledges_safe_submission: bool
    training_consent: bool = False
    redacted_training_sample: str | None = Field(default=None, max_length=6000)
    public_contributor_consent: bool = False


class ModerationDecision(BaseModel):
    status: str = Field(pattern="^(confirmed|rejected)$")
    reason: str = Field(min_length=3, max_length=1000)


class AlertItem(BaseModel):
    id: str
    title: str
    summary: str
    severity: RiskLevel
    published_at: str
    source_name: str
    source_url: str
    affected_platform: str
    region: str | None = None
    review_at: str
    expires_at: str
