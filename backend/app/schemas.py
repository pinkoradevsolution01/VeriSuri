from enum import Enum
from pydantic import BaseModel, Field


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


class Assessment(BaseModel):
    score: int = Field(ge=0, le=100)
    level: RiskLevel
    verdict: str
    summary: str
    signals: list[str] = []
    explanations: list[AssessmentExplanation] = []
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


class ReportLookupRequest(BaseModel):
    identifier: str = Field(min_length=3, max_length=180)
    entity_type: str = Field(pattern="^(gcash|maya|bank|phone|url)$")


class ScamReportCreate(BaseModel):
    entity_type: str = Field(pattern="^(gcash|maya|bank|phone|url|social)$")
    entity_value: str = Field(min_length=3, max_length=500)
    narrative: str = Field(min_length=20, max_length=6000)
    incident_at: str | None = None


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
