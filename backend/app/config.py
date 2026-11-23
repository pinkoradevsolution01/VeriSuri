from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    app_name: str = "VeriSuri Detection API"
    environment: str = "development"
    allowed_origins: str = "http://localhost:5173"
    google_web_risk_api_key: str | None = None
    enable_google_web_risk: bool = False
    free_web_risk_monthly_budget: int = 100000
    phishtank_app_key: str | None = None
    threat_feed_refresh_minutes: int = 60
    enable_phishdestroy: bool = True
    phishdestroy_cache_minutes: int = 15
    phishdestroy_requests_per_minute: int = 30
    api_rate_limit_per_minute: int = 45
    api_max_request_bytes: int = 25_000
    security_monitoring_salt: str = "development-only-change-in-production"
    supabase_url: str | None = None
    supabase_service_role_key: str | None = None
    # Approved model artifacts are private Supabase Storage objects.  The API
    # fetches them server-side into its ephemeral runtime cache; they are never
    # shipped to the browser or committed to Git.
    url_model_bucket: str = "verisuri-model-artifacts"
    url_model_artifact_path: str = "url-models/verisuri-url-v1.joblib"
    url_model_metrics_path: str = "url-models/verisuri-url-v1.metrics.json"

    @property
    def origins(self) -> list[str]:
        return [origin.strip() for origin in self.allowed_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
