from functools import lru_cache
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    app_name: str = "VeriSuri Detection API"
    environment: str = "development"
    allowed_origins: str = "http://localhost:5173"
    google_web_risk_api_key: str | None = None
    free_web_risk_monthly_budget: int = 100000
    supabase_url: str | None = None
    supabase_service_role_key: str | None = None

    @property
    def origins(self) -> list[str]:
        return [origin.strip() for origin in self.allowed_origins.split(",") if origin.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()
