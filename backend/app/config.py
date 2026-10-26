from functools import lru_cache
from typing import List

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Database
    database_url: str = "postgresql+asyncpg://sih1684:changeme@localhost:5432/sih1684"

    # Redis / Celery
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"

    # JWT
    secret_key: str = "change-this-to-a-secure-random-secret-at-least-32-chars"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7

    # CORS
    cors_origins: List[str] = ["http://localhost:3000", "http://localhost:5173"]

    # Demo mode
    demo_mode: bool = False

    # External APIs
    nvd_api_key: str = ""
    openai_api_key: str = ""

    # Scanner
    nmap_path: str = "/usr/bin/nmap"
    default_scan_timeout: int = 300
    max_concurrent_scans: int = 3


@lru_cache()
def get_settings() -> Settings:
    return Settings()
