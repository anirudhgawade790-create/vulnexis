from functools import lru_cache
from typing import List, Union

from pydantic import field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # Database
    database_url: str = "sqlite+aiosqlite:///./sih1684.db"

    # Redis / Celery
    redis_url: str = "redis://localhost:6379/0"
    celery_broker_url: str = "redis://localhost:6379/1"
    celery_result_backend: str = "redis://localhost:6379/2"

    # JWT
    secret_key: str = "change-this-to-a-secure-random-secret-at-least-32-chars"
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 30
    refresh_token_expire_days: int = 7

    # CORS — accepts both JSON array and comma-separated string
    cors_origins: Union[List[str], str] = ["http://localhost:3000", "http://localhost:5173"]

    @field_validator("cors_origins", mode="before")
    @classmethod
    def parse_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        if isinstance(v, list):
            return v
        # comma-separated: "http://a,http://b"
        if isinstance(v, str) and not v.startswith("["):
            return [o.strip() for o in v.split(",") if o.strip()]
        # JSON array string: '["http://a","http://b"]'
        import json
        return json.loads(v)

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
