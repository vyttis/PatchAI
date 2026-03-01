"""PatchPilot API configuration via pydantic-settings."""

from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}

    # --- Platform ---
    supabase_url: str = ""
    supabase_service_key: str = ""  # server-side only, never NEXT_PUBLIC_
    supabase_jwt_secret: str = ""  # for FastAPI JWT validation
    database_url: str = ""  # Supabase PgBouncer pooled connection string

    # --- Queue ---
    redis_url: str = ""  # Upstash Frankfurt

    # --- PKI (NEVER in DB) ---
    pki_master_key: str = ""  # 32 bytes hex-encoded (64 chars), Fly.io secret only

    # --- Intel feeds ---
    msrc_api_key: str = ""
    nvd_api_key: str = ""

    # --- AI (optional, org-level gate) ---
    claude_api_key: str = ""  # Only when org.settings.ai_policy.external_ai_enabled

    # --- Internal ---
    secret_key: str = ""  # FastAPI session secret

    # --- App ---
    debug: bool = False
    api_v1_prefix: str = "/api/v1"


settings = Settings()
