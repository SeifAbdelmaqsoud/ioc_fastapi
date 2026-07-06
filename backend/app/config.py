from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

# resolve relative to this file so it still finds .env regardless of where uvicorn was launched from
_ENV_FILE = Path(__file__).resolve().parent.parent / ".env"


class Settings(BaseSettings):
    vt_api_key: str
    openrouter_api_key: str
    openrouter_model: str = "nvidia/nemotron-3-ultra-550b-a55b:free"

    model_config = SettingsConfigDict(
        env_file=_ENV_FILE,
        env_file_encoding="utf-8",
        extra="ignore",
    )


settings = Settings()
