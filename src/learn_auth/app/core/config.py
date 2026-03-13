from pydantic import SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Settings for the application."""

    model_config = SettingsConfigDict(
        env_file=".envrc",
        extra="allow",
        case_sensitive=True,
    )
    # General
    APP_NAME: str = "learn_auth"
    HOST: str = "0.0.0.0"
    PORT: int = 8080
    DEBUG: bool = True
    SCHEMA: str = "learn_auth"
    SKIP_DB_INIT: bool = True

    # Database (from .envrc)
    POSTGRES_USER: str = ""
    POSTGRES_PASSWORD: SecretStr = SecretStr("")
    POSTGRES_DB: str = ""
    POSTGRES_PORT: int = 5432
    DATABASE_URL: str = ""

    # JWT — add these to .envrc too!
    JWT_SECRET_KEY: SecretStr = SecretStr("")  # 256-bit random secret — REQUIRED
    JWT_ALGORITHM: str = "HS256"
    JWT_ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    JWT_REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # Security
    MAX_FAILED_LOGIN_ATTEMPTS: int = 5
    ACCOUNT_LOCKOUT_MINUTES: int = 15


settings = Settings()


if __name__ == "__main__":
    print(settings.model_dump())
