from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Settings for the application."""

    model_config = SettingsConfigDict(
        env_file=".envrc",
        extra="allow",
        case_sensitive=True,
    )
    # General settings
    APP_NAME: str = "learn_auth"
    HOST: str = "0.0.0.0"
    PORT: int = 8080
    DEBUG: bool = True
    SCHEMA: str = "learn_auth"
    SKIP_DB_INIT: bool = True
    # from .envrc file
    POSTGRES_USER: str = ""
    POSTGRES_PASSWORD: str = ""
    POSTGRES_DB: str = ""
    POSTGRES_PORT: int = 5432
    DATABASE_URL: str = ""


settings = Settings()


if __name__ == "__main__":
    print(settings.model_dump())
