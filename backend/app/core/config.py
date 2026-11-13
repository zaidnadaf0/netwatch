"""Application configuration using Pydantic Settings."""

from functools import lru_cache
from typing import List, Optional
from pydantic_settings import BaseSettings
from pydantic import Field
from pydantic.config import ConfigDict


class Settings(BaseSettings):
    """Application settings."""

    APP_NAME: str = "NetWatch"
    APP_VERSION: str = "0.1.0"
    DEBUG: bool = Field(default=False, validation_alias="NETWATCH_DEBUG")
    ENVIRONMENT: str = Field(default="development", validation_alias="NETWATCH_ENV")

    API_V1_PREFIX: str = "/api/v1"
    CORS_ORIGINS: List[str] = Field(
        default=["http://localhost:3000", "http://localhost:5173"],
        validation_alias="NETWATCH_CORS_ORIGINS"
    )

    DATABASE_URL: str = Field(
        default="sqlite:///D:/NetWatch/netwatch.db",
        validation_alias="NETWATCH_DATABASE_URL"
    )
    DATABASE_POOL_SIZE: int = Field(default=5, validation_alias="NETWATCH_DB_POOL_SIZE")
    DATABASE_MAX_OVERFLOW: int = Field(default=10, validation_alias="NETWATCH_DB_MAX_OVERFLOW")

    AWS_REGION: str = Field(default="us-east-1", validation_alias="NETWATCH_AWS_REGION")
    AWS_ACCESS_KEY_ID: Optional[str] = Field(default=None, validation_alias="NETWATCH_AWS_ACCESS_KEY_ID")
    AWS_SECRET_ACCESS_KEY: Optional[str] = Field(default=None, validation_alias="NETWATCH_AWS_SECRET_ACCESS_KEY")
    VPC_FLOW_LOG_BUCKET: Optional[str] = Field(default=None, validation_alias="NETWATCH_VPC_FLOW_LOG_BUCKET")

    LOG_LEVEL: str = Field(default="INFO", validation_alias="NETWATCH_LOG_LEVEL")

    # Detection thresholds
    DETECTION_PORT_SCAN_THRESHOLD: int = Field(default=20, validation_alias="NETWATCH_PORT_SCAN_THRESHOLD")
    DETECTION_BRUTE_FORCE_THRESHOLD: int = Field(default=10, validation_alias="NETWATCH_BRUTE_FORCE_THRESHOLD")
    DETECTION_DATA_EXFIL_THRESHOLD_BYTES: int = Field(default=10_000_000, validation_alias="NETWATCH_DATA_EXFIL_THRESHOLD")
    DETECTION_TIME_WINDOW_SECONDS: int = Field(default=3600, validation_alias="NETWATCH_DETECTION_TIME_WINDOW")

    # Ingestion limits
    MAX_FILE_SIZE: int = Field(default=500 * 1024 * 1024, validation_alias="NETWATCH_MAX_FILE_SIZE")
    MAX_RECORDS: int = Field(default=50000, validation_alias="NETWATCH_MAX_RECORDS")
    CHUNK_SIZE: int = Field(default=1024 * 1024, validation_alias="NETWATCH_CHUNK_SIZE")

    model_config = ConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore"
    )


@lru_cache
def get_settings() -> Settings:
    """Get cached settings instance."""
    return Settings()


settings = get_settings()