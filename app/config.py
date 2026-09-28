"""Application configuration management using Pydantic Settings."""

from typing import Optional
from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """NetworkSentinel system settings loaded from environment or .env file."""

    # TypeSafe Jev Settings
    TYPESAFE_API_KEY: str = Field(default="", description="TypeSafe AI Jev API Key")
    JEV_API_URL: str = Field(
        default="https://api.typesafe.ai/v1/systemone",
        description="Endpoint for Jev System One decisions",
    )
    JEV_MODEL: str = Field(default="jev-latest", description="Model name")

    # Network Capture Settings
    CAPTURE_INTERFACE: Optional[str] = Field(
        default=None,
        description="Network interface name (e.g. eth0, en0). None for auto-detection.",
    )
    BPF_FILTER: str = Field(
        default="ip and not net 127.0.0.0/8 and not udp port 5353 and not udp port 1900 and not port 6379 and not port 8000",
        description="Berkeley Packet Filter string for Scapy",
    )

    # Redis Broker & Cache
    REDIS_URL: str = Field(
        default="redis://localhost:6379/0",
        description="Redis connection URL for queuing and caching",
    )
    REDIS_RAW_QUEUE: str = "net:raw_events"
    REDIS_PUB_SUB_CHANNEL: str = "net:classified"
    REDIS_CACHE_PREFIX: str = "cache:domain:"
    REDIS_ALERT_COOLDOWN_PREFIX: str = "alert:cooldown:"

    # Alerting Thresholds
    ALERT_THRESHOLD_NOUL: float = Field(
        default=0.85,
        ge=0.0,
        le=1.0,
        description="Probability threshold for suspicious activity (Noul answer)",
    )
    ALERT_MIN_SEVERITY: int = Field(
        default=3,
        ge=0,
        le=4,
        description="Minimum score level (0-4) required to trigger an alert",
    )

    # Resend Settings
    RESEND_API_KEY: str = Field(default="", description="Resend API key")
    RESEND_FROM_EMAIL: str = Field(
        default="onboarding@resend.dev",
        description="Sender email registered with Resend (use onboarding@resend.dev for zero-domain testing)",
    )
    ALERT_RECIPIENT: str = Field(
        default="your_notification_email@gmail.com",
        description="Destination email address for critical alerts",
    )

    # Persistence & Operational Options
    DATABASE_PATH: str = Field(
        default="network_sentinel.db",
        description="SQLite database path for event and alert persistence",
    )
    SIMULATION_MODE: bool = Field(
        default=False,
        description="Enable simulated packet feed when raw capture permissions are absent",
    )

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    @property
    def is_jev_configured(self) -> bool:
        """Check if a real TypeSafe Jev API key is configured."""
        return bool(
            self.TYPESAFE_API_KEY
            and self.TYPESAFE_API_KEY.strip()
            and not self.TYPESAFE_API_KEY.startswith("your_typesafe_jev_key")
        )

    @property
    def is_resend_configured(self) -> bool:
        """Check if a real Resend API key is configured."""
        return bool(
            self.RESEND_API_KEY
            and self.RESEND_API_KEY.strip()
            and not self.RESEND_API_KEY.startswith("re_your_resend_api_key")
        )


# Global settings singleton
settings = Settings()
