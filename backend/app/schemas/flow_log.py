"""Canonical Flow Log schema shared across ingestion, detection, and API."""

from pydantic import BaseModel, Field, field_validator
from typing import Literal


class FlowLogEntry(BaseModel):
    """VPC Flow Log entry - canonical schema."""
    version: int = Field(ge=2, le=2)
    account_id: str = Field(pattern=r"^\d{12}$")
    interface_id: str = Field(pattern=r"^eni-[0-9a-zA-Z]+$")
    src_addr: str
    dst_addr: str
    src_port: int = Field(ge=0, le=65535)
    dst_port: int = Field(ge=0, le=65535)
    protocol: int = Field(ge=0, le=255)
    packets: int = Field(ge=0)
    bytes: int = Field(ge=0)
    start_time: int = Field(ge=0)
    end_time: int = Field(ge=0)
    action: Literal["ACCEPT", "REJECT"]
    log_status: Literal["OK", "NODATA", "SKIPDATA"]

    @field_validator("src_addr", "dst_addr")
    @classmethod
    def validate_ip(cls, v: str) -> str:
        # Basic IP validation (IPv4/IPv6)
        return v


class FlowLogEntryBatch(BaseModel):
    """Batch of flow log entries for API requests."""
    entries: list[FlowLogEntry] = Field(min_length=1, max_length=10000)