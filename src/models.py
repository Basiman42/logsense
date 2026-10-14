"""LogSense olayları için ortak veri yapısını tanımlar."""

from dataclasses import dataclass
from datetime import datetime


@dataclass
class LogEvent:
    """Farklı log biçimlerinden gelen tek bir olayı ortak alanlarda tutar."""

    timestamp: datetime
    event_type: str
    source_ip: str | None = None
    username: str | None = None
    destination_port: int | None = None
    success: bool | None = None
    message: str | None = None