"""Ortak, normalize edilmiş log olayı veri yapısı."""

from dataclasses import dataclass
from datetime import datetime


@dataclass
class LogEvent:
    """Farklı log biçimlerinden gelen tek bir olayı ortak alanlarda tutar.

    ``event_type`` ve ``source_ip`` normalize edilmiş alanlardır. ``level`` ve
    ``source_file`` mevcut SQLite/analiz koduyla geriye dönük uyumluluk sağlar.
    """

    timestamp: datetime
    event_type: str
    source_ip: str | None = None
    username: str | None = None
    destination_port: int | None = None
    success: bool | None = None
    message: str = ""
    level: str = "INFO"
    source_file: str = ""

    @property
    def ip_address(self) -> str:
        """Eski storage/rules katmanının kullandığı IP alanı."""
        return self.source_ip or "0.0.0.0"
