import csv
import json
import os
import re
from datetime import datetime

from models import LogEvent

# Dinamik dosya yolları ayarları
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
ERR_LOG = os.path.join(DATA_DIR, "hatalar.log")

# LogHub/HDFS CSV biçimi: tarih ve saat ayrı sütunlardadır.
HDFS_CSV_COLUMNS = (
    "lineid",
    "date",
    "time",
    "pid",
    "level",
    "component",
    "content",
    "eventid",
    "eventtemplate",
)
LOG_LEVELS = {"TRACE", "DEBUG", "INFO", "WARN", "WARNING", "ERROR", "FATAL", "CRITICAL"}
IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _normalize_column_name(value: str) -> str:
    return str(value).strip().lstrip("\ufeff").casefold()


def _is_hdfs_header(row: list[str]) -> bool:
    """HDFS/LogHub CSV başlığını sütun sırası değişse de tanır."""
    names = tuple(_normalize_column_name(value) for value in row)
    return len(names) == len(HDFS_CSV_COLUMNS) and set(names) == set(HDFS_CSV_COLUMNS)


def _looks_like_hdfs_record(row: list[str]) -> bool:
    """Başlık bulunmayan ancak HDFS CSV sütunlarına benzeyen satırı tanır."""
    return (
        len(row) >= len(HDFS_CSV_COLUMNS)
        and re.fullmatch(r"\d{6}", row[1].strip()) is not None
        and re.fullmatch(r"\d{6}", row[2].strip()) is not None
        and row[4].strip().upper() in LOG_LEVELS
    )


def _parse_hdfs_csv_line(
    row: list[str], source_name: str, header: list[str] | tuple[str, ...]
) -> LogEvent:
    normalized_header = [_normalize_column_name(column) for column in header]
    if len(row) < len(normalized_header):
        raise ValueError(
            f"HDFS CSV satırında {len(normalized_header)} sütun bekleniyordu, {len(row)} bulundu"
        )

    data = {
        name: str(value).strip()
        for name, value in zip(normalized_header, row)
    }
    try:
        timestamp = datetime.strptime(
            f"{data['date']} {data['time']}", "%y%m%d %H%M%S"
        )
    except (KeyError, ValueError) as exc:
        raise ValueError("HDFS CSV Date/Time alanı YYMMDD ve HHMMSS biçiminde olmalı") from exc

    level = data.get("level", "UNKNOWN").upper() or "UNKNOWN"
    content = data.get("content", "")
    component = data.get("component", "")
    event_type = data.get("eventid") or component or level
    ip_match = IPV4_RE.search(content)

    return LogEvent(
        timestamp=timestamp,
        event_type=event_type,
        source_ip=ip_match.group(0) if ip_match else None,
        level=level,
        message=content,
        source_file=source_name,
    )


def parse_csv_line(
    row: list | str,
    source_name: str,
    header: list[str] | tuple[str, ...] | None = None,
) -> LogEvent | None:
    """CSV satırını LogEvent'e çevirir.

    Desteklenen biçimler:
    * Eski dört sütunlu biçim: timestamp, level, ip, message.
    * Başlıklı HDFS/LogHub biçimi: LineId, Date, Time, Pid, Level,
      Component, Content, EventId, EventTemplate.
    """
    if isinstance(row, str):
        parts = next(csv.reader([row]))
    else:
        parts = [str(value) for value in row]

    if not parts or not any(part.strip() for part in parts):
        raise ValueError("CSV satırı boş")

    # Başlık satırı olay değildir; ingest_file bunu hata saymadan atlayabilir.
    if _is_hdfs_header(parts):
        return None

    active_header = header
    if active_header and _is_hdfs_header(list(active_header)):
        return _parse_hdfs_csv_line(parts, source_name, active_header)

    # Bazı HDFS dışa aktarımlarında başlık olmayabilir; karakteristik Date/Time
    # ve Level sütunlarından bu biçimi yine de tanıyabiliriz.
    if _looks_like_hdfs_record(parts):
        return _parse_hdfs_csv_line(parts, source_name, HDFS_CSV_COLUMNS)

    # Tek hücreli satırda CSV metni geldiyse, virgülleri CSV kurallarına göre aç.
    if len(parts) == 1 and "," in parts[0]:
        parts = next(csv.reader([parts[0]]))

    time_str = parts[0].strip() if len(parts) > 0 else "2026-10-14 00:00:00"
    level = parts[1].strip() if len(parts) > 1 else "INFO"
    ip = parts[2].strip() if len(parts) > 2 else "0.0.0.0"
    message = parts[3].strip() if len(parts) > 3 else "CSV Message"

    try:
        timestamp = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        # Eski dört sütunlu CSV davranışını koru; yeni HDFS biçiminde tarih
        # yukarıdaki özel parser'da katı biçimde doğrulanır.
        timestamp = datetime.now()

    return LogEvent(
        timestamp=timestamp,
        event_type=level or "UNKNOWN",
        source_ip=ip or None,
        level=level or "UNKNOWN",
        message=message,
        source_file=source_name,
    )


def parse_json_line(line: str, source_name: str) -> LogEvent:
    """JSON Lines formatındaki tek bir satırı LogEvent nesnesine dönüştürür."""
    data = json.loads(line)
    time_str = str(data.get("timestamp") or "").strip()
    try:
        dt = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        try:
            dt = datetime.fromisoformat(time_str.replace("Z", "+00:00"))
        except ValueError:
            dt = datetime.now()

    level = str(data.get("level") or "UNKNOWN").upper()
    ip = str(data.get("ip_address") or "0.0.0.0")
    message = str(data.get("message") or "")
    return LogEvent(
        timestamp=dt,
        event_type=str(data.get("event_type") or level),
        source_ip=ip,
        level=level,
        message=message,
        source_file=source_name,
    )


def parse_syslog_line(line: str, source_name: str) -> LogEvent:
    """Regex kullanarak düz metin syslog satırını LogEvent'e dönüştürür."""
    pattern = (
        r"<(?P<prio>\d+)?>(?P<timestamp>\d{4}-\d{2}-\d{2}T"
        r"\d{2}:\d{2}:\d{2}Z?)\s+(?P<ip>[0-9.]+)\s+"
        r"\[(?P<level>\w+)\]\s+(?P<message>.*)"
    )
    match = re.match(pattern, line.strip())

    if not match:
        raise ValueError("Standart Syslog formatı eşleşmedi")

    data = match.groupdict()
    timestamp = datetime.strptime(
        data["timestamp"].replace("Z", ""), "%Y-%m-%dT%H:%M:%S"
    )
    level = data["level"].upper()
    return LogEvent(
        timestamp=timestamp,
        event_type=level,
        source_ip=data["ip"],
        level=level,
        message=data["message"],
        source_file=source_name,
    )


def parse_alien_or_unknown_line(line: str, source_name: str) -> LogEvent:
    """Bilinmeyen log biçimlerinden olası IP, seviye ve zamanı ayıklar."""
    cleaned_line = line.strip()

    ip_match = IPV4_RE.search(cleaned_line)
    ip_address = ip_match.group(0) if ip_match else None

    level_match = re.search(
        r"\b(ALERT|CRITICAL|ERROR|WARN|WARNING|INFO|DEBUG|FATAL)\b",
        cleaned_line,
        re.IGNORECASE,
    )
    level = level_match.group(1).upper() if level_match else "UNKNOWN"

    date_match = re.search(
        r"(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2})", cleaned_line
    )
    if date_match:
        time_str = date_match.group(1).replace("T", " ")
        try:
            timestamp = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            timestamp = datetime.now()
    else:
        timestamp = datetime.now()

    message = cleaned_line
    if ip_match:
        message = message.replace(ip_match.group(0), "")
    if level_match:
        message = message.replace(level_match.group(0), "")

    return LogEvent(
        timestamp=timestamp,
        event_type=level,
        source_ip=ip_address,
        level=level,
        message=message.strip() or "Bilinmeyen Yabancı Sinyal",
        source_file=source_name,
    )


def ingest_file(file_path: str):
    """Log dosyasını satır satır ayrıştırır; hatalı satırları hata günlüğüne yazar."""
    os.makedirs(DATA_DIR, exist_ok=True)
    source_name = os.path.basename(file_path)
    extension = os.path.splitext(file_path)[1].lower()
    okunan_satir = 0
    atlanan_satir = 0
    events = []
    csv_header = None

    with open(ERR_LOG, "a", encoding="utf-8") as err_file:
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as source_file:
                lines = source_file.readlines()
        except FileNotFoundError:
            err_file.write(f"Kritik Hata: '{source_name}' dosyası bulunamadı.\n")
            print(f"Hata: '{source_name}' dosyası bulunamadı!")
            return []

        for idx, line in enumerate(lines, 1):
            if not line.strip():
                continue

            event = None
            try:
                if extension == ".csv":
                    row = next(csv.reader([line]))
                    if _is_hdfs_header(row):
                        csv_header = row
                        continue
                    event = parse_csv_line(row, source_name, header=csv_header)
                elif extension in {".json", ".jsonl"}:
                    event = parse_json_line(line, source_name)
                else:
                    # Düz metin/.txt dosyalarında önce Syslog, sonra esnek parser.
                    try:
                        event = parse_syslog_line(line, source_name)
                    except ValueError:
                        event = parse_alien_or_unknown_line(line, source_name)
            except Exception as exc:
                err_file.write(
                    f"Kritik Hata [{source_name} - Satır {idx}]: {exc}\n"
                )
                atlanan_satir += 1
                continue

            if event is not None:
                events.append(event)
                okunan_satir += 1

    print(
        f"Özet: {okunan_satir} satır başarıyla okundu, "
        f"{atlanan_satir} satır hatalı olduğu için atlandı."
    )
    return events