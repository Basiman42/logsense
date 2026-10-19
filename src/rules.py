import math
import os
import re
import sqlite3
from datetime import datetime, timedelta

import yaml

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_NAME = os.path.join(BASE_DIR, "data", "logsense.db")
YAML_PATH = os.path.join(BASE_DIR, "src", "config", "rules.yaml")

ADMIN_TOKEN_RE = re.compile(r"\b(?:admin|administrator|root|superuser)\b", re.IGNORECASE)
ADMIN_HOME_PATH_RE = re.compile(
    r"/(?:user|home)/(?:root|admin|administrator)(?:/[^\s,;]*)?",
    re.IGNORECASE,
)
PORT_RE = re.compile(
    r"\bport\s*(?:=|:)?\s*(\d{1,5})\b"
    r"|(?:\d{1,3}\.){3}\d{1,3}:(\d{1,5})\b",
    re.IGNORECASE,
)
UNKNOWN_IPS = {"", "0.0.0.0", "unknown", "none"}


def load_rules(yaml_path: str = YAML_PATH) -> dict:
    """YAML ayar dosyasındaki kuralları güvenli biçimde yükler."""
    with open(yaml_path, "r", encoding="utf-8") as rule_file:
        return yaml.safe_load(rule_file) or {}


def _log_message(log: dict) -> str:
    return str(log.get("message") or "")


def _is_failed_log(log: dict) -> bool:
    return str(log.get("level") or "").upper() == "ERROR" or "failed" in _log_message(log).casefold()


def _is_outside_hours(timestamp: datetime, start_hour: int, end_hour: int) -> bool:
    """YAML'daki başlangıç/bitiş saatleri üzerinden mesai dışı pencereyi hesaplar."""
    if start_hour > end_hour:  # Örn. 22:00–06:00, gece yarısını geçer.
        return timestamp.hour >= start_hour or timestamp.hour < end_hour
    return timestamp.hour < start_hour or timestamp.hour >= end_hour


def _has_admin_account_reference(message: str) -> bool:
    """Admin/root sözcüğünü arar; kullanıcı ev dizini yollarını kanıt saymaz."""
    without_home_paths = ADMIN_HOME_PATH_RE.sub(" ", message or "")
    return ADMIN_TOKEN_RE.search(without_home_paths) is not None


def _extract_ports(message: str) -> set[int]:
    ports = set()
    for match in PORT_RE.finditer(message or ""):
        value = match.group(1) or match.group(2)
        if value is not None:
            port = int(value)
            if 0 <= port <= 65535:
                ports.add(port)
    return ports


def check_rules(source_file: str | None = None) -> list[dict]:
    """YAML kurallarını tüm kayıtlar veya seçilen kaynak dosya üzerinde uygular.

    Sonuçlar, HTML raporunda gerekçeyi ham log kanıtından ayrı gösterebilmek
    için ``explanation`` ve ``evidence`` alanlarını da içerir.
    """
    if not os.path.exists(DB_NAME):
        return []

    rules_data = load_rules()
    violations = []

    with sqlite3.connect(DB_NAME) as conn:
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        if source_file:
            cursor.execute(
                "SELECT * FROM logs WHERE source_file = ? ORDER BY timestamp ASC",
                (os.path.basename(source_file),),
            )
        else:
            cursor.execute("SELECT * FROM logs ORDER BY timestamp ASC")
        logs = [dict(row) for row in cursor.fetchall()]

    for rule in rules_data.get("rules", []):
        rule_id = rule.get("id")

        # Kural R1: Aynı IP'den kısa sürede art arda başarısız girişler.
        if rule_id == "R1":
            window = int(rule["time_window_minutes"])
            limit = int(rule["threshold_count"])

            for i, current_log in enumerate(logs):
                if not _is_failed_log(current_log):
                    continue

                ip = str(current_log.get("ip_address") or "0.0.0.0")
                if ip.casefold() in UNKNOWN_IPS:
                    continue
                current_time = datetime.fromisoformat(current_log["timestamp"])

                match_count = 0
                for j in range(i, -1, -1):
                    previous_log = logs[j]
                    previous_ip = str(previous_log.get("ip_address") or "0.0.0.0")
                    if previous_ip == ip and _is_failed_log(previous_log):
                        previous_time = datetime.fromisoformat(previous_log["timestamp"])
                        if current_time - previous_time <= timedelta(minutes=window):
                            match_count += 1
                        else:
                            break

                if match_count >= limit:
                    evidence = _log_message(current_log)
                    violations.append(
                        {
                            "rule_id": rule_id,
                            "rule_name": rule["name"],
                            "title": "Olası brute-force giriş denemesi",
                            "ip_address": ip,
                            "timestamp": current_log["timestamp"],
                            "source_file": current_log.get("source_file") or "",
                            "message": f"{window} dakikada {match_count} başarısız giriş eşleşti.",
                            "explanation": (
                                f"Aynı IP'den {window} dakika içinde {match_count} başarısız "
                                f"giriş kaydı bulundu; eşik {limit}."
                            ),
                            "evidence": evidence,
                        }
                    )

        # Kural R2: Mesai dışı yönetici hesabı etkinliği.
        elif rule_id == "R2":
            start_hour = int(rule["start_hour"])
            end_hour = int(rule["end_hour"])

            for log in logs:
                timestamp = datetime.fromisoformat(log["timestamp"])
                evidence = _log_message(log)
                if not _is_outside_hours(timestamp, start_hour, end_hour):
                    continue
                # /user/root/... gibi HDFS ev dizinleri, root hesabının işlem
                # yaptığına kanıt değildir; bunları kural eşleşmesinden çıkar.
                if not _has_admin_account_reference(evidence):
                    continue

                ip = str(log.get("ip_address") or "0.0.0.0")
                window = f"{start_hour:02d}:00–{end_hour:02d}:00"
                violations.append(
                    {
                        "rule_id": rule_id,
                        "rule_name": rule["name"],
                        "title": "Mesai dışı yönetici hesabı etkinliği",
                        "ip_address": ip,
                        "timestamp": log["timestamp"],
                        "source_file": log.get("source_file") or "",
                        "message": "Mesai dışı saatlerde admin/root hesabına ilişkin anahtar sözcük bulundu.",
                        "explanation": (
                            f"Kayıt saati {timestamp.strftime('%H:%M:%S')}; kuralın mesai dışı "
                            f"aralığı {window}. Mesajda kullanıcı ev dizini yolu dışında "
                            "admin/root hesabı anahtar sözcüğü bulundu. Bu bir kural eşleşmesidir; "
                            "tek başına doğrulanmış yetkisiz erişim kanıtı değildir."
                        ),
                        "evidence": evidence,
                    }
                )

        # Kural R3: Aynı IP'den kısa sürede çok sayıda farklı port.
        elif rule_id == "R3":
            window = int(rule["time_window_minutes"])
            limit = int(rule["threshold_ports"])

            for i, current_log in enumerate(logs):
                current_message = _log_message(current_log)
                if "port" not in current_message.casefold() and "connect" not in current_message.casefold():
                    continue

                ip = str(current_log.get("ip_address") or "0.0.0.0")
                if ip.casefold() in UNKNOWN_IPS:
                    continue
                current_time = datetime.fromisoformat(current_log["timestamp"])

                ports_found = set()
                for j in range(i, -1, -1):
                    previous_log = logs[j]
                    previous_ip = str(previous_log.get("ip_address") or "0.0.0.0")
                    previous_message = _log_message(previous_log)
                    if previous_ip == ip and (
                        "port" in previous_message.casefold()
                        or "connect" in previous_message.casefold()
                    ):
                        previous_time = datetime.fromisoformat(previous_log["timestamp"])
                        if current_time - previous_time <= timedelta(minutes=window):
                            ports_found.update(_extract_ports(previous_message))
                        else:
                            break

                if len(ports_found) >= limit:
                    port_list = ", ".join(str(port) for port in sorted(ports_found))
                    evidence = current_message
                    violations.append(
                        {
                            "rule_id": rule_id,
                            "rule_name": rule["name"],
                            "title": "Olası port taraması",
                            "ip_address": ip,
                            "timestamp": current_log["timestamp"],
                            "source_file": current_log.get("source_file") or "",
                            "message": f"{len(ports_found)} farklı port eşleşti: {port_list}.",
                            "explanation": (
                                f"Aynı IP'den {window} dakika içinde {len(ports_found)} farklı "
                                f"port numarası ({port_list}) gözlendi; eşik {limit}."
                            ),
                            "evidence": evidence,
                        }
                    )

    return violations


def detect_statistical_anomalies(source_file: str | None = None) -> list[dict]:
    """Tüm kayıtları veya seçilen dosyayı saatlik anomali açısından inceler."""
    if not os.path.exists(DB_NAME):
        return []

    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        if source_file:
            cursor.execute(
                "SELECT strftime('%Y-%m-%d %H:00:00', timestamp) AS hour_slot, "
                "COUNT(*) FROM logs WHERE source_file = ? "
                "GROUP BY hour_slot ORDER BY hour_slot ASC",
                (os.path.basename(source_file),),
            )
        else:
            cursor.execute(
                "SELECT strftime('%Y-%m-%d %H:00:00', timestamp) AS hour_slot, "
                "COUNT(*) FROM logs GROUP BY hour_slot ORDER BY hour_slot ASC"
            )
        rows = cursor.fetchall()

    if not rows:
        return []

    counts = [row[1] for row in rows]
    mean = sum(counts) / len(counts)
    variance = sum((count - mean) ** 2 for count in counts) / len(counts)
    std_dev = math.sqrt(variance)
    threshold = mean + (3 * std_dev)

    return [
        {
            "time_slot": hour_slot,
            "count": count,
            "mean": round(mean, 2),
            "threshold": round(threshold, 2),
            "explanation": (
                f"Bu saat diliminde {count} log var; gözlenen eşik "
                f"{round(threshold, 2)} (ortalama {round(mean, 2)} + 3σ)."
            ),
        }
        for hour_slot, count in rows
        if count > threshold
    ]
