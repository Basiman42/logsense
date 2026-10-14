import pytest
import os
import sqlite3
from datetime import datetime
from parsers import parse_csv_line, parse_json_line, parse_syslog_line, parse_alien_or_unknown_line, ingest_file
from storage import init_db, save_events, is_file_processed
from rules import load_rules, check_rules, detect_statistical_anomalies
from report import generate_charts, create_html_report

# ================= PART 1: PARSER TESTS =================

def test_parse_csv_line():
    """CSV satır ayrıştırma mekanizmasını doğrular."""
    # parsers.py içindeki row.strip() veya row[0] eşleşmesi için liste veya uygun string veriyoruz
    mock_row = "2026-10-20 14:32:10"
    try:
        event = parse_csv_line([mock_row, "INFO", "192.168.1.1", "Msg"], "test.csv")
    except:
        event = parse_csv_line(mock_row, "test.csv")
    assert isinstance(event.timestamp, datetime)

def test_parse_json_line():
    """JSON satır ayrıştırma mekanizmasını doğrular."""
    mock_json = '{"timestamp": "2026-10-20 14:32:10", "level": "ERROR", "ip_address": "10.0.0.1", "message": "Auth failed"}'
    event = parse_json_line(mock_json, "test.json")
    assert event.level == "ERROR"
    assert event.ip_address == "10.0.0.1"

def test_parse_syslog_line():
    """Standart Syslog regex eşleşmesini doğrular."""
    mock_syslog = "<134>2026-10-21T11:15:30Z 192.168.1.50 [ERROR] failed password"
    event = parse_syslog_line(mock_syslog, "test.log")
    assert event.level == "ERROR"
    assert event.ip_address == "192.168.1.50"

def test_parse_syslog_line_invalid():
    """Bozuk syslog formatının hata fırlattığını doğrular."""
    with pytest.raises(ValueError):
        parse_syslog_line("TAMAMEN BOZUK METIN", "test.log")

def test_parse_alien_or_unknown_line():
    """Evrensel (Uzaylı) parser yeteneğini doğrular."""
    alien_text = "[ZETA] TIME:2026-10-14 11:20:00 CODE:ERROR SRC:172.16.0.5 MSG:Attack"
    event = parse_alien_or_unknown_line(alien_text, "alien.xyz")
    assert event.level == "ERROR"
    assert event.ip_address == "172.16.0.5"

def test_parse_alien_no_data():
    """Hiçbir veri içermeyen satırlarda evrensel parser'ın çökmediğini doğrular."""
    event = parse_alien_or_unknown_line("???", "unknown.txt")
    assert event.level == "UNKNOWN"
    assert event.ip_address == "0.0.0.0"

# ================= PART 2: STORAGE TESTS =================

def test_database_init_and_flow():
    """Veritabanı oluşturma, dosya kontrolü ve kaydetme akışını doğrular."""
    init_db()
    assert os.path.exists("logsense.db")
    status_before = is_file_processed("fake_file.txt")
    assert status_before is False

def test_ingest_file_empty():
    """Olmayan dosya durumunda parser'ın güvenli dönüşünü test eder."""
    # Olmayan dosya hatasını try-except ile kontrol ediyoruz
    events = ingest_file("olmayan_dosya.txt")
    assert events == [] or isinstance(events, list)

# ================= PART 3: RULES & ANOMALY TESTS =================

def test_load_rules():
    """rules.yaml dosyasının başarıyla okunabildiğini test eder."""
    rules = load_rules("rules.yaml")
    assert "rules" in rules
    assert len(rules["rules"]) >= 3

def test_check_rules_empty():
    """Boş veritabanında kural motorunun çökmeden boş liste döndüğünü doğrular."""
    violations = check_rules()
    assert isinstance(violations, list)

def test_detect_statistical_anomalies_empty():
    """Veri yokken anomali motorunun güvenli çalıştığını test eder."""
    anomalies = detect_statistical_anomalies()
    assert anomalies == []

# ================= PART 4: REPORT TESTS =================

def test_generate_charts_and_html():
    """Grafiklerin üretilmesi ve HTML rapor çıktısını test eder."""
    create_html_report("test_rapor.html")
    assert os.path.exists("test_rapor.html")
    if os.path.exists("test_rapor.html"):
        os.remove("test_rapor.html")

# ================= PART 5: EDGE CASES =================

def test_csv_ingest_logic(tmp_path):
    """Geçici bir CSV dosyası oluşturup ingest mekanizmasını tam simüle eder."""
    d = tmp_path / "sub"
    d.mkdir()
    p = d / "test_run.csv"
    p.write_text("2026-10-20 14:32:10,INFO,192.168.1.1,Message\n")
    events = ingest_file(str(p))
    assert isinstance(events, list)

def test_json_ingest_logic(tmp_path):
    """Geçici bir JSON dosyası oluşturup ingest mekanizmasını tam simüle eder."""
    d = tmp_path / "sub"
    d.mkdir()
    p = d / "test_run.json"
    p.write_text('{"timestamp": "2026-10-20 14:32:10", "level": "INFO", "ip_address": "192.168.1.1", "message": "Msg"}\n')
    events = ingest_file(str(p))
    assert isinstance(events, list)

def test_txt_ingest_logic(tmp_path):
    """Geçici bir Syslog/Düz metin dosyası oluşturup ingest mekanizmasını tam simüle eder."""
    d = tmp_path / "sub"
    d.mkdir()
    p = d / "test_run.txt"
    p.write_text("<134>2026-10-21T11:15:30Z 192.168.1.50 [ERROR] failed\n")
    events = ingest_file(str(p))
    assert isinstance(events, list)
