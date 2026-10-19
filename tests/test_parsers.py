import os
import sqlite3
from datetime import datetime

import pytest

import parsers as parsers_module
import report as report_module
import rules as rules_module
import storage as storage_module
from models import LogEvent
from parsers import (
    ingest_file,
    parse_alien_or_unknown_line,
    parse_csv_line,
    parse_json_line,
    parse_syslog_line,
)
from report import create_html_report
from rules import check_rules, detect_statistical_anomalies, load_rules
from storage import init_db, is_file_processed, save_events


@pytest.fixture(autouse=True)
def isolate_project_files(tmp_path, monkeypatch):
    """Testlerin gerçek data/ ve reports/ dosyalarını değiştirmesini önler."""
    data_dir = tmp_path / "data"
    data_dir.mkdir()
    db_path = str(data_dir / "logsense.db")
    report_dir = str(tmp_path / "reports")

    monkeypatch.setattr(parsers_module, "DATA_DIR", str(data_dir))
    monkeypatch.setattr(parsers_module, "ERR_LOG", str(data_dir / "hatalar.log"))
    monkeypatch.setattr(storage_module, "DB_DIR", str(data_dir))
    monkeypatch.setattr(storage_module, "DB_NAME", db_path)
    monkeypatch.setattr(rules_module, "DB_NAME", db_path)
    monkeypatch.setattr(report_module, "DB_NAME", db_path)
    monkeypatch.setattr(report_module, "REPORT_DIR", report_dir)


# ================= PARSER TESTS =================

def test_parse_csv_line():
    event = parse_csv_line(
        ["2026-10-20 14:32:10", "INFO", "192.168.1.1", "Msg"], "test.csv"
    )
    assert event is not None
    assert event.timestamp == datetime(2026, 10, 20, 14, 32, 10)
    assert event.level == "INFO"
    assert event.ip_address == "192.168.1.1"
    assert event.message == "Msg"


def test_parse_json_line():
    mock_json = (
        '{"timestamp": "2026-10-20 14:32:10", "level": "ERROR", '
        '"ip_address": "10.0.0.1", "message": "Auth failed"}'
    )
    event = parse_json_line(mock_json, "test.json")
    assert event.level == "ERROR"
    assert event.ip_address == "10.0.0.1"


def test_parse_syslog_line():
    mock_syslog = "<134>2026-10-21T11:15:30Z 192.168.1.50 [ERROR] failed password"
    event = parse_syslog_line(mock_syslog, "test.log")
    assert event.level == "ERROR"
    assert event.ip_address == "192.168.1.50"


def test_parse_syslog_line_invalid():
    with pytest.raises(ValueError):
        parse_syslog_line("TAMAMEN BOZUK METIN", "test.log")


def test_parse_alien_or_unknown_line():
    alien_text = "[ZETA] TIME:2026-10-14 11:20:00 CODE:ERROR SRC:172.16.0.5 MSG:Attack"
    event = parse_alien_or_unknown_line(alien_text, "alien.xyz")
    assert event.level == "ERROR"
    assert event.ip_address == "172.16.0.5"


def test_parse_alien_no_data():
    event = parse_alien_or_unknown_line("???", "unknown.txt")
    assert event.level == "UNKNOWN"
    assert event.ip_address == "0.0.0.0"


def test_hdfs_headered_csv_ingest(tmp_path):
    """HDFS/LogHub başlığını atlar ve tarih/saat ile alanları eşler."""
    csv_path = tmp_path / "hdfs.csv"
    csv_path.write_text(
        "LineId,Date,Time,Pid,Level,Component,Content,EventId,EventTemplate\n"
        "1,081109,203615,148,INFO,dfs.DataNode$PacketResponder,"
        "Received block blk_123 from /10.251.42.84,E11,"
        "Received block blk_<*> from /<*>\n",
        encoding="utf-8",
    )

    events = ingest_file(str(csv_path))

    assert len(events) == 1
    event = events[0]
    assert event.timestamp == datetime(2008, 11, 9, 20, 36, 15)
    assert event.level == "INFO"
    assert event.event_type == "E11"
    assert event.ip_address == "10.251.42.84"
    assert event.message == "Received block blk_123 from /10.251.42.84"


# ================= STORAGE TESTS =================

def test_database_init_and_flow():
    init_db()
    assert os.path.exists(storage_module.DB_NAME)
    assert is_file_processed("fake_file.txt") is False

    event = LogEvent(
        timestamp=datetime(2026, 10, 20, 14, 32, 10),
        event_type="E10",
        source_ip="192.168.1.1",
        level="INFO",
        message="test event",
        source_file="fake_file.txt",
    )
    assert save_events([event], "fake_file.txt") == 1
    assert is_file_processed("fake_file.txt") is True
    assert save_events([event], "fake_file.txt") == 0


def test_ingest_file_missing():
    events = ingest_file("olmayan_dosya.txt")
    assert events == []


# ================= RULES & ANOMALY TESTS =================

def test_load_rules():
    rules = load_rules()
    assert "rules" in rules
    assert len(rules["rules"]) >= 3


def test_check_rules_without_database():
    violations = check_rules()
    assert violations == []


def test_detect_statistical_anomalies_without_database():
    assert detect_statistical_anomalies() == []


def _insert_log(timestamp, level, ip_address, message):
    init_db()
    with sqlite3.connect(storage_module.DB_NAME) as conn:
        conn.execute(
            "INSERT INTO logs (timestamp, level, ip_address, message, source_file) "
            "VALUES (?, ?, ?, ?, ?)",
            (timestamp, level, ip_address, message, "rules-test.csv"),
        )


def test_off_hours_rule_ignores_root_in_hdfs_home_path():
    _insert_log(
        "2008-11-09T23:41:10",
        "INFO",
        "0.0.0.0",
        "BLOCK* NameSystem.allocateBlock: /user/root/sortrand/_temporary/task/part-1",
    )
    violations = check_rules()
    assert not any(v["rule_id"] == "R2" for v in violations)


def test_off_hours_rule_reports_explicit_root_login_with_reason():
    _insert_log(
        "2008-11-09T23:41:10",
        "INFO",
        "10.0.0.5",
        "root login succeeded",
    )
    violations = check_rules()
    r2 = [violation for violation in violations if violation["rule_id"] == "R2"]
    assert len(r2) == 1
    assert "23:41:10" in r2[0]["explanation"]
    assert "22:00–06:00" in r2[0]["explanation"]
    assert r2[0]["evidence"] == "root login succeeded"


def test_port_scan_rule_counts_distinct_port_numbers():
    for index, port in enumerate((22, 23, 25, 80, 443)):
        _insert_log(
            f"2026-10-14T12:0{index}:00",
            "INFO",
            "10.0.0.8",
            f"connection attempt to port {port}",
        )
    violations = check_rules()
    r3 = [violation for violation in violations if violation["rule_id"] == "R3"]
    assert len(r3) == 1
    assert "22, 23, 25, 80, 443" in r3[0]["explanation"]


# ================= REPORT TESTS =================

def test_generate_charts_and_html():
    create_html_report("test_rapor.html")
    report_path = os.path.join(report_module.REPORT_DIR, "test_rapor.html")
    assert os.path.exists(report_path)


def test_html_report_explains_finding_and_labels_missing_ip():
    _insert_log(
        "2008-11-09T23:41:10",
        "INFO",
        "0.0.0.0",
        "root login succeeded",
    )
    create_html_report("clear_report.html")
    report_path = os.path.join(report_module.REPORT_DIR, "clear_report.html")
    html = open(report_path, encoding="utf-8").read()

    assert "Neden eşleşti?" in html
    assert "Ham log kanıtını göster" in html
    assert "Belirlenemedi" in html
    assert "root login succeeded" in html


# ================= INGEST EDGE CASES =================

def test_csv_ingest_logic(tmp_path):
    csv_path = tmp_path / "test_run.csv"
    csv_path.write_text(
        "2026-10-20 14:32:10,INFO,192.168.1.1,Message\n", encoding="utf-8"
    )
    events = ingest_file(str(csv_path))
    assert len(events) == 1
    assert events[0].message == "Message"


def test_json_ingest_logic(tmp_path):
    json_path = tmp_path / "test_run.json"
    json_path.write_text(
        '{"timestamp": "2026-10-20 14:32:10", "level": "INFO", '
        '"ip_address": "192.168.1.1", "message": "Msg"}\n',
        encoding="utf-8",
    )
    events = ingest_file(str(json_path))
    assert len(events) == 1
    assert events[0].ip_address == "192.168.1.1"


def test_txt_ingest_logic(tmp_path):
    log_path = tmp_path / "test_run.txt"
    log_path.write_text(
        "<134>2026-10-21T11:15:30Z 192.168.1.50 [ERROR] failed\n",
        encoding="utf-8",
    )
    events = ingest_file(str(log_path))
    assert len(events) == 1
    assert events[0].level == "ERROR"
