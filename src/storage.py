import sqlite3
import os
from datetime import datetime
from models import LogEvent

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_DIR = os.path.join(BASE_DIR, "data")
DB_NAME = os.path.join(DB_DIR, "logsense.db")

def init_db():
    os.makedirs(DB_DIR, exist_ok=True)
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT, level TEXT, ip_address TEXT, message TEXT, source_file TEXT,
        UNIQUE(timestamp, level, ip_address, message, source_file)
    )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS processed_files (
        file_name TEXT PRIMARY KEY, processed_at TEXT
    )
    """)
    conn.commit()
    conn.close()

def is_file_processed(file_name: str) -> bool:
    init_db()
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT 1 FROM processed_files WHERE file_name = ?", (file_name,))
    result = cursor.fetchone()
    conn.close()
    return result is not None

def save_events(events: list[LogEvent], file_name: str) -> int:
    init_db()
    if is_file_processed(file_name):
        print(f"Uyari: '{file_name}' dosyasi daha önce yuklenmis!")
        return 0
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    eklenen_kayit = 0
    for event in events:
        try:
            cursor.execute("""
            INSERT OR IGNORE INTO logs (timestamp, level, ip_address, message, source_file)
            VALUES (?, ?, ?, ?, ?)
            """, (event.timestamp.isoformat(), event.level, event.ip_address, event.message, event.source_file))
            if cursor.rowcount > 0:
                eklenen_kayit += 1
        except sqlite3.Error:
            continue
    cursor.execute("INSERT INTO processed_files (file_name, processed_at) VALUES (?, ?)", 
                   (file_name, datetime.now().isoformat()))
    conn.commit()
    conn.close()
    print(f"Veritabanina {eklenen_kayit} yeni kayit eklendi.")
    return eklenen_kayit
