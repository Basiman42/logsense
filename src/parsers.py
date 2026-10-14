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

def parse_csv_line(row: list, source_name: str) -> LogEvent:
    """CSV formatindaki tek bir satiri LogEvent nesnesine donusturur."""
    if isinstance(row, list):
        if len(row) == 1:
            parts = row[0].split(',')
        else:
            parts = row
    else:
        parts = str(row).split(',')
        
    time_str = parts[0].strip() if len(parts) > 0 else "2026-10-14 00:00:00"
    level = parts[1].strip() if len(parts) > 1 else "INFO"
    ip = parts[2].strip() if len(parts) > 2 else "0.0.0.0"
    msg = parts[3].strip() if len(parts) > 3 else "CSV Message"
        
    try:
        dt = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        dt = datetime.now()
        
    return LogEvent(
        timestamp=dt,
        level=level,
        ip_address=ip,
        message=msg,
        source_file=source_name
    )

def parse_json_line(line: str, source_name: str) -> LogEvent:
    """JSON Lines formatindaki tek bir satiri LogEvent nesnesine donusturur."""
    data = json.loads(line)
    time_str = data.get("timestamp", "").strip()
    try:
        dt = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
    except ValueError:
        dt = datetime.now()
        
    return LogEvent(
        timestamp=dt,
        level=data.get("level", "UNKNOWN"),
        ip_address=data.get("ip_address", "0.0.0.0"),
        message=data.get("message", ""),
        source_file=source_name
    )

def parse_syslog_line(line: str, source_name: str) -> LogEvent:
    """Regex kullanarak düz metin syslog satırını LogEvent nesnesine donusturur."""
    pattern = r"<(?P<prio>\d+)?>(?P<timestamp>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z?)\s+(?P<ip>[0-9.]+)\s+\[(?P<level>\w+)\]\s+(?P<message>.*)"
    match = re.match(pattern, line.strip())
    
    if not match:
        raise ValueError("Standart Syslog formati eslesmedi")
        
    data = match.groupdict()
    dt = datetime.strptime(data["timestamp"].replace('Z', ''), "%Y-%m-%dT%H:%M:%S")
    return LogEvent(
        timestamp=dt,
        level=data["level"],
        ip_address=data["ip"],
        message=data["message"],
        source_file=source_name
    )

def parse_alien_or_unknown_line(line: str, source_name: str) -> LogEvent:
    """Bilinmeyen karmasik log formatlarindan veya uzayli loglarindan veri ayiklar."""
    cleaned_line = line.strip()
    
    # 1. IP Adresi Tarama
    ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', cleaned_line)
    ip_address = ip_match.group(0) if ip_match else "0.0.0.0"
    
    # 2. Log Seviyesi Tarama
    level_match = re.search(r'\[?(ALERT|CRITICAL|ERROR|WARN|INFO|DEBUG|FATAL)\]?', cleaned_line, re.IGNORECASE)
    level = level_match.group(1).upper() if level_match else "UNKNOWN"
    
    # 3. Zaman Bilgisi Tarama (Farklı varyasyonlar için)
    date_match = re.search(r'(\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2})', cleaned_line)
    if date_match:
        time_str = date_match.group(1).replace('T', ' ')
        try:
            dt = datetime.strptime(time_str, "%Y-%m-%d %H:%M:%S")
        except:
            dt = datetime.now()
    else:
        dt = datetime.now()
        
    message = cleaned_line
    if ip_match:
        message = message.replace(ip_match.group(0), "")
    if level_match:
        message = message.replace(level_match.group(0), "")
        
    return LogEvent(
        timestamp=dt,
        level=level,
        ip_address=ip_address,
        message=message.strip() or "Bilinmeyen Yabanci Sinyal",
        source_file=source_name
    )

def ingest_file(file_path: str):
    """Ana ingest motoru. Sirasiyla tum formatlari dener, evrensel parser'a duser."""
    os.makedirs(DATA_DIR, exist_ok=True)
    source_name = os.path.basename(file_path)
    okunan_satir = 0
    atlanan_satir = 0
    events = []

    with open(ERR_LOG, "a", encoding="utf-8") as err_file:
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()
        except FileNotFoundError:
            err_file.write(f"Kritik Hata: '{source_name}' dosyasi bulunamadi.\n")
            print(f"Hata: '{source_name}' dosyasi bulunamadi!")
            return []

        for idx, line in enumerate(lines, 1):
            if not line.strip():
                continue
                
            event = None
            # Hata toleranslı sıralı analiz stratejisi (Fallback Chain)
            try:
                if file_path.endswith('.csv'):
                    row = next(csv.reader([line]))
                    event = parse_csv_line(row, source_name)
                elif file_path.endswith('.json') or file_path.endswith('.jsonl'):
                    event = parse_json_line(line, source_name)
                else:
                    # Düz metin veya .txt dosyalarda önce Syslog biçimi denenir
                    try:
                        event = parse_syslog_line(line, source_name)
                    except ValueError:
                        # Syslog formati patlarsa programı çökertme, EVRENSEL parser'a devret!
                        event = parse_alien_or_unknown_line(line, source_name)
            except Exception as e:
                err_file.write(f"Kritik Hata [{source_name} - Satir {idx}]: {str(e)}\n")
                atlanan_satir += 1
                continue
                
            if event:
                events.append(event)
                okunan_satir += 1
                
    print(f"Ozet: {okunan_satir} satir basariyla okundu, {atlanan_satir} satir hatali oldugu icin atlandi.")
    return events
