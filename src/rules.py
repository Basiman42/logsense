import sqlite3
import yaml
import math
import os
from datetime import datetime, timedelta

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_NAME = os.path.join(BASE_DIR, "data", "logsense.db")
YAML_PATH = os.path.join(BASE_DIR, "src", "config", "rules.yaml")

def load_rules(yaml_path: str = YAML_PATH) -> dict:
    """YAML ayar dosyasindaki kurallari guvenli sekilde yukler."""
    with open(yaml_path, 'r', encoding='utf-8') as f:
        return yaml.safe_load(f)

def check_rules() -> list[dict]:
    """YAML'dan okunan dinamik kurallari veritabani uzerinde isletir."""
    if not os.path.exists(DB_NAME):
        return []
        
    rules_data = load_rules()
    violations = []
    
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM logs ORDER BY timestamp ASC")
    logs = [dict(row) for row in cursor.fetchall()]
    conn.close()

    for rule in rules_data.get('rules', []):
        rule_id = rule['id']
        
        # --- KURAL 1: Brute Force ---
        if rule_id == "R1":
            window = rule['time_window_minutes']
            limit = rule['threshold_count']
            
            for i, current_log in enumerate(logs):
                if current_log['level'] == 'ERROR' or 'failed' in current_log['message'].lower():
                    ip = current_log['ip_address']
                    current_time = datetime.fromisoformat(current_log['timestamp'])
                    
                    match_count = 0
                    for j in range(i, -1, -1):
                        prev_log = logs[j]
                        if prev_log['ip_address'] == ip and (prev_log['level'] == 'ERROR' or 'failed' in prev_log['message'].lower()):
                            prev_time = datetime.fromisoformat(prev_log['timestamp'])
                            if current_time - prev_time <= timedelta(minutes=window):
                                match_count += 1
                            else:
                                break
                                
                    if match_count >= limit:
                        violations.append({
                            "rule_id": rule_id,
                            "rule_name": rule['name'],
                            "ip_address": ip,
                            "timestamp": current_log['timestamp'],
                            "message": f"IP {ip} tarafindan {window} dakikada {match_count} hatali giris yapildi."
                        })
                        
        # --- KURAL 2: Mesai Disi Islemler ---
        elif rule_id == "R2":
            for log in logs:
                dt = datetime.fromisoformat(log['timestamp'])
                if dt.hour >= rule['start_hour'] or dt.hour < rule['end_hour']:
                    if 'admin' in log['message'].lower() or 'root' in log['message'].lower():
                        violations.append({
                            "rule_id": rule_id,
                            "rule_name": rule['name'],
                            "ip_address": log['ip_address'],
                            "timestamp": log['timestamp'],
                            "message": f"Mesai disi saatte yonetici islemi: {log['message']}"
                        })
                        
        # --- KURAL 3: Port Tarama ---
        elif rule_id == "R3":
            window = rule['time_window_minutes']
            limit = rule['threshold_ports']
            
            for i, current_log in enumerate(logs):
                if 'port' in current_log['message'].lower():
                    ip = current_log['ip_address']
                    current_time = datetime.fromisoformat(current_log['timestamp'])
                    
                    ports_found = set()
                    for j in range(i, -1, -1):
                        prev_log = logs[j]
                        if prev_log['ip_address'] == ip and 'port' in prev_log['message'].lower():
                            prev_time = datetime.fromisoformat(prev_log['timestamp'])
                            if current_time - prev_time <= timedelta(minutes=window):
                                ports_found.add(prev_log['message'])
                            else:
                                break
                                
                    if len(ports_found) >= limit:
                        violations.append({
                            "rule_id": rule_id,
                            "rule_name": rule['name'],
                            "ip_address": ip,
                            "timestamp": current_log['timestamp'],
                            "message": f"IP {ip} kisa surede {len(ports_found)} port denedi."
                        })
                        
    return violations

def detect_statistical_anomalies() -> list[dict]:
    """Ortalama + 3 Standart Sapma yontemiyle anomali tespiti yapar."""
    if not os.path.exists(DB_NAME):
        return []
        
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT strftime('%Y-%m-%d %H:00:00', timestamp) as hour_slot, COUNT(*) FROM logs GROUP BY hour_slot ORDER BY hour_slot ASC")
    rows = cursor.fetchall()
    conn.close()
    
    if not rows:
        return []
        
    counts = [r[1] for r in rows]
    mean = sum(counts) / len(counts)
    variance = sum((x - mean) ** 2 for x in counts) / len(counts)
    std_dev = math.sqrt(variance)
    threshold = mean + (3 * std_dev)
    
    anomalies = []
    for hour_slot, count in rows:
        if count > threshold:
            anomalies.append({
                "time_slot": hour_slot,
                "count": count,
                "mean": round(mean, 2),
                "threshold": round(threshold, 2)
            })
            
    return anomalies
