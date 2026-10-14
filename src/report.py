import sqlite3
import matplotlib.pyplot as plt
import os
from jinja2 import Template
from rules import check_rules, detect_statistical_anomalies

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_NAME = os.path.join(BASE_DIR, "data", "logsense.db")
REPORT_DIR = os.path.join(BASE_DIR, "reports")

def generate_charts():
    """Raporlama icin gerekli olan 2 adet görsel grafigi uretir."""
    os.makedirs(REPORT_DIR, exist_ok=True)
    if not os.path.exists(DB_NAME):
        return
        
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Grafik 1: En çok baglanti kuran IP'ler
    cursor.execute("SELECT ip_address, COUNT(*) as c FROM logs GROUP BY ip_address ORDER BY c DESC LIMIT 10")
    ip_data = cursor.fetchall()
    if ip_data:
        plt.figure(figsize=(10, 4))
        plt.bar([r[0] for r in ip_data], [r[1] for r in ip_data], color='skyblue')
        plt.title("En Cok Olay Ureten Top 10 IP")
        plt.xticks(rotation=45)
        plt.tight_layout()
        plt.savefig(os.path.join(REPORT_DIR, "top_ips.png"))
        plt.close()

    # Grafik 2: Zaman bazli trafik dagilimi
    cursor.execute("SELECT strftime('%H:00', timestamp) as h, COUNT(*) FROM logs GROUP BY h ORDER BY h ASC")
    hour_data = cursor.fetchall()
    if hour_data:
        plt.figure(figsize=(10, 4))
        plt.plot([r[0] for r in hour_data], [r[1] for r in hour_data], marker='o', color='orange')
        plt.title("Saatlik Log Dagitimi")
        plt.grid(True)
        plt.tight_layout()
        plt.savefig(os.path.join(REPORT_DIR, "hourly_distribution.png"))
        plt.close()
        
    conn.close()

def create_html_report(output_filename: str = "rapor.html"):
    """Tum analiz sonuclarini sik bir HTML sayfaya dökerek rapor olusturur."""
    generate_charts()
    violations = check_rules()
    anomalies = detect_statistical_anomalies()
    
    total_logs = 0
    if os.path.exists(DB_NAME):
        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM logs")
        total_logs = cursor.fetchone()[0]
        conn.close()

    html_template = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>LogSense Raporu</title>
    </head>
    <body style="font-family:Arial; margin:30px; background:#f4f6f9;">
        <h1>LogSense Sistem Analiz Raporu</h1>
        <h2>Toplam Log: {{ total_logs }}</h2>
        <h3>Kural Ihlalleri</h3>
        <ul>
            {% for v in violations %}
            <li>{{ v.timestamp }} - {{ v.ip_address }} : {{ v.message }}</li>
            {% endfor %}
        </ul>
        <h3>Grafikler</h3>
        <img src="top_ips.png" style="max-width:100%;"><br><br>
        <img src="hourly_distribution.png" style="max-width:100%;">
    </body>
    </html>
    """
    t = Template(html_template)
    rendered = t.render(total_logs=total_logs, violations=violations, anomalies=anomalies)
    
    output_path = os.path.join(REPORT_DIR, output_filename)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(rendered)
        
    print(f"Rapor basariyla '{output_path}' konumuna kaydedildi!")
