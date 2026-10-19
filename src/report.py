import os
import sqlite3
from datetime import datetime

import matplotlib.pyplot as plt
from jinja2 import Environment

from rules import check_rules, detect_statistical_anomalies

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DB_NAME = os.path.join(BASE_DIR, "data", "logsense.db")
REPORT_DIR = os.path.join(BASE_DIR, "reports")
TOP_IPS_CHART = "top_ips.png"
HOURLY_CHART = "hourly_distribution.png"


def generate_charts(source_file: str | None = None) -> dict[str, bool]:
    """Tüm veritabanı veya seçilen kaynak dosya için grafik üretir."""
    os.makedirs(REPORT_DIR, exist_ok=True)
    chart_paths = {
        "top_ips": os.path.join(REPORT_DIR, TOP_IPS_CHART),
        "hourly": os.path.join(REPORT_DIR, HOURLY_CHART),
    }

    # Önceki çalıştırmadan kalan eski grafikler yeni raporda yanlış görünmesin.
    for chart_path in chart_paths.values():
        if os.path.exists(chart_path):
            os.remove(chart_path)

    if not os.path.exists(DB_NAME):
        return {"top_ips": False, "hourly": False}

    source_name = os.path.basename(source_file) if source_file else None
    with sqlite3.connect(DB_NAME) as conn:
        cursor = conn.cursor()
        if source_name:
            cursor.execute(
                "SELECT ip_address, COUNT(*) AS count FROM logs WHERE source_file = ? "
                "GROUP BY ip_address ORDER BY count DESC LIMIT 10",
                (source_name,),
            )
            ip_data = cursor.fetchall()
            cursor.execute(
                "SELECT strftime('%H:00', timestamp) AS hour, COUNT(*) FROM logs "
                "WHERE source_file = ? GROUP BY hour ORDER BY hour ASC",
                (source_name,),
            )
        else:
            cursor.execute(
                "SELECT ip_address, COUNT(*) AS count FROM logs "
                "GROUP BY ip_address ORDER BY count DESC LIMIT 10"
            )
            ip_data = cursor.fetchall()
            cursor.execute(
                "SELECT strftime('%H:00', timestamp) AS hour, COUNT(*) FROM logs "
                "GROUP BY hour ORDER BY hour ASC"
            )
        hour_data = cursor.fetchall()

    if ip_data:
        labels = [
            "IP belirlenemedi" if ip in (None, "", "0.0.0.0") else ip
            for ip, _ in ip_data
        ]
        plt.figure(figsize=(10, 4))
        plt.bar(labels, [count for _, count in ip_data], color="#4f7cff")
        plt.title("En çok log üreten kaynaklar")
        plt.ylabel("Log sayısı")
        plt.xticks(rotation=35, ha="right")
        plt.tight_layout()
        plt.savefig(chart_paths["top_ips"], dpi=140)
        plt.close()

    if hour_data:
        plt.figure(figsize=(10, 4))
        plt.plot(
            [hour for hour, _ in hour_data],
            [count for _, count in hour_data],
            marker="o",
            color="#f59e0b",
        )
        plt.title("Saatlere göre log dağılımı")
        plt.ylabel("Log sayısı")
        plt.xlabel("Saat")
        plt.grid(True, alpha=0.25)
        plt.tight_layout()
        plt.savefig(chart_paths["hourly"], dpi=140)
        plt.close()

    return {name: os.path.exists(path) for name, path in chart_paths.items()}


def _report_output_path(output_filename: str) -> str:
    if os.path.isabs(output_filename):
        output_path = output_filename
    else:
        output_path = os.path.join(REPORT_DIR, output_filename)
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    return output_path


def _chart_src(chart_name: str, output_path: str) -> str:
    chart_path = os.path.join(REPORT_DIR, chart_name)
    relative_path = os.path.relpath(chart_path, os.path.dirname(os.path.abspath(output_path)))
    return relative_path.replace(os.sep, "/")


def create_html_report(output_filename: str = "rapor.html", source_file: str | None = None):
    """Belirtilirse tek dosyayı, aksi hâlde tüm veritabanını raporlar."""
    source_name = os.path.basename(source_file) if source_file else None
    charts = generate_charts(source_name)
    violations = check_rules(source_name)
    anomalies = detect_statistical_anomalies(source_name)

    total_logs = 0
    if os.path.exists(DB_NAME):
        with sqlite3.connect(DB_NAME) as conn:
            if source_name:
                total_logs = conn.execute(
                    "SELECT COUNT(*) FROM logs WHERE source_file = ?", (source_name,)
                ).fetchone()[0]
            else:
                total_logs = conn.execute("SELECT COUNT(*) FROM logs").fetchone()[0]

    output_path = _report_output_path(output_filename)
    html_template = """<!doctype html>
<html lang="tr">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>LogSense | Analiz Raporu</title>
  <style>
    :root { color-scheme: light; --ink:#172033; --muted:#667085; --line:#e4e8ef;
            --blue:#315eea; --pale:#f4f7fb; --amber:#fff7e6; --amber-ink:#925f00; }
    * { box-sizing:border-box; }
    body { margin:0; background:#f4f6fa; color:var(--ink); font:15px/1.55 Arial,sans-serif; }
    main { max-width:1120px; margin:0 auto; padding:28px 18px 50px; }
    header { padding:26px 28px; border-radius:16px; color:#fff;
             background:linear-gradient(120deg,#193b9b,#315eea); }
    header h1 { margin:0 0 4px; font-size:28px; }
    header p { margin:0; color:#dce5ff; }
    .metrics { display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr));
               gap:14px; margin:18px 0 24px; }
    .metric,.panel,.finding { background:#fff; border:1px solid var(--line); border-radius:13px; }
    .metric { padding:17px 19px; }
    .metric span { display:block; color:var(--muted); font-size:13px; }
    .metric strong { display:block; margin-top:4px; font-size:25px; }
    .panel { padding:22px; margin:18px 0; }
    h2 { margin:0 0 14px; font-size:20px; }
    h3 { margin:12px 0 8px; font-size:17px; }
    .notice { padding:11px 14px; border-radius:9px; background:#eef3ff; color:#34446b; }
    .finding { padding:18px; margin:12px 0; border-left:5px solid #f0ad2e; }
    .finding-top { display:flex; flex-wrap:wrap; justify-content:space-between; gap:8px; color:var(--muted); font-size:13px; }
    .badge { display:inline-block; padding:3px 9px; border-radius:999px;
             background:#fff1cc; color:var(--amber-ink); font-weight:700; }
    .reason { margin:8px 0 12px; }
    .meta { color:var(--muted); font-size:14px; }
    .unknown { color:#9a6700; font-weight:700; }
    details { margin-top:12px; border-top:1px solid var(--line); padding-top:10px; }
    summary { cursor:pointer; color:var(--blue); font-weight:700; }
    pre { white-space:pre-wrap; overflow-wrap:anywhere; margin:10px 0 0; padding:12px;
          border-radius:8px; background:#f6f8fb; color:#344054; font:13px/1.5 Consolas,monospace; }
    .empty { padding:15px; border-radius:9px; background:#f7f9fc; color:var(--muted); }
    .charts { display:grid; grid-template-columns:repeat(auto-fit,minmax(300px,1fr)); gap:16px; }
    .chart-card { min-width:0; padding:12px; border:1px solid var(--line); border-radius:10px; }
    .chart-card img { display:block; width:100%; height:auto; }
    table { width:100%; border-collapse:collapse; }
    th,td { padding:10px; border-bottom:1px solid var(--line); text-align:left; }
    th { color:var(--muted); font-size:13px; }
    footer { margin-top:22px; color:var(--muted); font-size:12px; }
    @media(max-width:540px) { header h1 {font-size:23px;} .panel {padding:16px;} }
  </style>
</head>
<body><main>
  <header>
    <h1>LogSense — Analiz Raporu</h1>
    <p>Kapsam: {{ scope_label }} · Rapor zamanı: {{ generated_at }} · Otomatik kural eşleşmeleri inceleme gerektirir.</p>
  </header>

  <section class="metrics" aria-label="Özet">
    <div class="metric"><span>Toplam log</span><strong>{{ total_logs }}</strong></div>
    <div class="metric"><span>Kural eşleşmesi</span><strong>{{ violations|length }}</strong></div>
    <div class="metric"><span>Saatlik anomali</span><strong>{{ anomalies|length }}</strong></div>
  </section>

  <section class="panel">
    <h2>Güvenlik bulguları</h2>
    <p class="notice">Her bulguda önce neden eşleştiği, ardından ham log kanıtı gösterilir. IP adresi bulunamayan kayıtlar “IP belirlenemedi” olarak işaretlenir; 0.0.0.0 gerçek kaynak IP değildir.</p>
    {% if violations %}
      {% for v in violations %}
      <article class="finding">
        <div class="finding-top">
          <span class="badge">{{ v.rule_id }} · {{ v.rule_name }}</span>
          <span>{{ v.timestamp }}</span>
        </div>
        <h3>{{ v.title or v.rule_name }}</h3>
        <p class="reason"><strong>Neden eşleşti?</strong> {{ v.explanation or v.message }}</p>
        <p class="meta"><strong>Kaynak dosya:</strong> {{ v.source_file or "Belirtilmemiş" }}</p>
        <p class="meta"><strong>Kaynak IP:</strong>
          {% if not v.ip_address or v.ip_address == "0.0.0.0" %}
            <span class="unknown">Belirlenemedi — log satırında IP yok.</span>
          {% else %}{{ v.ip_address }}{% endif %}
        </p>
        <details>
          <summary>Ham log kanıtını göster</summary>
          <pre>{{ v.evidence or v.message }}</pre>
        </details>
      </article>
      {% endfor %}
    {% else %}
      <p class="empty">Mevcut kurallara göre eşleşme bulunmadı.</p>
    {% endif %}
  </section>

  <section class="panel">
    <h2>Saatlik istatistiksel anomaliler</h2>
    {% if anomalies %}
      <table><thead><tr><th>Saat dilimi</th><th>Log sayısı</th><th>Ortalama</th><th>Eşik</th><th>Gerekçe</th></tr></thead><tbody>
      {% for a in anomalies %}
        <tr><td>{{ a.time_slot }}</td><td>{{ a.count }}</td><td>{{ a.mean }}</td><td>{{ a.threshold }}</td><td>{{ a.explanation }}</td></tr>
      {% endfor %}
      </tbody></table>
    {% else %}
      <p class="empty">Anomali eşiğini aşan saat dilimi bulunmadı.</p>
    {% endif %}
  </section>

  <section class="panel">
    <h2>Trafik grafikleri</h2>
    <div class="charts">
      {% if charts.top_ips %}
      <div class="chart-card"><img src="{{ top_ips_src }}" alt="En çok log üreten kaynaklar"></div>
      {% else %}<p class="empty">IP grafiği için veri yok.</p>{% endif %}
      {% if charts.hourly %}
      <div class="chart-card"><img src="{{ hourly_src }}" alt="Saatlere göre log dağılımı"></div>
      {% else %}<p class="empty">Saatlik grafik için veri yok.</p>{% endif %}
    </div>
  </section>
  <footer>Rapor, yapılandırılmış kurallarla otomatik oluşturulmuştur. Tespitleri ham log ve sistem bağlamıyla doğrulayın.</footer>
</main></body></html>"""

    template = Environment(autoescape=True).from_string(html_template)
    scope_label = f"Dosya: {source_name}" if source_name else "Tüm veritabanı"
    rendered = template.render(
        scope_label=scope_label,
        total_logs=total_logs,
        violations=violations,
        anomalies=anomalies,
        charts=charts,
        top_ips_src=_chart_src(TOP_IPS_CHART, output_path),
        hourly_src=_chart_src(HOURLY_CHART, output_path),
        generated_at=datetime.now().astimezone().strftime("%Y-%m-%d %H:%M:%S %Z"),
    )

    with open(output_path, "w", encoding="utf-8") as report_file:
        report_file.write(rendered)

    print(f"Rapor başarıyla '{output_path}' konumuna kaydedildi!")
