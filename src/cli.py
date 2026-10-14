import argparse
import time
import os
import sys

# Bulunduğu klasörü yola ekle
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from parsers import ingest_file
from storage import save_events
from report import create_html_report

def main():
    parser = argparse.ArgumentParser(description="LogSense CLI Log Analiz Araci")
    subparsers = parser.add_subparsers(dest="command", required=True)

    # logsense ingest <dosya>
    ingest_parser = subparsers.add_parser("ingest", help="Log dosyasini sisteme yukler")
    ingest_parser.add_argument("file_path", type=str, help="Yuklenecek dosyanin yolu")

    # logsense analyze
    subparsers.add_parser("analyze", help="Kurallari ve anomalileri calistirir")

    # logsense report --out rapor.html
    report_parser = subparsers.add_parser("report", help="HTML raporu olusturur")
    report_parser.add_argument("--out", type=str, default="rapor.html", help="Cikti HTML dosya adi")

    args = parser.parse_args()

    # Temel dizin yollarını belirle
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    if args.command == "ingest":
        start_time = time.time()
        
        # Eğer kullanıcı düz 'log.txt' yazdıysa otomatik data/log.txt konumuna bak
        target_path = args.file_path
        if not os.path.exists(target_path) and os.path.exists(os.path.join(base_dir, "data", target_path)):
            target_path = os.path.join(base_dir, "data", target_path)

        events = ingest_file(target_path)
        if events:
            save_events(events, os.path.basename(target_path))
        end_time = time.time()
        print(f"Performans (F8): Islem {end_time - start_time:.4f} saniye surdu.")

    elif args.command == "analyze":
        from rules import check_rules
        violations = check_rules()
        print(f"Analiz tamamlandi. Toplam {len(violations)} kural ihlali tespit edildi.")

    elif args.command == "report":
        create_html_report(args.out)

if __name__ == "__main__":
    main()
