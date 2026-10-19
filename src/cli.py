import argparse
import os
import sqlite3
import sys
import time
from collections import Counter

# Bulunduğu klasörü Python'ın arama yoluna ekle
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from parsers import ingest_file
from report import create_html_report
from storage import DB_NAME, save_events


def _database_scope(source_file: str | None = None) -> tuple[int, int]:
    """Analiz kapsamındaki kayıt ve kaynak dosya sayılarını döndürür."""
    if not os.path.exists(DB_NAME):
        return 0, 0

    with sqlite3.connect(DB_NAME) as conn:
        if source_file:
            count = conn.execute(
                "SELECT COUNT(*) FROM logs WHERE source_file = ?",
                (os.path.basename(source_file),),
            ).fetchone()[0]
            return count, 1 if count else 0

        count, file_count = conn.execute(
            "SELECT COUNT(*), COUNT(DISTINCT source_file) FROM logs"
        ).fetchone()
        return count, file_count


def _run_analysis(source_file: str | None = None) -> None:
    from rules import check_rules, load_rules

    source_name = os.path.basename(source_file) if source_file else None
    record_count, source_count = _database_scope(source_name)
    violations = check_rules(source_name)
    counts = Counter(item.get("rule_id", "?") for item in violations)
    rule_names = {
        rule.get("id"): rule.get("name", rule.get("id", "Kural"))
        for rule in load_rules().get("rules", [])
    }

    if source_name:
        print(f"Analiz kapsamı: '{source_name}' dosyası ({record_count} kayıt).")
    else:
        print(
            f"Analiz kapsamı: tüm veritabanı ({record_count} kayıt, "
            f"{source_count} kaynak dosya)."
        )

    for rule_id in ("R1", "R2", "R3"):
        print(f"{rule_id} — {rule_names.get(rule_id, 'Kural')}: {counts[rule_id]} eşleşme")

    if violations and not source_name:
        by_source = Counter(
            item.get("source_file") or "Kaynak dosya bilinmiyor"
            for item in violations
        )
        print("Bulgu kaynakları:")
        for name, count in by_source.most_common():
            print(f"  - {name}: {count}")
    elif source_name and record_count == 0:
        print(f"Uyarı: Veritabanında '{source_name}' adına ait kayıt bulunamadı.")
    elif not violations:
        print("Bu kapsamda kural eşleşmesi bulunmadı.")

    print(
        f"Analiz tamamlandı. Toplam {len(violations)} kural eşleşmesi bulundu. "
        "Eşleşmeler otomatik göstergelerdir; tek başına doğrulanmış saldırı kanıtı değildir."
    )


def main():
    parser = argparse.ArgumentParser(description="LogSense CLI log analiz aracı")
    subparsers = parser.add_subparsers(dest="command", required=True)

    ingest_parser = subparsers.add_parser("ingest", help="Log dosyasını sisteme yükler")
    ingest_parser.add_argument("file_path", type=str, help="Yüklenecek dosyanın yolu")

    analyze_parser = subparsers.add_parser("analyze", help="Kuralları çalıştırır")
    analyze_parser.add_argument(
        "--file",
        dest="source_file",
        help="Yalnızca daha önce içe aktarılmış bu dosyayı analiz et",
    )

    report_parser = subparsers.add_parser("report", help="HTML raporu oluşturur")
    report_parser.add_argument(
        "--out", type=str, default="rapor.html", help="HTML çıktı dosyası"
    )
    report_parser.add_argument(
        "--file",
        dest="source_file",
        help="Raporu yalnızca bu kaynak dosyaya göre oluştur",
    )

    args = parser.parse_args()
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

    if args.command == "ingest":
        start_time = time.time()
        target_path = args.file_path
        if not os.path.exists(target_path):
            data_path = os.path.join(base_dir, "data", target_path)
            if os.path.exists(data_path):
                target_path = data_path

        events = ingest_file(target_path)
        if events:
            save_events(events, os.path.basename(target_path))
        print(f"Performans (F8): İşlem {time.time() - start_time:.4f} saniye sürdü.")

    elif args.command == "analyze":
        _run_analysis(args.source_file)

    elif args.command == "report":
        create_html_report(args.out, source_file=args.source_file)


if __name__ == "__main__":
    main()
