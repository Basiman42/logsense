# LogSense — Lise Stajyeri Python Projesi

LogSense; farklı formatlardaki log dosyalarını (CSV, JSON Lines, Syslog) merkezi bir SQLite veritabanında toplayan, kural tabanlı ve istatistiksel yöntemlerle şüpheli siber güvenlik olaylarını tespit eden modüler bir CLI aracıdır.

## 🚀 Kurulum

Proje saf Python 3.11+ ve izin verilen harici kütüphanelerle geliştirilmiştir. Bağımlılıkları yüklemek için:

```bash
pip install pyyaml matplotlib jinja2 pytest pytest-cov
```

## 💻 Kullanım

Araç 3 temel komut satırı argümanı (argparse) ile çalışır:

1. **Log Verisi Yükleme (Ingest):**
   ```bash
   python main.py ingest örnek_log.csv
   ```
   *Not: Bozuk satırlar atlanır ve `hatalar.log` dosyasına raporlanır.*

2. **Kural Analizi (Analyze):**
   ```bash
   python main.py analyze
   ```

3. **HTML Rapor Üretimi (Report):**
   ```bash
   python main.py report --out rapor.html
   ```

## 📊 Performans Ölçümü (F8)
* **Test Edilen Veri Seti:** 100.000 Satır Karmaşık Log Verisi
* **Ölçülen Süre:** ~3.4 saniye
* **Hedef:** < 10 saniye (Başarılı)
* *Optimizasyon Yöntemi: SQLite toplu ekleme (bulk insert) ve döngü içi regex derleme optimizasyonları yapılmıştır.*

## 🛠 Bilinen Eksikler
* Canlı log akışları (streaming) desteklenmemektedir, sadece statik dosyalar işlenebilir.
* Büyük veritabanı sorgularında indeksleme mimarisi daha da geliştirilebilir.
