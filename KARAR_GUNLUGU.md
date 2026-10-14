# 📓 Karar Günlüğü ve Yapay Zeka Beyanı

## 📅 19 Ekim 2026 — 1. Gün
* **Ne Yapıldı:** Proje klasör yapısı kuruldu. Git deposu `git init` ile başlatıldı. Ortak veri yapısı olan `LogEvent` dataclass'ı tanımlandı.
* **Alınan Kararlar:** Veri bütünlüğü ve zaman bazlı kuralların kolay işlenmesi için `timestamp` alanının metin yerine direkt `datetime` nesnesi olarak tutulmasına karar verildi.
* **AI Beyanı:** Proje mimarisinin Python standart kütüphanelerine uygun bölünmesi konusunda mimari danışmanlık alındı.

## 📅 20 Ekim 2026 — 2. Gün
* **Ne Yapıldı:** CSV ve JSON Lines parser modülleri yazıldı. İlk 5 adet birim (unit) test eklendi.
* **Karşılaşılan Sorun ve Çözüm:** `UnicodeDecodeError` hatası alındı. Bazı logların `Windows-1254` ile kodlandığı fark edildi. Kod önce `utf-8` deneyecek, çökerse `windows-1254` ile okumaya devam edecek şekilde `try-except` bloğuna alındı. Programın çökmesi engellendi (F2).

## 📅 21 Ekim 2026 — 3. Gün
* **Ne Yapıldı:** Syslog formatı için Regex kalıbı entegre edildi. SQLite depolama altyapısı yazıldı.
* **Karşılaşılan Sorun ve Çözüm:** Aynı dosya üst üste yüklendiğinde veritabanında mükerrer kayıt oluşuyordu. Bunu engellemek için hem `processed_files` tablosu eklendi hem de `logs` tablosuna `UNIQUE` kısıtlaması getirildi.

## 📅 26 Ekim 2026 — 4. Gün
* **Ne Yapıldı:** `rules.yaml` motoru yazıldı. 3 temel güvenlik kuralı kod değiştirilmeden dinamik çalışacak hale getirildi.
* **AI Beyanı:** AI'a *"YAML kurallarını karmaşık kütüphaneler olmadan nasıl filtrelerim?"* sorusu soruldu. AI ilk başta çok ağır bir kütüphane (pyknow) önerdi, ancak staj sınırları nedeniyle reddedilip saf Python sözlük filtresi yapılmasına karar verildi.

## 📅 27 Ekim 2026 — 5. Gün
* **Ne Yapıldı:** Ortalama + 3 Standart Sapma formülü saf Python (math) ile kodlanarak anomali tespiti (F5) yapıldı. Mentorun sürpriz gereksinimi olan "Şüpheli IP Kara Listeye Alma" altyapısı mevcut mimari bozulmadan veritabanına eklendi.

## 📅 28 Ekim 2026 — 6. Gün
* **Ne Yapıldı:** Argparse ile CLI tamamlandı. Matplotlib ile 2 grafik çizildi ve Jinja2 HTML raporuna gömüldü. Uçtan uca performans testleri tamamlandı (3.4 sn).
