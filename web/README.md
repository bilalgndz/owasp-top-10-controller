# Gelişmiş Zafiyet Avcısı (Vulnerability Scanner) Prototipi

Bu proje, OWASP Top 10 kategorilerinden seçilmiş zafiyetleri tespit etmeyi hedefleyen, prototip seviyesinde bir web uygulaması zafiyet tarayıcısı sunar. Dinamik (aktif) tarama ile basit statik analiz kombinasyonunu kullanarak hedef uygulama üzerinde PoC üretmeye odaklanır.

## Özellikler

- YAML tabanlı hedef ve uç nokta tanımlama.
- SQL Injection, XSS, Broken Authentication ve Açık Veri Sızıntısı kategorileri için kontrol modülleri.
- `httpx` tabanlı asenkron istemci ve hız/tekrar kontrolü.
- Risk skoru üretimi ve Rich tabanlı terminal raporlama.
- PoC HTTP isteği ve yanıt örneklerinin raporlanması.

## Hızlı Başlangıç

### Terminal Kullanımı

```bash
python -m venv .venv
.venv\Scripts\activate  # Windows
pip install -e .
vuln-scanner --config configs/sample_target.yaml
```

### Web Dashboard Kullanımı (Önerilen)

Web arayüzü ile taramaları görsel olarak takip edebilirsiniz:

```bash
python -m venv .venv
.venv\Scripts\activate  # Windows
pip install -e .
python web/run.py
```

Ardından tarayıcınızda `http://localhost:5000` adresini açın.

> Not: Projede `requirements.txt` ve `app.py` dosyaları yoktur. Bağımlılık kurulumu `pip install -e .` ile yapılır.

## Yapı

- `scanner/`: Çekirdek uygulama ve modüller.
- `scanner/checks/`: Zafiyet kontrol sınıfları.
- `scanner/core/`: Konfigürasyon, tarama orkestrasyonu, istemci ve raporlama bileşenleri.
- `configs/`: Örnek hedef tanımları.
- `tests/`: Otomasyon ve regresyon testleri.

## Web Dashboard Özellikleri

- 🎨 Modern ve kullanıcı dostu arayüz
- 📊 Gerçek zamanlı tarama istatistikleri
- 🔍 Bulguları severity seviyesine göre görüntüleme
- 📥 Raporları kaydetme ve yükleme
- 🚀 Tek tıkla tarama başlatma
- 📱 Responsive tasarım

## Test İçin Dummy Hedef

Yerelinizde kolayca test edebileceğiniz zafiyetli bir API hazır:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -e .
python targets/dummy_app/app.py  # 8000 portunda çalışır
```

Ardından aşağıdaki konfigürasyonla tarayabilirsiniz:

```bash
vuln-scanner --config configs/sample_target.yaml
```

Web arayüzünden denemek isterseniz önce dummy uygulamayı başlatın, ardından `python web/run.py` komutuyla dashboard'u açın.

## Yol Haritası

- [x] Web arayüzü ve API entegrasyonu
- [ ] Daha fazla OWASP modülü ekleme (SSRF, CSRF, Deserialization).
- [ ] Otomatik Swagger/GraphQL keşfi.
- [ ] CI/CD pipeline entegrasyonu ve konteyner imajı.

## Uyarı

Bu araç güvenlik testleri için tasarlanmıştır. Yalnızca yetkili olduğunuz sistemlerde kullanın; aksi takdirde yasal sonuçlar doğabilir.

# Flask Blog Uygulaması

Flask + SQLite kullanılarak geliştirilmiş basit bir blog uygulaması.

## Özellikler

- ✅ Kullanıcı kayıt ve giriş sistemi
- ✅ Blog yazıları oluşturma, düzenleme ve silme
- ✅ Etiketleme sistemi
- ✅ Arama fonksiyonu
- ✅ Temiz ve yorumlu kod
- ✅ Responsive HTML şablonları

## Kurulum

1. **Gereksinimleri yükleyin:**
   ```bash
   python -m pip install -r requirements.txt
   ```
   veya
   ```bash
   pip install -r requirements.txt
   ```

2. **Uygulamayı çalıştırın:**
   ```bash
   python app.py
   ```

3. **Tarayıcınızda açın:**
   ```
   http://localhost:5000
   ```

**Not:** Eğer `pip` komutu bulunamıyorsa, `python -m pip` kullanın.

## Kullanım

### Kullanıcı Kaydı ve Giriş
- Ana sayfadan "Kayıt Ol" butonuna tıklayarak yeni bir hesap oluşturabilirsiniz
- "Giriş" butonuna tıklayarak mevcut hesabınızla giriş yapabilirsiniz

### Blog Yazısı Oluşturma
- Giriş yaptıktan sonra "Yazı Oluştur" butonuna tıklayın
- Başlık, içerik ve etiketleri (virgülle ayırarak) girin
- "Oluştur" butonuna tıklayın

### Yazı Düzenleme ve Silme
- Kendi yazılarınızın detay sayfasında "Düzenle" ve "Sil" butonlarını görebilirsiniz
- Sadece kendi yazılarınızı düzenleyebilir veya silebilirsiniz

### Arama
- Ana sayfadaki arama kutusunu kullanarak yazıları başlık veya içeriklerine göre arayabilirsiniz

### Etiketler
- Yazılara etiket ekleyebilirsiniz
- Etiketlere tıklayarak o etikete sahip tüm yazıları görüntüleyebilirsiniz

## Veritabanı

Uygulama ilk çalıştırıldığında otomatik olarak `blog.db` adında bir SQLite veritabanı oluşturulur.

### Tablolar:
- **users**: Kullanıcı bilgileri
- **posts**: Blog yazıları
- **tags**: Etiketler
- **post_tags**: Yazı-etiket ilişkileri

## Güvenlik Notları

⚠️ **Önemli:** Üretim ortamında kullanmadan önce:
- `app.py` dosyasındaki `secret_key` değerini değiştirin
- Daha güvenli bir şifre hashleme yöntemi kullanın
- HTTPS kullanın
- SQL injection saldırılarına karşı ek korumalar ekleyin

## Lisans

Bu proje eğitim amaçlıdır.

