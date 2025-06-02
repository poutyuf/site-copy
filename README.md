# 🌐 Site Kopyalama Aracı

Bu proje, web sitelerini yerel olarak kopyalamanıza ve arşivlemenize olanak sağlayan güçlü bir araçtır.

---

## 🚀 Özellikler

- **Tam Site Kopyalama**  
  HTML, CSS, JavaScript, resim ve diğer medya dosyalarını indirir.
- **Alt Alan Adı Desteği**  
  Alt alan adlarını otomatik tespit eder ve kopyalar.
- **Akıllı Bağlantı Yönetimi**  
  Tüm bağlantıları yerel kopyaya uygun şekilde günceller.
- **Proxy Desteği**  
  HTTP, HTTPS, SOCKS4 ve SOCKS5 proxy desteği sunar.
- **Telegram Bot Entegrasyonu**  
  Kolay kullanım için Telegram bot arayüzü sağlar.
- **Google Drive Entegrasyonu**  
  Büyük dosyaları otomatik olarak Google Drive'a yükler.

---

## 📋 Gereksinimler

- Python 3.8+
- aiohttp
- beautifulsoup4
- python-telegram-bot
- google-api-python-client
- Diğer gereksinimler için `requirements.txt` dosyasına bakın.

---

## 🛠️ Kurulum

1. Projeyi klonlayın:
```bash
git clone https://github.com/kullaniciadi/site-copy.git
cd site-copy
```

2. Gerekli paketleri yükleyin:
```bash
pip install -r requirements.txt
```

3. Ortam değişkenlerini ayarlayın:
```bash
export TELEGRAM_BOT_TOKEN="your_bot_token"
export ADMIN_IDS="id1,id2,id3"
```

---

## 💻 Kullanım

### Telegram Bot Üzerinden

1. Botu başlatın:
```bash
python poutyuf.py
```

2. Telegram'da botu bulun ve `/start` komutunu gönderin.  
3. "Site Kopyala" butonuna tıklayın ve URL'yi girin.  
4. Bot siteyi otomatik olarak kopyalayacak ve size bilgi verecektir.

### Programatik Kullanım

```python
from poutyuf import SiteKopyalayici

kopyalayici = SiteKopyalayici()
await kopyalayici.siteyi_kopyala_async("https://example.com", "./output")
```

---

## 🔧 Gelişmiş Özellikler

- **Derinlik Kontrolü**  
  Alt sayfaların ne kadar derinine inileceğini belirleyebilirsiniz.
- **Proxy Yönetimi**  
  Proxy'leri dinamik olarak ekleyip test edebilirsiniz.
- **Dosya Filtreleme**  
  Hangi dosya türlerinin indirileceğini özelleştirebilirsiniz.
- **Hata Yönetimi**  
  Kapsamlı loglama ve hata yakalama mekanizmaları içerir.

---

## 🤝 Katkıda Bulunma

@poutyuf iletişim kur

---

## 🙏 Teşekkürler

