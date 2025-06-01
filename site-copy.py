import os
import re
import sys
import subprocess
import json
import random
import aiohttp
from typing import List, Dict, Optional

class ProxyManager:
    """Proxy yönetimi için sınıf"""
    def __init__(self, proxy_file: str = "proxies.json"):
        self.proxy_file = proxy_file
        self.proxies: List[Dict[str, str]] = []
        self.load_proxies()
    
    def load_proxies(self) -> None:
        """Proxy listesini dosyadan yükler"""
        try:
            if os.path.exists(self.proxy_file):
                with open(self.proxy_file, 'r', encoding='utf-8') as f:
                    self.proxies = json.load(f)
                logger.info(f"{Renkler.YESIL}✅ {len(self.proxies)} proxy yüklendi{Renkler.ENDC}")
        except Exception as e:
            logger.error(f"{Renkler.HATA}❌ Proxy dosyası yüklenemedi: {e}{Renkler.ENDC}")
            self.proxies = []
    
    def save_proxies(self) -> None:
        """Proxy listesini dosyaya kaydeder"""
        try:
            with open(self.proxy_file, 'w', encoding='utf-8') as f:
                json.dump(self.proxies, f, indent=2, ensure_ascii=False)
            logger.info(f"{Renkler.YESIL}✅ {len(self.proxies)} proxy kaydedildi{Renkler.ENDC}")
        except Exception as e:
            logger.error(f"{Renkler.HATA}❌ Proxy dosyası kaydedilemedi: {e}{Renkler.ENDC}")
    
    async def test_proxy(self, session: aiohttp.ClientSession, proxy: Dict[str, str], timeout: int = 10) -> bool:
        """Proxy'nin çalışıp çalışmadığını test eder"""
        test_urls = [
            "http://www.google.com",
            "https://www.example.com",
            "http://www.httpbin.org/ip"
        ]
        
        try:
            for url in test_urls:
                try:
                    async with session.get(url, proxy=proxy['url'], timeout=timeout) as response:
                        if response.status == 200:
                            return True
                except:
                    continue
            return False
        except Exception as e:
            logger.error(f"{Renkler.HATA}❌ Proxy test hatası ({proxy['url']}): {e}{Renkler.ENDC}")
            return False
    
    def format_proxy(self, proxy: str) -> Optional[Dict[str, str]]:
        """Proxy formatını düzenler, doğrular ve türünü belirler"""
        try:
            proxy = proxy.strip()
            
            # URL formatındaysa parse et
            if proxy.startswith(('http://', 'https://', 'socks4://', 'socks5://')):
                parsed = urlparse(proxy)
                proxy_type = parsed.scheme
                host = parsed.hostname
                port = parsed.port
                if not port and ':' in parsed.netloc:
                    host, port = parsed.netloc.split(':')
            else:
                # IP:PORT formatını işle
                if '@' in proxy:  # Kullanıcı adı:şifre@host:port formatı
                    auth, address = proxy.rsplit('@', 1)
                    if ':' in auth:
                        username, password = auth.split(':', 1)
                    else:
                        username, password = auth, ''
                    host, port = address.rsplit(':', 1)
                else:
                    if proxy.count(':') == 1:
                        host, port = proxy.split(':')
                    else:
                        # IPv6 adresi olabilir
                        if '[' in proxy and ']' in proxy:
                            host = proxy[proxy.find('[')+1:proxy.find(']')]
                            port = proxy[proxy.find(']')+2:]  # +2 for ']:' pattern
                        else:
                            return None
                
                proxy_type = 'http'  # Varsayılan olarak HTTP
            
            # Port'u sayıya çevir
            try:
                port = int(port)
                if not (0 < port < 65536):
                    return None
            except (ValueError, TypeError):
                return None
            
            # Host adresini doğrula
            if not host:
                return None
            
            # IPv4/IPv6 veya domain kontrolü
            try:
                # IPv6 kontrolü
                if ':' in host and not host.startswith('['):
                    host = f'[{host}]'
                # Domain kontrolü
                elif not re.match(r'^[a-zA-Z0-9\-\.]+$', host):
                    return None
            except Exception:
                return None
            
            formatted_proxy = {
                'type': proxy_type,
                'host': host,
                'port': port,
                'url': f"{proxy_type}://{host}:{port}"
            }
            
            # Eğer kullanıcı adı/şifre varsa ekle
            if '@' in proxy and 'username' in locals():
                formatted_proxy.update({
                    'username': username,
                    'password': password,
                    'url': f"{proxy_type}://{username}:{password}@{host}:{port}"
                })
            
            return formatted_proxy
            
        except Exception as e:
            logger.error(f"{Renkler.HATA}❌ Proxy format hatası: {e}{Renkler.ENDC}")
            return None
    
    async def load_proxies_from_api(self, api_url: str) -> bool:
        """API'den proxy listesi yükler"""
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(api_url) as response:
                    if response.status != 200:
                        logger.error(f"{Renkler.HATA}❌ API yanıt vermedi: {response.status}{Renkler.ENDC}")
                        return False
                    
                    content_type = response.headers.get('Content-Type', '')
                    if 'application/json' in content_type:
                        data = await response.json()
                        if isinstance(data, list):
                            proxies = data
                        elif isinstance(data, dict):
                            # API yanıt formatına göre uyarla
                            proxies = data.get('proxies', []) or data.get('data', []) or []
                        else:
                            logger.error(f"{Renkler.HATA}❌ Geçersiz API yanıt formatı{Renkler.ENDC}")
                            return False
                    else:
                        # Düz metin formatı (her satırda bir proxy)
                        text = await response.text()
                        proxies = [line.strip() for line in text.splitlines() if line.strip()]
                    
                    success_count = 0
                    for proxy in proxies:
                        if isinstance(proxy, dict):
                            # API'den gelen proxy dict formatındaysa
                            proxy_str = proxy.get('url') or f"{proxy.get('type', 'http')}://{proxy.get('host')}:{proxy.get('port')}"
                        else:
                            # String formatındaysa
                            proxy_str = str(proxy)
                        
                        if self.add_proxy(proxy_str):
                            success_count += 1
                    
                    logger.info(
                        f"{Renkler.YESIL}✅ API'den {success_count}/{len(proxies)} proxy yüklendi"
                        f"{Renkler.ENDC}"
                    )
                    return True
                    
        except Exception as e:
            logger.error(f"{Renkler.HATA}❌ API'den proxy yükleme hatası: {e}{Renkler.ENDC}")
            return False
    
    def add_proxy(self, proxy: str) -> bool:
        """Yeni proxy ekler"""
        formatted_proxy = self.format_proxy(proxy)
        if not formatted_proxy:
            logger.error(f"{Renkler.HATA}❌ Geçersiz proxy formatı: {proxy}{Renkler.ENDC}")
            return False
        
        # Aynı proxy'nin olup olmadığını kontrol et
        if any(p['url'] == formatted_proxy['url'] for p in self.proxies):
            logger.warning(f"{Renkler.UYARI}⚠️ Bu proxy zaten ekli: {formatted_proxy['url']}{Renkler.ENDC}")
            return False
        
        self.proxies.append(formatted_proxy)
        self.save_proxies()
        logger.info(f"{Renkler.YESIL}✅ Yeni proxy eklendi: {formatted_proxy['url']}{Renkler.ENDC}")
        return True
    
    def remove_proxy(self, proxy_url: str) -> bool:
        """Proxy'yi listeden kaldırır"""
        initial_count = len(self.proxies)
        self.proxies = [p for p in self.proxies if p['url'] != proxy_url]
        
        if len(self.proxies) < initial_count:
            self.save_proxies()
            logger.info(f"{Renkler.YESIL}✅ Proxy kaldırıldı: {proxy_url}{Renkler.ENDC}")
            return True
        return False
    
    def get_random_proxy(self) -> Optional[Dict[str, str]]:
        """Rastgele bir proxy döndürür"""
        return random.choice(self.proxies) if self.proxies else None
    
    def list_proxies(self) -> List[Dict[str, str]]:
        """Tüm proxyleri listeler"""
        return self.proxies

def check_and_install(package):
    try:
        __import__(package)
    except ImportError:
        print(f"{package} yüklü değil, yükleniyor...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])

# Gerekli kütüphaneleri kontrol et ve yükle
required_packages = [
    "requests",
    "bs4",
    "fake_useragent",
    "aiohttp",
    "aiofiles",
    "python-telegram-bot",
    "google",
    "dropbox"
]

for pkg in required_packages:
    check_and_install(pkg)

import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse, unquote
import time
from fake_useragent import UserAgent, FakeUserAgentError
import logging
import zipfile # create_zip_archive tarafından kullanılıyor, ancak bot şu anda bu fonksiyonu çağırmıyor.

from telegram import Update
from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes, CallbackQueryHandler, MessageHandler, filters, ConversationHandler

# Telegram bot token
TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN")  # Ortam değişkeninden oku
ADMIN_IDS = [int(id) for id in os.environ.get("ADMIN_IDS", "").split(",") if id]  # Admin ID'leri

from telegram import InlineKeyboardButton, InlineKeyboardMarkup
from collections import defaultdict

class UserManager:
    """Kullanıcı yönetimi için sınıf"""
    def __init__(self):
        self.usage_count = defaultdict(int)  # Kullanıcı başına kullanım sayısı
        self.max_usage = 1  # Normal kullanıcılar için maksimum kullanım sayısı
    
    def can_use_bot(self, user_id: int) -> bool:
        """Kullanıcının botu kullanıp kullanamayacağını kontrol eder"""
        if user_id in ADMIN_IDS:
            return True
        return self.usage_count[user_id] < self.max_usage
    
    def increment_usage(self, user_id: int) -> None:
        """Kullanıcının kullanım sayısını artırır"""
        if user_id not in ADMIN_IDS:
            self.usage_count[user_id] += 1
    
    def get_remaining_usage(self, user_id: int) -> int:
        """Kullanıcının kalan kullanım hakkını döndürür"""
        if user_id in ADMIN_IDS:
            return float('inf')
        return max(0, self.max_usage - self.usage_count[user_id])

# Global user manager instance
user_manager = UserManager()

# Bot için durumlar (ConversationHandler)
ASK_URL_STATE = 0
BROWSING_FILES = 1

# Global proxy manager instance
proxy_manager = ProxyManager()

async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Bot başlatıldığında veya /start komutu kullanıldığında ana menüyü gösterir."""
    user_id = update.effective_user.id
    
    # Kullanıcının botu kullanıp kullanamayacağını kontrol et
    if not user_manager.can_use_bot(user_id):
        await update.message.reply_text(
            "❌ Üzgünüm, maksimum kullanım hakkınızı doldurdunuz.\n"
            "Bot kullanımı kişi başı 1 kere ile sınırlıdır."
        )
        return
    
    # Temel butonlar
    keyboard = [
        [InlineKeyboardButton("Site Kopyala 🖥️", callback_data='initiate_kopyala')],
        [InlineKeyboardButton("Dosyaları Görüntüle 📂", callback_data='browse_files')],
        [InlineKeyboardButton("Yardım ❓", callback_data='show_help_menu')]
    ]
    
    # Admin ise proxy yönetimi butonlarını ekle
    if user_id in ADMIN_IDS:
        keyboard.insert(-1, [InlineKeyboardButton("Proxy Yönetimi 🌐", callback_data='proxy_menu')])
    
    reply_markup = InlineKeyboardMarkup(keyboard)
    
    # Karşılama mesajı
    welcome_text = "👋 Merhaba! Site kopyalama botuna hoş geldiniz.\n\n"
    
    # Kullanım hakkı bilgisi
    if user_id not in ADMIN_IDS:
        remaining = user_manager.get_remaining_usage(user_id)
        welcome_text += f"ℹ️ Kalan kullanım hakkınız: {remaining}\n\n"
    
    welcome_text += "Aşağıdaki butonlardan işlem seçebilirsiniz."
    
    # Mesaj gönder
    if update.callback_query:
        await update.callback_query.edit_message_text(
            welcome_text,
            reply_markup=reply_markup
        )
    else:
        await update.message.reply_text(
            welcome_text,
            reply_markup=reply_markup
        )

async def ask_for_url_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """'Site Kopyala' butonuna basıldığında URL ister."""
    query = update.callback_query
    await query.answer()
    
    user_id = update.effective_user.id
    
    # Kullanım hakkı kontrolü
    if not user_manager.can_use_bot(user_id):
        await query.edit_message_text(
            "❌ Üzgünüm, maksimum kullanım hakkınızı doldurdunuz.\n"
            "Bot kullanımı kişi başı 1 kere ile sınırlıdır.",
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("Ana Menü 🏠", callback_data='start')
            ]])
        )
        return ConversationHandler.END
    
    # Admin değilse kullanım sayısını artır
    if user_id not in ADMIN_IDS:
        user_manager.increment_usage(user_id)
    
    await query.edit_message_text(
        text="Lütfen kopyalamak istediğiniz sitenin URL'sini gönderin (örn: https://example.com):\n\n"
             "İptal etmek için /cancel yazabilirsiniz."
    )
    return ASK_URL_STATE

async def proxy_menu_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Proxy yönetim menüsünü gösterir."""
    query = update.callback_query
    await query.answer()
    
    user_id = update.effective_user.id
    
    # Admin kontrolü
    if user_id not in ADMIN_IDS:
        await query.edit_message_text(
            "⛔️ Bu menüye erişim yetkiniz yok.\n"
            "Proxy yönetimi sadece adminler tarafından yapılabilir.",
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("🔙 Ana Menü", callback_data='start')
            ]])
        )
        return
    
    proxies = proxy_manager.list_proxies()
    proxy_count = len(proxies)
    
    keyboard = [
        [InlineKeyboardButton("➕ Proxy Ekle", callback_data='add_proxy')],
        [InlineKeyboardButton("🌐 API'den Yükle", callback_data='add_proxy_api')],
        [InlineKeyboardButton(f"📋 Proxy Listesi ({proxy_count})", callback_data='list_proxies')],
        [InlineKeyboardButton("🔄 Tümünü Test Et", callback_data='test_all_proxies')],
        [InlineKeyboardButton("🔙 Ana Menü", callback_data='start')]
    ]
    
    await query.edit_message_text(
        "🌐 **Proxy Yönetimi**\n\n"
        f"Toplam Proxy: {proxy_count}\n\n"
        "**Proxy Ekleme Seçenekleri:**\n"
        "1. Manuel Ekleme:\n"
        "   • `protocol://host:port`\n"
        "   • `host:port`\n"
        "   • `username:password@host:port`\n\n"
        "2. API'den Yükleme:\n"
        "   • JSON API desteği\n"
        "   • Toplu proxy yükleme\n\n"
        "**Desteklenen Protokoller:**\n"
        "• HTTP, HTTPS\n"
        "• SOCKS4, SOCKS5",
        reply_markup=InlineKeyboardMarkup(keyboard),
        parse_mode='Markdown'
    )

async def add_proxy_api_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """API'den proxy yükleme menüsünü gösterir."""
    query = update.callback_query
    await query.answer()
    
    user_id = update.effective_user.id
    
    # Admin kontrolü
    if user_id not in ADMIN_IDS:
        await query.edit_message_text(
            "⛔️ Bu özelliğe erişim yetkiniz yok.\n"
            "Proxy yönetimi sadece adminler tarafından yapılabilir.",
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("🔙 Ana Menü", callback_data='start')
            ]])
        )
        return ConversationHandler.END
    
    keyboard = [
        [InlineKeyboardButton("🔙 Proxy Menüsü", callback_data='proxy_menu')]
    ]
    
    await query.edit_message_text(
        "🌐 **API'den Proxy Yükleme**\n\n"
        "Lütfen proxy listesi içeren API URL'sini gönderin.\n\n"
        "**Desteklenen Formatlar:**\n"
        "1. JSON API:\n"
        "   ```json\n"
        "   {\n"
        '     "proxies": [\n'
        '       {"host": "1.2.3.4", "port": 8080},\n'
        '       {"url": "http://user:pass@5.6.7.8:8080"}\n'
        "     ]\n"
        "   }\n"
        "   ```\n\n"
        "2. Düz Metin:\n"
        "   ```\n"
        "   1.2.3.4:8080\n"
        "   http://5.6.7.8:8080\n"
        "   user:pass@9.10.11.12:8080\n"
        "   ```\n\n"
        "İptal etmek için 'Proxy Menüsü' butonunu kullanın.",
        reply_markup=InlineKeyboardMarkup(keyboard),
        parse_mode='Markdown'
    )
    return ASK_API_URL_STATE

async def test_all_proxies_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Tüm proxyleri test eder."""
    query = update.callback_query
    await query.answer()
    
    user_id = update.effective_user.id
    
    # Admin kontrolü
    if user_id not in ADMIN_IDS:
        await query.edit_message_text(
            "⛔️ Bu özelliğe erişim yetkiniz yok.\n"
            "Proxy yönetimi sadece adminler tarafından yapılabilir.",
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("🔙 Ana Menü", callback_data='start')
            ]])
        )
        return
    
    proxies = proxy_manager.list_proxies()
    if not proxies:
        await query.edit_message_text(
            "❌ Test edilecek proxy bulunamadı!",
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("🔙 Proxy Menüsü", callback_data='proxy_menu')
            ]])
        )
        return
    
    progress_message = await query.edit_message_text(
        "🔄 Proxyler test ediliyor...\n"
        f"0/{len(proxies)} tamamlandı"
    )
    
    results = []
    async with aiohttp.ClientSession() as session:
        for i, proxy in enumerate(proxies, 1):
            test_result = await proxy_manager.test_proxy(session, proxy)
            results.append({
                'proxy': proxy['url'],
                'working': test_result
            })
            
            # Her 5 testte bir ilerleme mesajını güncelle
            if i % 5 == 0 or i == len(proxies):
                await progress_message.edit_text(
                    f"🔄 Proxyler test ediliyor...\n"
                    f"{i}/{len(proxies)} tamamlandı"
                )
    
    # Sonuçları göster
    working_count = sum(1 for r in results if r['working'])
    report = (
        f"📊 Proxy Test Sonuçları\n\n"
        f"✅ Çalışan: {working_count}\n"
        f"❌ Çalışmayan: {len(results) - working_count}\n\n"
        "📋 Detaylı Sonuçlar:\n"
    )
    
    for result in results:
        status = "✅" if result['working'] else "❌"
        report += f"{status} {result['proxy']}\n"
    
    # Uzun mesajları böl
    if len(report) > 4096:
        chunks = [report[i:i+4096] for i in range(0, len(report), 4096)]
        for i, chunk in enumerate(chunks):
            if i == 0:
                await progress_message.edit_text(
                    chunk,
                    reply_markup=InlineKeyboardMarkup([[
                        InlineKeyboardButton("🔙 Proxy Menüsü", callback_data='proxy_menu')
                    ]])
                )
            else:
                await context.bot.send_message(
                    chat_id=query.message.chat_id,
                    text=chunk
                )
    else:
        await progress_message.edit_text(
            report,
            reply_markup=InlineKeyboardMarkup([[
                InlineKeyboardButton("🔙 Proxy Menüsü", callback_data='proxy_menu')
            ]])
        )

async def add_proxy_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Yeni proxy ekleme komutu."""
    if not context.args:
        await update.message.reply_text(
            "❌ Proxy adresi belirtilmedi!\n\n"
            "Kullanım:\n"
            "1. Tekli proxy eklemek için:\n"
            "`/add_proxy protocol://host:port` veya `/add_proxy host:port`\n"
            "Örnek: `/add_proxy https://1.2.3.4:8080` veya `/add_proxy 1.2.3.4:8080`\n\n"
            "2. API'den proxy listesi yüklemek için:\n"
            "`/add_proxy --api URL`\n"
            "Örnek: `/add_proxy --api https://api.example.com/proxies`\n\n"
            "3. Kullanıcı adı/şifre ile proxy eklemek için:\n"
            "`/add_proxy username:password@host:port`\n"
            "Örnek: `/add_proxy user:pass@1.2.3.4:8080`",
            parse_mode='Markdown'
        )
        return
    
    # API'den yükleme kontrolü
    if context.args[0] == '--api':
        if len(context.args) < 2:
            await update.message.reply_text(
                "❌ API URL'si belirtilmedi!\n"
                "Kullanım: `/add_proxy --api URL`",
                parse_mode='Markdown'
            )
            return
        
        api_url = ' '.join(context.args[1:])
        message = await update.message.reply_text("🔄 API'den proxyler yükleniyor...")
        success = await proxy_manager.load_proxies_from_api(api_url)
        
        if success:
            await message.edit_text(
                f"✅ API'den proxyler başarıyla yüklendi!\n"
                f"📋 Güncel proxy sayısı: {len(proxy_manager.list_proxies())}\n\n"
                "Proxy listesini görmek için /list_proxies komutunu kullanabilirsiniz."
            )
        else:
            await message.edit_text(
                "❌ API'den proxy yüklenemedi!\n"
                "Lütfen API URL'sini kontrol edin ve tekrar deneyin."
            )
        return
    
    # Tekli proxy ekleme
    proxy = ' '.join(context.args)
    message = await update.message.reply_text("🔄 Proxy ekleniyor ve test ediliyor...")
    
    if proxy_manager.add_proxy(proxy):
        # Proxy'i test et
        formatted_proxy = proxy_manager.format_proxy(proxy)
        async with aiohttp.ClientSession() as session:
            test_result = await proxy_manager.test_proxy(session, formatted_proxy)
        
        if test_result:
            await message.edit_text(
                f"✅ Proxy başarıyla eklendi ve test edildi!\n"
                f"🔗 {formatted_proxy['url']}\n\n"
                "Proxy listesini görmek için /list_proxies komutunu kullanabilirsiniz."
            )
        else:
            await message.edit_text(
                f"⚠️ Proxy eklendi fakat test başarısız!\n"
                f"🔗 {formatted_proxy['url']}\n"
                "Proxy çalışmıyor olabilir, ancak yine de listeye eklendi.\n\n"
                "Proxy listesini görmek için /list_proxies komutunu kullanabilirsiniz."
            )
    else:
        await message.edit_text(
            "❌ Proxy eklenemedi! Lütfen formatı kontrol edin.\n\n"
            "Desteklenen formatlar:\n"
            "1. `protocol://host:port`\n"
            "2. `host:port`\n"
            "3. `username:password@host:port`\n"
            "4. `protocol://username:password@host:port`\n\n"
            "Protokoller: http, https, socks4, socks5\n"
            "IPv4, IPv6 ve domain adresler desteklenir.",
            parse_mode='Markdown'
        )

async def test_proxy_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Proxy test komutu."""
    if not context.args:
        await update.message.reply_text(
            "❌ Test edilecek proxy belirtilmedi!\n\n"
            "Kullanım:\n"
            "1. Belirli bir proxy'i test etmek için:\n"
            "`/test_proxy protocol://host:port`\n\n"
            "2. Tüm proxyleri test etmek için:\n"
            "`/test_proxy --all`",
            parse_mode='Markdown'
        )
        return
    
    if context.args[0] == '--all':
        message = await update.message.reply_text("🔄 Tüm proxyler test ediliyor...")
        proxies = proxy_manager.list_proxies()
        
        if not proxies:
            await message.edit_text("❌ Test edilecek proxy bulunamadı!")
            return
        
        results = []
        async with aiohttp.ClientSession() as session:
            for proxy in proxies:
                test_result = await proxy_manager.test_proxy(session, proxy)
                results.append({
                    'proxy': proxy['url'],
                    'working': test_result
                })
        
        # Sonuçları göster
        working_count = sum(1 for r in results if r['working'])
        report = (
            f"📊 Proxy Test Sonuçları\n\n"
            f"✅ Çalışan: {working_count}\n"
            f"❌ Çalışmayan: {len(results) - working_count}\n\n"
            "📋 Detaylı Sonuçlar:\n"
        )
        
        for result in results:
            status = "✅" if result['working'] else "❌"
            report += f"{status} {result['proxy']}\n"
        
        if len(report) > 4096:  # Telegram mesaj limiti
            report = report[:4093] + "..."
        
        await message.edit_text(report)
    else:
        proxy = ' '.join(context.args)
        message = await update.message.reply_text("🔄 Proxy test ediliyor...")
        
        formatted_proxy = proxy_manager.format_proxy(proxy)
        if not formatted_proxy:
            await message.edit_text(
                "❌ Geçersiz proxy formatı!\n"
                "Lütfen formatı kontrol edin ve tekrar deneyin."
            )
            return
        
        async with aiohttp.ClientSession() as session:
            test_result = await proxy_manager.test_proxy(session, formatted_proxy)
        
        if test_result:
            await message.edit_text(
                f"✅ Proxy çalışıyor!\n"
                f"🔗 {formatted_proxy['url']}\n\n"
                "Bu proxy'i listeye eklemek için /add_proxy komutunu kullanabilirsiniz."
            )
        else:
            await message.edit_text(
                f"❌ Proxy çalışmıyor!\n"
                f"🔗 {formatted_proxy['url']}"
            )

async def list_proxies_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Proxy listesini gösterir."""
    proxies = proxy_manager.list_proxies()
    
    if not proxies:
        keyboard = [[InlineKeyboardButton("➕ Proxy Ekle", callback_data='add_proxy')]]
        await update.message.reply_text(
            "📋 Proxy Listesi\n\n"
            "❌ Henüz proxy eklenmemiş!\n"
            "Proxy eklemek için 'Proxy Ekle' butonunu kullanın veya /add_proxy komutunu kullanabilirsiniz.",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
        return
    
    # Proxyleri listele ve her biri için silme butonu ekle
    keyboard = []
    proxy_list = "📋 **Proxy Listesi**\n\n"
    
    for i, proxy in enumerate(proxies, 1):
        proxy_list += f"{i}. `{proxy['url']}`\n"
        keyboard.append([InlineKeyboardButton(f"🗑️ Sil: {proxy['url']}", callback_data=f"remove_proxy:{proxy['url']}")])
    
    keyboard.append([InlineKeyboardButton("🔙 Proxy Menüsü", callback_data='proxy_menu')])
    
    await update.message.reply_text(
        proxy_list,
        reply_markup=InlineKeyboardMarkup(keyboard),
        parse_mode='Markdown'
    )

async def remove_proxy_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """Proxy silme işlemi için callback."""
    query = update.callback_query
    await query.answer()
    
    proxy_url = query.data.split(':', 1)[1]
    if proxy_manager.remove_proxy(proxy_url):
        # Proxy listesini güncelle
        proxies = proxy_manager.list_proxies()
        if not proxies:
            keyboard = [
                [InlineKeyboardButton("➕ Proxy Ekle", callback_data='add_proxy')],
                [InlineKeyboardButton("🔙 Proxy Menüsü", callback_data='proxy_menu')]
            ]
            await query.edit_message_text(
                "📋 Proxy Listesi\n\n"
                "❌ Tüm proxyler silindi!\n"
                "Yeni proxy eklemek için 'Proxy Ekle' butonunu kullanın.",
                reply_markup=InlineKeyboardMarkup(keyboard)
            )
        else:
            # Güncel listeyi göster
            keyboard = []
            proxy_list = "📋 **Proxy Listesi**\n\n"
            
            for i, proxy in enumerate(proxies, 1):
                proxy_list += f"{i}. `{proxy['url']}`\n"
                keyboard.append([InlineKeyboardButton(f"🗑️ Sil: {proxy['url']}", callback_data=f"remove_proxy:{proxy['url']}")])
            
            keyboard.append([InlineKeyboardButton("🔙 Proxy Menüsü", callback_data='proxy_menu')])
            
            await query.edit_message_text(
                proxy_list,
                reply_markup=InlineKeyboardMarkup(keyboard),
                parse_mode='Markdown'
            )
    else:
        await query.edit_message_text(
            f"❌ Proxy silinemedi: {proxy_url}",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("🔙 Proxy Menüsü", callback_data='proxy_menu')]])
        )

async def show_help_menu_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    """'Yardım' butonuna basıldığında yardım menüsünü gösterir."""
    query = update.callback_query
    await query.answer()
    help_text = (
        "ℹ️ **Site Kopyalama Botu Yardım Menüsü**\n\n"
        "Bu bot, belirttiğiniz web sitelerini kopyalamanıza ve yönetmenize olanak tanır.\n\n"
        "**Ana Komutlar:**\n"
        "/start - Ana menüyü gösterir\n"
        "/help - Bu yardım menüsünü gösterir\n\n"
        "**Site Kopyalama:**\n"
        "1. Ana menüden 'Site Kopyala 🖥️' butonuna tıklayarak işlemi başlatın:\n"
        "   - Bot sizden URL isteyecektir (örn: https://example.com)\n"
        "   - URL'yi gönderdiğinizde kopyalama başlar\n"
        "   - İşlem bittiğinde size bildirilecektir\n\n"
        "**Dosya Yönetimi:**\n"
        "1. 'Dosyaları Görüntüle 📂' butonu ile:\n"
        "   - İndirilen siteleri görüntüleyin\n"
        "   - HTML dosyalarını tarayıcıda açın\n"
        "   - Klasörler arasında gezinin\n\n"
        "**Proxy Yönetimi:**\n"
        "1. Proxy Ekleme:\n"
        "   `/add_proxy host:port` - Basit proxy ekler\n"
        "   `/add_proxy protocol://host:port` - Protokol belirterek ekler\n"
        "   `/add_proxy user:pass@host:port` - Kullanıcı adı/şifre ile ekler\n"
        "   `/add_proxy --api URL` - API'den proxy listesi yükler\n\n"
        "2. Proxy Listeleme ve Test:\n"
        "   `/list_proxies` - Mevcut proxyleri listeler\n"
        "   `/test_proxy host:port` - Belirli bir proxy'i test eder\n"
        "   `/test_proxy --all` - Tüm proxyleri test eder\n\n"
        "**İşleyiş Detayları:**\n"
        "🔹 HTML, CSS, JS, resim ve font dosyaları indirilir\n"
        "🔹 İç bağlantılar yerel kopyaya uygun şekilde güncellenir\n"
        "🔹 Dosyalar 'Telegram_Klonlar' klasöründe saklanır\n"
        "🔹 Proxy kullanımı ile engelli sitelere erişim sağlanır\n"
        "🔹 IPv4, IPv6 ve domain proxy adresleri desteklenir\n"
        "🔹 HTTP, HTTPS, SOCKS4, SOCKS5 proxy protokolleri desteklenir\n\n"
        "Ana menüye dönmek için /start komutunu kullanabilirsiniz."
    )
    try:
        await query.edit_message_text(text=help_text, parse_mode='Markdown')
    except Exception as e:
        logger.warning(f"Yardım mesajı düzenlenemedi, yeni mesaj gönderiliyor: {e}")
        # Butonun olduğu mesajı düzenleyemezse, yeni bir mesaj olarak gönder
        if query.message:
            await context.bot.send_message(chat_id=query.message.chat_id, text=help_text, parse_mode='Markdown')
        else: # Fallback, eğer query.message yoksa (çok nadir bir durum)
             logger.error("Yardım mesajı gönderilemedi, query.message mevcut değil.")

async def actual_kopyala_logic(url: str, update: Update, context: ContextTypes.DEFAULT_TYPE):
    """Verilen URL için site kopyalama işlemini gerçekleştirir."""
    ilerleme_mesaji = await update.message.reply_text(
        f"⏳ {url} sitesi için hazırlık yapılıyor...\n"
        "🔍 Alt alan adları taranıyor..."
    )
    
    genel_kayit_klasoru = "Telegram_Klonlar"
    os.makedirs(genel_kayit_klasoru, exist_ok=True)

    ana_domain_parsed = urlparse(url)
    ana_domain_netloc = ana_domain_parsed.netloc
    if not ana_domain_netloc:
        await ilerleme_mesaji.edit_text(f"❌ Geçersiz URL formatı: {url}. Lütfen tam bir URL girin.")
        return

    # Alt alan adlarını bul
    ana_domain = '.'.join(ana_domain_netloc.split('.')[-2:])  # örn: example.com
    alt_alan_adlari = await alt_alan_adlarini_bul(ana_domain)
    
    if alt_alan_adlari:
        await ilerleme_mesaji.edit_text(
            f"🔍 {len(alt_alan_adlari)} alt alan adı bulundu:\n" +
            "\n".join([f"- {domain}" for domain in alt_alan_adlari[:5]]) +
            ("\n..." if len(alt_alan_adlari) > 5 else "")
        )
    
    # Ana siteyi kopyala
    ana_site_klasor_adi = ana_domain_netloc.replace('.', '_').replace(':', '_port_')
    ana_site_kayit_yolu = os.path.join(genel_kayit_klasoru, ana_site_klasor_adi)

    # Proxy seçimi
    proxy = proxy_manager.get_random_proxy()
    if proxy:
        await ilerleme_mesaji.edit_text(
            f"⏳ Ana site ({url}) kopyalanıyor...\n"
            f"🌐 Proxy: {proxy['url']}"
        )
        connector = aiohttp.TCPConnector()
        session_params = {
            'connector': connector,
            'headers': {'User-Agent': get_random_user_agent()},
            'trust_env': True,
            'proxy': proxy['url']
        }
    else:
        await ilerleme_mesaji.edit_text(
            f"⏳ Ana site ({url}) kopyalanıyor...\n"
            "⚠️ Proxy bulunamadı, doğrudan bağlantı kullanılıyor"
        )
        connector = aiohttp.TCPConnector()
        session_params = {
            'connector': connector,
            'headers': {'User-Agent': get_random_user_agent()},
            'trust_env': True
        }

    async with aiohttp.ClientSession(**session_params) as session:
        await ilerleme_mesaji.edit_text(f"⏳ Ana site ({url}) kopyalanıyor...")
        indirilen_varliklar_tum_siteler_cache = {}
        success = await siteyi_kopyala_async(url, ana_site_kayit_yolu, session, indirilen_varliklar_tum_siteler_cache, max_derinlik=2)
        
        if success:
            if alt_alan_adlari:
                await ilerleme_mesaji.edit_text("🔄 Alt alan adları kopyalanıyor...")
                for alt_alan in alt_alan_adlari:
                    alt_alan_url = f"https://{alt_alan}"
                    alt_alan_klasor = os.path.join(ana_site_kayit_yolu, alt_alan.replace('.', '_'))
                    try:
                        await siteyi_kopyala_async(
                            alt_alan_url, alt_alan_klasor, session,
                            indirilen_varliklar_tum_siteler_cache, max_derinlik=1
                        )
                    except Exception as e:
                        logger.warning(f"{Renkler.UYARI}Alt alan adı kopyalanamadı ({alt_alan_url}): {e}{Renkler.ENDC}")
            
            zip_path = f"{ana_site_kayit_yolu}.zip"
            await ilerleme_mesaji.edit_text("📦 ZIP arşivi oluşturuluyor...")
            if create_zip_archive(ana_site_kayit_yolu, zip_path):
                file_size = os.path.getsize(zip_path)
                if file_size > 50 * 1024 * 1024:  # 50MB'dan büyükse
                    await ilerleme_mesaji.edit_text("☁️ Dosya Dropbox'a yükleniyor...")
                    dropbox_link = await buyuk_dosyayi_buluta_yukle(zip_path)
                    if dropbox_link:
                        await ilerleme_mesaji.edit_text(
                            f"✅ Site başarıyla kopyalandı!\n\n"
                            f"📦 Dosya boyutu: {get_human_readable_size(file_size)}\n"
                            f"☁️ İndirme linki: {dropbox_link}"
                        )
                    else:
                        await ilerleme_mesaji.edit_text(
                            f"⚠️ Site kopyalandı fakat dosya çok büyük ve Dropbox'a yüklenemedi.\n"
                            f"📂 Yerel kayıt yolu: {ana_site_kayit_yolu}"
                        )
                else:
                    await ilerleme_mesaji.edit_text(
                        f"✅ Site başarıyla kopyalandı!\n\n"
                        f"📂 Kayıt yolu: {ana_site_kayit_yolu}\n"
                        f"📦 ZIP arşivi: {zip_path}\n"
                        f"📊 Dosya boyutu: {get_human_readable_size(file_size)}"
                    )
        else:
            await ilerleme_mesaji.edit_text(f"❌ {url} kopyalanırken hata oluştu.")

async def process_url_input_and_kopyala(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Kullanıcıdan gelen URL'yi işler ve kopyalama mantığını çağırır."""
    url = update.message.text
    parsed_url = urlparse(url)
    if not parsed_url.scheme or not parsed_url.netloc: # Temel URL doğrulaması
        await update.message.reply_text(
            "⚠️ Geçersiz URL. Lütfen 'http://' veya 'https://' ile başlayan tam bir URL girin.\n"
            "Yeni bir işlem başlatmak için /start yazabilirsiniz."
        )
        return ConversationHandler.END # Geçersiz URL durumunda konuşmayı sonlandır

    await actual_kopyala_logic(url, update, context)
    return ConversationHandler.END # Kopyalama işlemi sonrası konuşmayı sonlandır

async def cancel_conversation(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Konuşmayı iptal eder."""
    await update.message.reply_text("İşlem iptal edildi. Yeni bir işlem başlatmak için /start yazabilirsiniz.")
    return ConversationHandler.END

async def browse_files_callback(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Dosya gezgini başlatır."""
    query = update.callback_query
    await query.answer()
    
    current_path = os.path.join(os.getcwd(), "Telegram_Klonlar")
    if not os.path.exists(current_path):
        await query.edit_message_text(
            "Henüz indirilmiş site bulunmuyor. Önce bir site kopyalayın.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Ana Menü 🏠", callback_data='start')]])
        )
        return ConversationHandler.END
    
    try:
        items = list_directory_contents(current_path)
        keyboard = create_file_browser_keyboard(items, current_path)
        await query.edit_message_text(
            f"📂 Dosya Gezgini\nKonum: {os.path.basename(current_path)}",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
        return BROWSING_FILES
    except Exception as e:
        await query.edit_message_text(
            f"Dosyalar listelenirken hata oluştu: {str(e)}",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Ana Menü 🏠", callback_data='start')]])
        )
        return ConversationHandler.END

def list_directory_contents(path):
    """Dizindeki dosya ve klasörleri listeler."""
    items = []
    for item in os.listdir(path):
        full_path = os.path.join(path, item)
        is_dir = os.path.isdir(full_path)
        size = os.path.getsize(full_path) if not is_dir else 0
        items.append({
            'name': item,
            'path': full_path,
            'is_directory': is_dir,
            'size': size
        })
    return sorted(items, key=lambda x: (not x['is_directory'], x['name'].lower()))

def create_file_browser_keyboard(items, current_path):
    """Dosya gezgini için klavye oluşturur."""
    keyboard = []
    
    # Üst dizine çıkma butonu
    parent_path = os.path.dirname(current_path)
    if os.path.exists(parent_path) and current_path != os.path.join(os.getcwd(), "Telegram_Klonlar"):
        keyboard.append([InlineKeyboardButton("📁 .. (Üst Dizin)", callback_data=f'browse:{parent_path}')])
    
    # Dosya ve klasör butonları
    for item in items:
        name = item['name']
        path = item['path']
        if item['is_directory']:
            button_text = f"📁 {name}"
            callback_data = f'browse:{path}'
        else:
            size = get_human_readable_size(item['size'])
            button_text = f"📄 {name} ({size})"
            callback_data = f'open:{path}'
        keyboard.append([InlineKeyboardButton(button_text, callback_data=callback_data)])
    
    # Ana menü butonu
    keyboard.append([InlineKeyboardButton("Ana Menü 🏠", callback_data='start')])
    return keyboard

def get_human_readable_size(size_in_bytes):
    """Dosya boyutunu okunabilir formata çevirir."""
    try:
        for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
            if size_in_bytes < 1024.0:
                return f"{size_in_bytes:.1f} {unit}"
            size_in_bytes /= 1024.0
        return f"{size_in_bytes:.1f} PB"
    except Exception as e:
        logger.error(f"{Renkler.HATA}Boyut dönüştürme hatası: {e}{Renkler.ENDC}")
        return "N/A"

async def handle_file_action(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """Dosya ve klasör işlemlerini yönetir."""
    query = update.callback_query
    await query.answer()
    
    action, path = query.data.split(':', 1)
    
    if not is_safe_path(os.path.join(os.getcwd(), "Telegram_Klonlar"), path):
        await query.edit_message_text(
            "Güvenlik hatası: İzin verilmeyen dizin erişimi.",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Ana Menü 🏠", callback_data='start')]])
        )
        return ConversationHandler.END
    
    try:
        if action == 'browse':
            items = list_directory_contents(path)
            keyboard = create_file_browser_keyboard(items, path)
            await query.edit_message_text(
                f"📂 Dosya Gezgini\nKonum: {os.path.basename(path)}",
                reply_markup=InlineKeyboardMarkup(keyboard)
            )
            return BROWSING_FILES
        elif action == 'open':
            if os.path.exists(path):
                # HTML dosyaları için özel işlem
                if path.endswith('.html'):
                    await query.edit_message_text(
                        f"🌐 HTML dosyası açılıyor: {os.path.basename(path)}\n"
                        "Tarayıcınızda görüntülemek için aşağıdaki butonu kullanın:",
                        reply_markup=InlineKeyboardMarkup([
                            [InlineKeyboardButton("Tarayıcıda Aç 🌐", url=f"file://{path}")],
                            [InlineKeyboardButton("Geri Dön 🔙", callback_data=f"browse:{os.path.dirname(path)}")]
                        ])
                    )
                else:
                    await query.edit_message_text(
                        f"⚠️ Bu dosya türü doğrudan açılamıyor: {os.path.basename(path)}\n"
                        "Dosyayı bilgisayarınızda bulup manuel olarak açabilirsiniz.",
                        reply_markup=InlineKeyboardMarkup([
                            [InlineKeyboardButton("Geri Dön 🔙", callback_data=f"browse:{os.path.dirname(path)}")]
                        ])
                    )
            else:
                await query.edit_message_text(
                    "❌ Dosya bulunamadı.",
                    reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Geri Dön 🔙", callback_data=f"browse:{os.path.dirname(path)}")]])
                )
            return BROWSING_FILES
    except Exception as e:
        await query.edit_message_text(
            f"İşlem sırasında hata oluştu: {str(e)}",
            reply_markup=InlineKeyboardMarkup([[InlineKeyboardButton("Ana Menü 🏠", callback_data='start')]])
        )
        return ConversationHandler.END

def is_safe_path(base_path, requested_path):
    """Güvenli yol kontrolü yapar."""
    try:
        base_path = os.path.abspath(base_path)
        requested_path = os.path.abspath(requested_path)
        return os.path.commonpath([base_path, requested_path]) == base_path
    except ValueError:
        return False

# Bot için durumlar (ConversationHandler)
ASK_URL_STATE = 0
BROWSING_FILES = 1
ASK_API_URL_STATE = 2

async def main_bot():
    if not TELEGRAM_BOT_TOKEN:
        print("HATA: TELEGRAM_BOT_TOKEN ortam değişkeni ayarlanmamış. Bot başlatılamıyor.")
        return
    app = ApplicationBuilder().token(TELEGRAM_BOT_TOKEN).build()

    # Temel konuşma işleyicisi
    conv_handler = ConversationHandler(
        entry_points=[
            CallbackQueryHandler(ask_for_url_callback, pattern='^initiate_kopyala$'),
            CallbackQueryHandler(browse_files_callback, pattern='^browse_files$'),
            CallbackQueryHandler(add_proxy_api_callback, pattern='^add_proxy_api$')
        ],
        states={
            ASK_URL_STATE: [MessageHandler(filters.TEXT & ~filters.COMMAND, process_url_input_and_kopyala)],
            BROWSING_FILES: [
                CallbackQueryHandler(handle_file_action, pattern='^(browse|open):'),
                CallbackQueryHandler(start_command, pattern='^start$')
            ],
            ASK_API_URL_STATE: [MessageHandler(filters.TEXT & ~filters.COMMAND, process_api_url)]
        },
        fallbacks=[
            CommandHandler("cancel", cancel_conversation),
            CommandHandler("start", start_command),
            CallbackQueryHandler(start_command, pattern='^start$'),
            CallbackQueryHandler(proxy_menu_callback, pattern='^proxy_menu$')
        ]
    )
    app.add_handler(conv_handler)

    # Temel komut işleyicisi
    app.add_handler(CommandHandler("start", start_command))

    # Callback işleyicileri
    app.add_handler(CallbackQueryHandler(show_help_menu_callback, pattern='^show_help_menu$'))
    app.add_handler(CallbackQueryHandler(proxy_menu_callback, pattern='^proxy_menu$'))
    app.add_handler(CallbackQueryHandler(test_all_proxies_callback, pattern='^test_all_proxies$'))

    print("Telegram botu başlatıldı.")
    await app.run_polling()

async def process_api_url(update: Update, context: ContextTypes.DEFAULT_TYPE) -> int:
    """API URL'sini işler ve proxy'leri yükler."""
    user_id = update.effective_user.id
    
    # Admin kontrolü
    if user_id not in ADMIN_IDS:
        await update.message.reply_text(
            "⛔️ Bu özelliğe erişim yetkiniz yok.\n"
            "Proxy yönetimi sadece adminler tarafından yapılabilir."
        )
        return ConversationHandler.END
    
    api_url = update.message.text.strip()
    message = await update.message.reply_text("🔄 API'den proxyler yükleniyor...")
    
    success = await proxy_manager.load_proxies_from_api(api_url)
    
    if success:
        keyboard = [[InlineKeyboardButton("🔙 Proxy Menüsü", callback_data='proxy_menu')]]
        await message.edit_text(
            f"✅ API'den proxyler başarıyla yüklendi!\n"
            f"📋 Güncel proxy sayısı: {len(proxy_manager.list_proxies())}\n\n"
            "Proxy menüsüne dönmek için butonu kullanın.",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
    else:
        keyboard = [[InlineKeyboardButton("🔄 Tekrar Dene", callback_data='add_proxy_api')]]
        await message.edit_text(
            "❌ API'den proxy yüklenemedi!\n"
            "Lütfen URL'yi kontrol edin ve tekrar deneyin.",
            reply_markup=InlineKeyboardMarkup(keyboard)
        )
    
    return ConversationHandler.END

# ANSI renk kodları (isteğe bağlı, konsol çıktısını renklendirmek için)
class Renkler:
    HEADER = '\033[95m'
    MAVI = '\033[94m'
    YESIL = '\033[92m'
    UYARI = '\033[93m'
    HATA = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

# Logging ayarları
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def get_random_user_agent():
    """Rastgele bir User-Agent döndürür."""
    try:
        ua = UserAgent(fallback='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36')
        return ua.random
    except FakeUserAgentError:
        logger.warning("FakeUserAgentError: İnternet bağlantısı veya User-Agent listesi sorunu. Varsayılan User-Agent kullanılacak.")
        return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
    except Exception: 
        logger.warning("UserAgent başlatılırken bir hata oluştu. Varsayılan User-Agent kullanılacak.")
        return 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'

def dosya_ad_temizle(url_parcasi, varlik_turu="asset"):
    """URL parçasından geçerli bir dosya adı oluşturur."""
    try:
        # URL'yi parse et ve decode et
        parsed_url = urlparse(url_parcasi)
        path = parsed_url.path
        decoded_path = unquote(path)
        dosya_adi = os.path.basename(decoded_path)
        
        # Dosya adı boşsa, query veya varsayılan değer kullan
        if not dosya_adi:
            if parsed_url.query:
                try:
                    dosya_adi = re.sub(r'[^a-zA-Z0-9_.-]', '_', parsed_url.query)
                except Exception as e:
                    logger.warning(f"{Renkler.UYARI}Query temizlenirken hata: {e}, varsayılan ad kullanılıyor{Renkler.ENDC}")
                    dosya_adi = ""
            
            if not dosya_adi:
                dosya_adi = f"default_{varlik_turu}"
        
        # Uzantıyı kontrol et ve gerekirse ekle
        name_part, ext_part = os.path.splitext(dosya_adi)
        if not ext_part:
            ext_part = {
                'CSS': '.css',
                'JS': '.js',
                'Font': '.woff2',
                'Resim': '.png'
            }.get(varlik_turu, '')
        
        dosya_adi = name_part + ext_part
        
        # Dosya adı uzunluğunu kontrol et
        MAX_FILENAME_LEN = 200
        if len(dosya_adi) > MAX_FILENAME_LEN:
            name, ext = os.path.splitext(dosya_adi)
            ellipsis = "..."
            if len(ext) > MAX_FILENAME_LEN - len(ellipsis) - 1:
                dosya_adi = dosya_adi[:MAX_FILENAME_LEN - len(ellipsis)] + ellipsis
            else:
                name = name[:MAX_FILENAME_LEN - len(ext) - len(ellipsis)]
                dosya_adi = name + ellipsis + ext
        
        # Geçersiz karakterleri temizle
        dosya_adi = re.sub(r'[\\/*?:"<>|]', "_", dosya_adi)
        
        # Özel durumları kontrol et
        if dosya_adi in [".", ".."]:
            dosya_adi = f"file_{varlik_turu}_{dosya_adi}"
        
        return dosya_adi
        
    except Exception as e:
        logger.error(f"{Renkler.HATA}Dosya adı temizlenirken hata: {e}{Renkler.ENDC}")
        return f"error_{varlik_turu}_{int(time.time())}"  # Benzersiz hata durumu dosya adı

import asyncio
import aiohttp
import aiofiles
from googlesearch import search
import dropbox
from urllib.parse import urlparse

async def alt_alan_adlarini_bul(ana_domain):
    """Google dork kullanarak alt alan adlarını bulur."""
    alt_alan_adlari = set()
    basarisiz_sorgular = []
    MAX_RETRY = 3
    RETRY_DELAY = 2
    
    dork_sorgulari = [
        f"site:*.{ana_domain} -www",
        f"site:*.{ana_domain} -site:www.{ana_domain}",
        f"site:{ana_domain} inurl:*.*"
    ]
    
    logger.info(f"{Renkler.MAVI}🔍 Alt alan adları taranıyor: {ana_domain}{Renkler.ENDC}")
    
    for sorgu in dork_sorgulari:
        for deneme in range(MAX_RETRY):
            try:
                logger.info(f"{Renkler.MAVI}Google sorgusu çalıştırılıyor (Deneme {deneme + 1}/{MAX_RETRY}): {sorgu}{Renkler.ENDC}")
                for url in search(sorgu, num_results=30, lang="tr"):
                    try:
                        parsed_url = urlparse(url)
                        if parsed_url.netloc.endswith(ana_domain) and parsed_url.netloc != f"www.{ana_domain}":
                            alt_alan_adlari.add(parsed_url.netloc)
                            logger.info(f"{Renkler.YESIL}Alt alan adı bulundu: {parsed_url.netloc}{Renkler.ENDC}")
                    except Exception as e:
                        logger.warning(f"{Renkler.UYARI}URL işlenirken hata ({url}): {e}{Renkler.ENDC}")
                        continue
                
                await asyncio.sleep(2)  # Google'ın rate limit'ini aşmamak için
                break  # Başarılı sorgu, döngüden çık
                
            except Exception as e:
                if deneme < MAX_RETRY - 1:
                    logger.warning(f"{Renkler.UYARI}Google araması başarısız, yeniden deneniyor ({deneme + 1}/{MAX_RETRY}): {e}{Renkler.ENDC}")
                    await asyncio.sleep(RETRY_DELAY * (deneme + 1))
                else:
                    logger.error(f"{Renkler.HATA}Google araması başarısız ({sorgu}): {e}{Renkler.ENDC}")
                    basarisiz_sorgular.append(sorgu)
    
    if basarisiz_sorgular:
        logger.warning(
            f"{Renkler.UYARI}⚠️ {len(basarisiz_sorgular)} sorgu başarısız oldu:\n" +
            "\n".join([f"- {sorgu}" for sorgu in basarisiz_sorgular])
        )
    
    bulunan_alan_adlari = list(alt_alan_adlari)
    logger.info(
        f"{Renkler.YESIL}✅ Tarama tamamlandı: {len(bulunan_alan_adlari)} alt alan adı bulundu\n" +
        "\n".join([f"- {domain}" for domain in bulunan_alan_adlari[:5]]) +
        ("\n..." if len(bulunan_alan_adlari) > 5 else "")
    )
    
    return bulunan_alan_adlari

async def buyuk_dosyayi_buluta_yukle(file_path):
    """Büyük dosyaları Dropbox'a yükler."""
    MAX_RETRY = 3
    RETRY_DELAY = 2
    CHUNK_SIZE = 4 * 1024 * 1024  # 4MB chunks
    
    try:
        # Token kontrolü
        DROPBOX_ACCESS_TOKEN = os.environ.get("DROPBOX_ACCESS_TOKEN")
        if not DROPBOX_ACCESS_TOKEN:
            logger.error(f"{Renkler.HATA}DROPBOX_ACCESS_TOKEN bulunamadı{Renkler.ENDC}")
            return None
        
        # Dosya kontrolü
        if not os.path.exists(file_path):
            logger.error(f"{Renkler.HATA}Yüklenecek dosya bulunamadı: {file_path}{Renkler.ENDC}")
            return None
        
        file_size = os.path.getsize(file_path)
        file_name = os.path.basename(file_path)
        dropbox_path = f"/Telegram_Klonlar/{file_name}"
        
        logger.info(f"{Renkler.MAVI}Dropbox'a yükleme başlatılıyor: {file_name} ({get_human_readable_size(file_size)}){Renkler.ENDC}")
        
        dbx = dropbox.Dropbox(DROPBOX_ACCESS_TOKEN)
        
        # Küçük dosyalar için doğrudan yükleme
        if file_size <= CHUNK_SIZE:
            for deneme in range(MAX_RETRY):
                try:
                    with open(file_path, 'rb') as f:
                        response = dbx.files_upload(f.read(), dropbox_path)
                        shared_link = dbx.sharing_create_shared_link(response.path_display)
                        logger.info(f"{Renkler.YESIL}✅ Dosya başarıyla yüklendi: {file_name}{Renkler.ENDC}")
                        return shared_link.url
                except Exception as e:
                    if deneme < MAX_RETRY - 1:
                        logger.warning(f"{Renkler.UYARI}Yükleme başarısız, yeniden deneniyor ({deneme + 1}/{MAX_RETRY}): {e}{Renkler.ENDC}")
                        await asyncio.sleep(RETRY_DELAY * (deneme + 1))
                    else:
                        raise
        
        # Büyük dosyalar için parçalı yükleme
        else:
            yuklenen_boyut = 0
            for deneme in range(MAX_RETRY):
                try:
                    with open(file_path, 'rb') as f:
                        # Yükleme oturumu başlat
                        upload_session_start_result = dbx.files_upload_session_start(f.read(CHUNK_SIZE))
                        yuklenen_boyut += CHUNK_SIZE
                        logger.info(f"{Renkler.MAVI}Yükleme başladı: %{(yuklenen_boyut/file_size*100):.1f} ({get_human_readable_size(yuklenen_boyut)}/{get_human_readable_size(file_size)}){Renkler.ENDC}")
                        
                        cursor = dropbox.files.UploadSessionCursor(
                            session_id=upload_session_start_result.session_id,
                            offset=f.tell()
                        )
                        commit = dropbox.files.CommitInfo(path=dropbox_path)
                        
                        # Kalan parçaları yükle
                        while f.tell() < file_size:
                            if (file_size - f.tell()) <= CHUNK_SIZE:
                                dbx.files_upload_session_finish(f.read(CHUNK_SIZE), cursor, commit)
                                yuklenen_boyut = file_size
                            else:
                                dbx.files_upload_session_append_v2(f.read(CHUNK_SIZE), cursor)
                                cursor.offset = f.tell()
                                yuklenen_boyut += CHUNK_SIZE
                            
                            logger.info(f"{Renkler.MAVI}Yükleniyor: %{(yuklenen_boyut/file_size*100):.1f} ({get_human_readable_size(yuklenen_boyut)}/{get_human_readable_size(file_size)}){Renkler.ENDC}")
                        
                        # Paylaşım linki oluştur
                        shared_link = dbx.sharing_create_shared_link(dropbox_path)
                        logger.info(f"{Renkler.YESIL}✅ Dosya başarıyla yüklendi: {file_name}{Renkler.ENDC}")
                        return shared_link.url
                        
                except Exception as e:
                    if deneme < MAX_RETRY - 1:
                        logger.warning(f"{Renkler.UYARI}Yükleme başarısız, yeniden deneniyor ({deneme + 1}/{MAX_RETRY}): {e}{Renkler.ENDC}")
                        await asyncio.sleep(RETRY_DELAY * (deneme + 1))
                    else:
                        raise
                        
    except Exception as e:
        logger.error(f"{Renkler.HATA}Dropbox'a yükleme hatası: {e}{Renkler.ENDC}")
        return None

async def varlik_kaydet_async(session, url_tam, kayit_yolu_tam, varlik_turu):
    """Belirtilen URL'den varlığı asenkron olarak indirir ve kaydeder."""
    MAX_RETRY = 5  # Maksimum deneme sayısı artırıldı
    RETRY_DELAY = 2  # Temel bekleme süresi artırıldı
    DOWNLOAD_TIMEOUT = 30  # İndirme zaman aşımı
    CHUNK_SIZE = 16384  # Chunk boyutu artırıldı (16KB)
    
    for deneme in range(MAX_RETRY):
        try:
            bekleme_suresi = RETRY_DELAY * (2 ** deneme)  # Üstel geri çekilme
            if deneme > 0:
                logger.info(f"{Renkler.MAVI}⏳ {bekleme_suresi} saniye bekleniyor... (Deneme {deneme + 1}/{MAX_RETRY}){Renkler.ENDC}")
                await asyncio.sleep(bekleme_suresi)
            
            logger.info(f"{Renkler.MAVI}📥 {varlik_turu} indiriliyor (Deneme {deneme + 1}/{MAX_RETRY}): {url_tam}{Renkler.ENDC}")
            
            async with session.get(url_tam, timeout=DOWNLOAD_TIMEOUT) as response:
                response.raise_for_status()
                content_length = response.headers.get('Content-Length')
                content_type = response.headers.get('Content-Type', '')
                
                # MIME type kontrolü
                if not content_type.startswith(('text/', 'image/', 'video/', 'audio/', 'application/')):
                    logger.warning(f"{Renkler.UYARI}⚠️ Desteklenmeyen içerik türü: {content_type}{Renkler.ENDC}")
                    return False
                
                # Dizin oluştur
                try:
                    os.makedirs(os.path.dirname(kayit_yolu_tam), exist_ok=True)
                except OSError as e:
                    logger.error(f"{Renkler.HATA}❌ Dizin oluşturulamadı ({os.path.dirname(kayit_yolu_tam)}): {e}{Renkler.ENDC}")
                    return False
                
                # Dosyayı kaydet
                try:
                    toplam_boyut = int(content_length) if content_length else None
                    indirilen_boyut = 0
                    
                    async with aiofiles.open(kayit_yolu_tam, 'wb') as f:
                        async for chunk in response.content.iter_chunked(CHUNK_SIZE):
                            await f.write(chunk)
                            indirilen_boyut += len(chunk)
                            
                            if toplam_boyut:
                                yuzde = (indirilen_boyut / toplam_boyut) * 100
                                if yuzde % 20 == 0:  # Her %20'de bir ilerleme göster
                                    logger.info(
                                        f"{Renkler.MAVI}📥 {varlik_turu} indiriliyor: "
                                        f"%{yuzde:.1f} ({get_human_readable_size(indirilen_boyut)}/{get_human_readable_size(toplam_boyut)})"
                                        f"{Renkler.ENDC}"
                                    )
                    
                    # Dosya boyutu kontrolü
                    if toplam_boyut and indirilen_boyut != toplam_boyut:
                        raise IOError(f"Eksik indirme: {indirilen_boyut}/{toplam_boyut} bayt")
                    
                    logger.info(
                        f"{Renkler.YESIL}✅ {varlik_turu} kaydedildi: {kayit_yolu_tam} "
                        f"({get_human_readable_size(indirilen_boyut)}){Renkler.ENDC}"
                    )
                    return True
                    
                except IOError as e:
                    logger.error(f"{Renkler.HATA}❌ {varlik_turu} dosyası yazılamadı ({kayit_yolu_tam}): {e}{Renkler.ENDC}")
                    # Yarım kalan dosyayı temizle
                    if os.path.exists(kayit_yolu_tam):
                        try:
                            os.remove(kayit_yolu_tam)
                            logger.info(f"{Renkler.UYARI}🗑️ Yarım kalan dosya temizlendi: {kayit_yolu_tam}{Renkler.ENDC}")
                        except Exception as e2:
                            logger.error(f"{Renkler.HATA}❌ Yarım kalan dosya temizlenemedi: {e2}{Renkler.ENDC}")
                    return False
                
        except aiohttp.ClientError as e:
            if deneme < MAX_RETRY - 1:
                logger.warning(f"{Renkler.UYARI}⚠️ {varlik_turu} indirilemedi: {e}{Renkler.ENDC}")
                continue
            else:
                logger.error(f"{Renkler.HATA}❌ {varlik_turu} indirilemedi ({url_tam}): {e}{Renkler.ENDC}")
        except asyncio.TimeoutError:
            if deneme < MAX_RETRY - 1:
                logger.warning(f"{Renkler.UYARI}⚠️ {varlik_turu} indirme zaman aşımı{Renkler.ENDC}")
                continue
            else:
                logger.error(f"{Renkler.HATA}❌ {varlik_turu} indirme zaman aşımı ({url_tam}){Renkler.ENDC}")
        except Exception as e:
            logger.error(f"{Renkler.HATA}❌ {varlik_turu} işlenirken beklenmeyen hata ({url_tam}): {e}{Renkler.ENDC}")
            break
    
    return False

async def css_varliklarini_isle_async(session, css_icerik, css_url_tam, kayit_dizini, indirilen_varliklar_global, ana_url):
    """CSS içeriğindeki url() varlıklarını asenkron indirir ve yolları günceller."""
    yeni_css_icerik = css_icerik
    ASSET_WAIT = 0.5  # Varlıklar arası bekleme süresi
    
    # CSS içindeki URL'leri bul (gelişmiş regex ile)
    url_patterns = [
        # Standart url() yapısı
        r'url\s*\((?:\s*[\'"]?\s*)([^\'"\)\s]+)(?:\s*[\'"]?\s*)\)',
        # @import url() yapısı
        r'@import\s+(?:url\s*\()?[\'"]?([^\'"\)\s]+)[\'"]?\)?',
        # Özel font-face src yapısı
        r'src:\s*(?:url\s*\()?[\'"]?([^\'"\)\s]+\.(?:woff2?|ttf|otf|eot))[\'"]?\)?'
    ]
    
    basarisiz_varliklar = []
    islenen_varlik_sayisi = 0
    toplam_varlik = sum(len(re.findall(pattern, css_icerik)) for pattern in url_patterns)
    
    logger.info(f"{Renkler.MAVI}🔍 CSS içeriğinde {toplam_varlik} varlık bulundu{Renkler.ENDC}")
    
    try:
        for pattern in url_patterns:
            for match in re.finditer(pattern, css_icerik):
                css_varlik_url_orjinal = match.group(1)
                if not css_varlik_url_orjinal.strip() or css_varlik_url_orjinal.startswith(('data:', '#', 'blob:', 'javascript:')):
                    continue
                
                islenen_varlik_sayisi += 1
                try:
                    css_varlik_url_tam = urljoin(css_url_tam, css_varlik_url_orjinal)
                    
                    # Cache kontrolü
                    if css_varlik_url_tam in indirilen_varliklar_global:
                        yerel_varlik_yolu_css_icin = indirilen_varliklar_global[css_varlik_url_tam]['css_relative_path']
                        logger.info(f"{Renkler.MAVI}♻️ CSS varlığı zaten indirilmiş (cache): {css_varlik_url_tam} -> {yerel_varlik_yolu_css_icin}{Renkler.ENDC}")
                    else:
                        # Varlık türünü belirle
                        uzanti = os.path.splitext(urlparse(css_varlik_url_tam).path)[1].lower()
                        varlik_turu_css, kayit_alt_dizini_css_varlik = "CSS_Varlik", 'assets'
                        
                        # Uzantıya göre varlık türünü ve dizinini belirle
                        if uzanti in ['.png', '.jpg', '.jpeg', '.gif', '.svg', '.webp', '.avif']:
                            varlik_turu_css, kayit_alt_dizini_css_varlik = "CSS_Resim", 'images'
                        elif uzanti in ['.woff', '.woff2', '.ttf', '.otf', '.eot']:
                            varlik_turu_css, kayit_alt_dizini_css_varlik = "CSS_Font", 'fonts'
                        elif uzanti in ['.css']:
                            varlik_turu_css, kayit_alt_dizini_css_varlik = "CSS_Import", 'css'
                        
                        # Dosya adını temizle ve kayıt yolunu oluştur
                        dosya_adi_css_varlik = dosya_ad_temizle(css_varlik_url_tam, varlik_turu_css)
                        tam_kayit_yolu_css_varlik = os.path.join(kayit_dizini, kayit_alt_dizini_css_varlik, dosya_adi_css_varlik)
                        
                        # Varlığı indir
                        logger.info(f"{Renkler.MAVI}📥 CSS varlığı indiriliyor ({islenen_varlik_sayisi}/{toplam_varlik}): {css_varlik_url_tam}{Renkler.ENDC}")
                        if await varlik_kaydet_async(session, css_varlik_url_tam, tam_kayit_yolu_css_varlik, varlik_turu_css):
                            # Yolları güncelle
                            css_dosyasinin_tam_kayit_yolu = indirilen_varliklar_global[css_url_tam]['local_path']
                            yerel_varlik_yolu_css_icin = os.path.relpath(
                                tam_kayit_yolu_css_varlik,
                                os.path.dirname(css_dosyasinin_tam_kayit_yolu)
                            ).replace("\\","/")
                            
                            # Global cache'e ekle
                            indirilen_varliklar_global[css_varlik_url_tam] = {
                                'local_path': tam_kayit_yolu_css_varlik,
                                'html_relative_path': os.path.join(kayit_alt_dizini_css_varlik, dosya_adi_css_varlik).replace("\\", "/"),
                                'css_relative_path': yerel_varlik_yolu_css_icin
                            }
                            
                            # İçe aktarılan CSS dosyasını da işle
                            if varlik_turu_css == "CSS_Import":
                                try:
                                    async with aiofiles.open(tam_kayit_yolu_css_varlik, 'r', encoding='utf-8') as f:
                                        import_css_icerik = await f.read()
                                    import_css_icerik = await css_varliklarini_isle_async(
                                        session, import_css_icerik, css_varlik_url_tam,
                                        kayit_dizini, indirilen_varliklar_global, ana_url
                                    )
                                    async with aiofiles.open(tam_kayit_yolu_css_varlik, 'w', encoding='utf-8') as f:
                                        await f.write(import_css_icerik)
                                except Exception as e:
                                    logger.error(f"{Renkler.HATA}❌ İçe aktarılan CSS işlenirken hata: {e}{Renkler.ENDC}")
                            
                            # Rate limiting
                            await asyncio.sleep(ASSET_WAIT)
                        else:
                            basarisiz_varliklar.append(css_varlik_url_tam)
                            continue
                    
                    # CSS içeriğini güncelle
                    orjinal_url_ifadesi = match.group(0)
                    if '@import' in orjinal_url_ifadesi.lower():
                        yeni_url_ifadesi = f'@import "{yerel_varlik_yolu_css_icin}"'
                    else:
                        yeni_url_ifadesi = f"url('{yerel_varlik_yolu_css_icin}')"
                    yeni_css_icerik = yeni_css_icerik.replace(orjinal_url_ifadesi, yeni_url_ifadesi, 1)
                    
                except Exception as e:
                    logger.error(f"{Renkler.HATA}❌ CSS varlığı işlenirken hata ({css_varlik_url_orjinal}): {e}{Renkler.ENDC}")
                    basarisiz_varliklar.append(css_varlik_url_orjinal)
                    continue
        
        # Başarısız varlıkları raporla
        if basarisiz_varliklar:
            logger.warning(
                f"{Renkler.UYARI}⚠️ {len(basarisiz_varliklar)} CSS varlığı indirilemedi:\n" +
                "\n".join([f"- {url}" for url in basarisiz_varliklar[:5]]) +
                ("\n..." if len(basarisiz_varliklar) > 5 else "") +
                f"\nToplam: {len(basarisiz_varliklar)}/{toplam_varlik} başarısız"
            )
        else:
            logger.info(f"{Renkler.YESIL}✅ Tüm CSS varlıkları başarıyla işlendi ({toplam_varlik} varlık){Renkler.ENDC}")
        
        return yeni_css_icerik
        
    except Exception as e:
        logger.error(f"{Renkler.HATA}❌ CSS içeriği işlenirken genel hata: {e}{Renkler.ENDC}")
        return css_icerik  # Hata durumunda orijinal içeriği döndür

async def varlik_indir_ve_yolu_guncelle_async(session, tag, attribute_name, varlik_turu, kayit_alt_dizini, ana_url, kayit_dizini, indirilen_varliklar_global):
    """HTML etiketlerindeki varlıkları asenkron indirir ve yollarını günceller."""
    try:
        if not tag.get(attribute_name):
            return

        varlik_url_orjinal = tag[attribute_name]
        if not varlik_url_orjinal.strip() or varlik_url_orjinal.startswith(('data:', '#', 'javascript:')):
            if varlik_url_orjinal.startswith('data:'):
                logger.info(f"{Renkler.UYARI}Data URI bulundu (HTML), indirme atlanıyor: {varlik_url_orjinal[:70]}...{Renkler.ENDC}")
            return

        try:
            varlik_url_tam = urljoin(ana_url, varlik_url_orjinal)
            if varlik_url_tam in indirilen_varliklar_global:
                logger.info(f"{Renkler.MAVI}{varlik_turu} zaten indirilmiş (cache): {varlik_url_tam}{Renkler.ENDC}")
                tag[attribute_name] = indirilen_varliklar_global[varlik_url_tam]['html_relative_path']
                return

            dosya_adi = dosya_ad_temizle(varlik_url_tam, varlik_turu)
            tam_kayit_yolu = os.path.join(kayit_dizini, kayit_alt_dizini, dosya_adi)
            
            if await varlik_kaydet_async(session, varlik_url_tam, tam_kayit_yolu, varlik_turu):
                yerel_yol_html_icin = os.path.join(kayit_alt_dizini, dosya_adi).replace("\\", "/")
                tag[attribute_name] = yerel_yol_html_icin
                
                # CSS dosyasıysa, içeriğini de işle
                if varlik_turu == 'CSS' and os.path.exists(tam_kayit_yolu):
                    logger.info(f"{Renkler.MAVI}CSS dosyası ({tam_kayit_yolu}) içerisindeki varlıklar işleniyor...{Renkler.ENDC}")
                    try:
                        async with aiofiles.open(tam_kayit_yolu, 'r', encoding='utf-8', errors='replace') as f_css:
                            css_icerik_orjinal = await f_css.read()
                        
                        indirilen_varliklar_global[varlik_url_tam] = {
                            'local_path': tam_kayit_yolu,
                            'html_relative_path': yerel_yol_html_icin,
                            'css_relative_path': ''
                        }
                        
                        guncellenmis_css_icerik = await css_varliklarini_isle_async(
                            session, css_icerik_orjinal, varlik_url_tam,
                            kayit_dizini, indirilen_varliklar_global, ana_url
                        )
                        
                        if guncellenmis_css_icerik != css_icerik_orjinal:
                            async with aiofiles.open(tam_kayit_yolu, 'w', encoding='utf-8') as f_css_write:
                                await f_css_write.write(guncellenmis_css_icerik)
                            logger.info(f"{Renkler.YESIL}CSS dosyası ({tam_kayit_yolu}) içindeki yollar güncellendi.{Renkler.ENDC}")
                    except Exception as e_css:
                        logger.error(f"{Renkler.HATA}CSS dosyası ({tam_kayit_yolu}) işlenirken hata: {e_css}{Renkler.ENDC}")
                else:
                    indirilen_varliklar_global[varlik_url_tam] = {
                        'local_path': tam_kayit_yolu,
                        'html_relative_path': yerel_yol_html_icin,
                        'css_relative_path': ''
                    }
                
                await asyncio.sleep(0.2)  # Rate limiting için kısa bekleme
                
        except Exception as e:
            logger.error(f"{Renkler.HATA}Varlık işlenirken hata ({varlik_url_orjinal}): {e}{Renkler.ENDC}")
            
    except Exception as e:
        logger.error(f"{Renkler.HATA}Varlık işleme sırasında beklenmeyen hata: {e}{Renkler.ENDC}")

async def siteyi_kopyala_async(url, site_kayit_dizini, session, indirilen_varliklar_tum_siteler, max_derinlik=1, mevcut_derinlik=0):
    """Belirli bir URL'yi ve alt sayfalarını asenkron olarak kopyalar."""
    logger.info(f"{Renkler.HEADER}🌐 Site kopyalama işlemi başlatılıyor (Derinlik {mevcut_derinlik}/{max_derinlik}): {url}{Renkler.ENDC}")
    
    MAX_RETRY = 5
    RETRY_DELAY = 3
    PAGE_LOAD_WAIT = 5  # Sayfa yüklenmesi için bekleme süresi
    
    # Sayfa yüklenmesi için bekleme
    logger.info(f"{Renkler.MAVI}⏳ Sayfa yüklenmesi için {PAGE_LOAD_WAIT} saniye bekleniyor...{Renkler.ENDC}")
    await asyncio.sleep(PAGE_LOAD_WAIT)
    
    try:
        for deneme in range(MAX_RETRY):
            try:
                logger.info(f"{Renkler.MAVI}📡 Sayfa indiriliyor (Deneme {deneme + 1}/{MAX_RETRY}): {url}{Renkler.ENDC}")
                async with session.get(url, timeout=60, allow_redirects=True) as response:
                    response.raise_for_status() 
                    current_url = str(response.url)
                    content = await response.text()
                    content_size = len(content)
                    logger.info(f"{Renkler.YESIL}✅ Sayfa başarıyla alındı ({get_human_readable_size(content_size)}). Son URL: {current_url}{Renkler.ENDC}")
                    
                    # İçerik yüklenmesi için ek bekleme
                    await asyncio.sleep(2)
                    break
            except aiohttp.ClientError as e:
                if deneme < MAX_RETRY - 1:
                    bekleme_suresi = RETRY_DELAY * (deneme + 1)
                    logger.warning(f"{Renkler.UYARI}⚠️ Sayfa alınamadı, {bekleme_suresi} saniye sonra yeniden deneniyor ({deneme + 1}/{MAX_RETRY}): {e}{Renkler.ENDC}")
                    await asyncio.sleep(bekleme_suresi)
                else:
                    raise
    except Exception as e:
        logger.error(f"{Renkler.HATA}❌ Sayfa alınamadı ({url}): {e}{Renkler.ENDC}")
        return False

    soup = BeautifulSoup(content, 'html.parser')
    
    # Dizinleri oluştur (ana site_kayit_dizini altında)
    alt_dizinler = ['css', 'js', 'images', 'fonts', 'assets'] 
    for dizin_adi_iter in alt_dizinler:
        tam_dizin_yolu = os.path.join(site_kayit_dizini, dizin_adi_iter)
        if not os.path.exists(tam_dizin_yolu):
            try:
                os.makedirs(tam_dizin_yolu)
                logger.info(f"{Renkler.MAVI}Dizin oluşturuldu: {tam_dizin_yolu}{Renkler.ENDC}")
            except OSError as e:
                logger.error(f"{Renkler.HATA}Dizin oluşturulamadı {tam_dizin_yolu}: {e}{Renkler.ENDC}")
                return False

    # Alt sayfaları topla
    alt_sayfalar = set()
    if mevcut_derinlik < max_derinlik:
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            if not href.startswith(('http://', 'https://', '//', '#', 'javascript:', 'mailto:', 'tel:')):
                tam_url = urljoin(current_url, href)
                parsed_tam_url = urlparse(tam_url)
                parsed_current_url = urlparse(current_url)
                if parsed_tam_url.netloc == parsed_current_url.netloc:
                    alt_sayfalar.add(tam_url)

    # Varlıkları işle (chunk'lara bölerek) - Kapsamlı kopyalama
    CHUNK_SIZE = 8  # Aynı anda işlenecek maksimum varlık sayısı (daha az yük için)
    ASSET_WAIT = 0.5  # Varlıklar arası bekleme süresi
    
    logger.info(f"{Renkler.MAVI}📦 Tüm varlıklar taranıyor ve indiriliyor...{Renkler.ENDC}")
    
    # CSS dosyaları
    css_tasks = []
    for link_tag in soup.find_all('link', rel='stylesheet'):
        css_tasks.append(varlik_indir_ve_yolu_guncelle_async(session, link_tag, 'href', 'CSS', 'css', current_url, site_kayit_dizini, indirilen_varliklar_tum_siteler))
    
    # Tüm link etiketleri (CSS, favicon, manifest, vb.)
    for link_tag in soup.find_all('link', href=True):
        rel_value = link_tag.get('rel', [])
        if isinstance(rel_value, str):
            rel_value = [rel_value]
        
        if 'icon' in rel_value or 'shortcut icon' in rel_value:
            css_tasks.append(varlik_indir_ve_yolu_guncelle_async(session, link_tag, 'href', 'Favicon', 'images', current_url, site_kayit_dizini, indirilen_varliklar_tum_siteler))
        elif 'manifest' in rel_value:
            css_tasks.append(varlik_indir_ve_yolu_guncelle_async(session, link_tag, 'href', 'Manifest', 'assets', current_url, site_kayit_dizini, indirilen_varliklar_tum_siteler))
        elif 'preload' in rel_value:
            as_value = link_tag.get('as', '')
            if as_value == 'font':
                css_tasks.append(varlik_indir_ve_yolu_guncelle_async(session, link_tag, 'href', 'Font', 'fonts', current_url, site_kayit_dizini, indirilen_varliklar_tum_siteler))
            elif as_value == 'image':
                css_tasks.append(varlik_indir_ve_yolu_guncelle_async(session, link_tag, 'href', 'PreloadImage', 'images', current_url, site_kayit_dizini, indirilen_varliklar_tum_siteler))
            elif as_value == 'script':
                css_tasks.append(varlik_indir_ve_yolu_guncelle_async(session, link_tag, 'href', 'PreloadJS', 'js', current_url, site_kayit_dizini, indirilen_varliklar_tum_siteler))
            elif as_value == 'style':
                css_tasks.append(varlik_indir_ve_yolu_guncelle_async(session, link_tag, 'href', 'PreloadCSS', 'css', current_url, site_kayit_dizini, indirilen_varliklar_tum_siteler))
    
    # Font dosyaları (ek kontroller)
    font_tasks = []
    for link_tag in soup.find_all('link', rel=lambda x: x and ('font' in str(x).lower() if x else False)):
        if link_tag.get('href'):
            font_tasks.append(varlik_indir_ve_yolu_guncelle_async(session, link_tag, 'href', 'Font', 'fonts', current_url, site_kayit_dizini, indirilen_varliklar_tum_siteler))
    
    # JavaScript dosyaları
    js_tasks = []
    for script_tag in soup.find_all('script', src=True):
        js_tasks.append(varlik_indir_ve_yolu_guncelle_async(session, script_tag, 'src', 'JS', 'js', current_url, site_kayit_dizini, indirilen_varliklar_tum_siteler))
    
    # Resimler ve medya dosyaları
    img_tasks = []
    for img_tag in soup.find_all('img'):
        if img_tag.get('src'):
            img_tasks.append(varlik_indir_ve_yolu_guncelle_async(session, img_tag, 'src', 'Resim', 'images', current_url, site_kayit_dizini, indirilen_varliklar_tum_siteler))
        if img_tag.get('data-src'):  # Lazy loading desteği
            img_tasks.append(varlik_indir_ve_yolu_guncelle_async(session, img_tag, 'data-src', 'LazyResim', 'images', current_url, site_kayit_dizini, indirilen_varliklar_tum_siteler))
        if img_tag.get('srcset'):
            yeni_srcset_degerleri = []
            for deger_blogu in img_tag['srcset'].split(','):
                deger_blogu_strip = deger_blogu.strip()
                parcalar = deger_blogu_strip.split(maxsplit=1)
                resim_url_orjinal_srcset = parcalar[0]
                descriptor = parcalar[1] if len(parcalar) > 1 else ""
                if not resim_url_orjinal_srcset.strip() or resim_url_orjinal_srcset.startswith(('data:', '#', 'javascript:')):
                    yeni_srcset_degerleri.append(deger_blogu_strip)
                    continue
                temp_tag = BeautifulSoup(f'<img src="{resim_url_orjinal_srcset}">', 'html.parser').img
                img_tasks.append(varlik_indir_ve_yolu_guncelle_async(session, temp_tag, 'src', 'Resim_Srcset', 'images', current_url, site_kayit_dizini, indirilen_varliklar_tum_siteler))
                if temp_tag.get('src') and temp_tag['src'] != resim_url_orjinal_srcset:
                    yeni_srcset_degerleri.append(f"{temp_tag['src']} {descriptor}")
                else:
                    yeni_srcset_degerleri.append(deger_blogu_strip)
            img_tag['srcset'] = ', '.join(yeni_srcset_degerleri)
    
    # Video ve audio dosyaları
    media_tasks = []
    for source_tag in soup.find_all('source'):
        if source_tag.get('src'):
            media_tasks.append(varlik_indir_ve_yolu_guncelle_async(session, source_tag, 'src', 'KaynakVarlik', 'assets', current_url, site_kayit_dizini, indirilen_varliklar_tum_siteler))
        if source_tag.get('srcset'):
            media_tasks.append(varlik_indir_ve_yolu_guncelle_async(session, source_tag, 'srcset', 'KaynakSrcset', 'assets', current_url, site_kayit_dizini, indirilen_varliklar_tum_siteler))
    
    for video_tag in soup.find_all('video'):
        if video_tag.get('poster'):
            media_tasks.append(varlik_indir_ve_yolu_guncelle_async(session, video_tag, 'poster', 'VideoPoster', 'images', current_url, site_kayit_dizini, indirilen_varliklar_tum_siteler))
        if video_tag.get('src'):
            media_tasks.append(varlik_indir_ve_yolu_guncelle_async(session, video_tag, 'src', 'Video', 'assets', current_url, site_kayit_dizini, indirilen_varliklar_tum_siteler))
    
    for audio_tag in soup.find_all('audio'):
        if audio_tag.get('src'):
            media_tasks.append(varlik_indir_ve_yolu_guncelle_async(session, audio_tag, 'src', 'Audio', 'assets', current_url, site_kayit_dizini, indirilen_varliklar_tum_siteler))
    
    # Embed ve object etiketleri
    for embed_tag in soup.find_all('embed'):
        if embed_tag.get('src'):
            media_tasks.append(varlik_indir_ve_yolu_guncelle_async(session, embed_tag, 'src', 'Embed', 'assets', current_url, site_kayit_dizini, indirilen_varliklar_tum_siteler))
    
    for object_tag in soup.find_all('object'):
        if object_tag.get('data'):
            media_tasks.append(varlik_indir_ve_yolu_guncelle_async(session, object_tag, 'data', 'Object', 'assets', current_url, site_kayit_dizini, indirilen_varliklar_tum_siteler))
    
    # iframe'ler (sadece aynı domain)
    for iframe_tag in soup.find_all('iframe'):
        if iframe_tag.get('src'):
            iframe_url = urljoin(current_url, iframe_tag['src'])
            iframe_parsed = urlparse(iframe_url)
            current_parsed = urlparse(current_url)
            if iframe_parsed.netloc == current_parsed.netloc:
                media_tasks.append(varlik_indir_ve_yolu_guncelle_async(session, iframe_tag, 'src', 'Iframe', 'assets', current_url, site_kayit_dizini, indirilen_varliklar_tum_siteler))
    
    # Inline stiller
    for tag_with_style in soup.find_all(style=True):
        style_content = tag_with_style['style']
        guncellenmis_style_content = await css_varliklarini_isle_async(session, style_content, current_url, site_kayit_dizini, indirilen_varliklar_tum_siteler, current_url)
        if guncellenmis_style_content != style_content:
            tag_with_style['style'] = guncellenmis_style_content
            logger.info(f"{Renkler.YESIL}Inline stil güncellendi: {tag_with_style.name}{Renkler.ENDC}")

    # Tüm görevleri birleştir ve chunk'lara bölerek işle
    tum_tasks = css_tasks + font_tasks + js_tasks + img_tasks + media_tasks
    toplam_varlik = len(tum_tasks)
    
    if toplam_varlik > 0:
        logger.info(f"{Renkler.MAVI}🔄 Toplam {toplam_varlik} varlık işlenecek{Renkler.ENDC}")
        
        for i in range(0, toplam_varlik, CHUNK_SIZE):
            chunk = tum_tasks[i:i + CHUNK_SIZE]
            chunk_no = (i // CHUNK_SIZE) + 1
            toplam_chunk = (toplam_varlik + CHUNK_SIZE - 1) // CHUNK_SIZE
            
            logger.info(f"{Renkler.MAVI}📦 Chunk {chunk_no}/{toplam_chunk} işleniyor ({len(chunk)} varlık)...{Renkler.ENDC}")
            
            # Her chunk'taki varlıkları işle
            chunk_results = await asyncio.gather(*chunk, return_exceptions=True)
            
            # Hataları kontrol et
            for j, result in enumerate(chunk_results):
                if isinstance(result, Exception):
                    logger.error(f"{Renkler.HATA}❌ Varlık indirme hatası (Chunk {chunk_no}, Varlık {i+j+1}): {result}{Renkler.ENDC}")
            
            # İlerleme durumunu göster
            islenmiş_varlik = min((i + CHUNK_SIZE), toplam_varlik)
            yuzde = (islenmiş_varlik / toplam_varlik) * 100
            logger.info(f"{Renkler.MAVI}📊 İlerleme: %{yuzde:.1f} ({islenmiş_varlik}/{toplam_varlik} varlık işlendi){Renkler.ENDC}")
            
            # Rate limiting ve sayfa yüklenmesi için bekleme
            if i + CHUNK_SIZE < toplam_varlik:  # Son chunk değilse bekle
                logger.info(f"{Renkler.MAVI}⏳ Sonraki chunk için {ASSET_WAIT} saniye bekleniyor...{Renkler.ENDC}")
                await asyncio.sleep(ASSET_WAIT)
    else:
        logger.info(f"{Renkler.MAVI}ℹ️ İndirilecek varlık bulunamadı{Renkler.ENDC}")

    # Ana HTML dosyasını kaydet
    try:
        sayfa_adi = 'index.html' if url.endswith('/') or url.endswith(current_url.split('/')[-1]) else f"{os.path.basename(current_url)}.html"
        ana_html_dosya_yolu = os.path.join(site_kayit_dizini, sayfa_adi)
        try:
            async with aiofiles.open(ana_html_dosya_yolu, 'w', encoding='utf-8') as f:
                await f.write(str(soup.prettify()))
            logger.info(f"{Renkler.YESIL}{Renkler.BOLD}✅ HTML dosyası kaydedildi: {ana_html_dosya_yolu}{Renkler.ENDC}")
        except IOError as e:
            logger.error(f"{Renkler.HATA}HTML dosyası yazılamadı ({ana_html_dosya_yolu}): {e}{Renkler.ENDC}")
            return False
        
        # Alt sayfaları işle
        if alt_sayfalar and mevcut_derinlik < max_derinlik:
            logger.info(f"{Renkler.MAVI}🔍 Alt sayfalar işleniyor... ({len(alt_sayfalar)} sayfa bulundu){Renkler.ENDC}")
            alt_sayfa_sonuclari = []
            basarisiz_sayfalar = []
            
            for alt_sayfa in alt_sayfalar:
                try:
                    alt_sayfa_sonucu = await siteyi_kopyala_async(
                        alt_sayfa, site_kayit_dizini, session,
                        indirilen_varliklar_tum_siteler,
                        max_derinlik, mevcut_derinlik + 1
                    )
                    alt_sayfa_sonuclari.append(alt_sayfa_sonucu)
                    if not alt_sayfa_sonucu:
                        basarisiz_sayfalar.append(alt_sayfa)
                except Exception as e:
                    logger.error(f"{Renkler.HATA}Alt sayfa işlenirken hata ({alt_sayfa}): {e}{Renkler.ENDC}")
                    basarisiz_sayfalar.append(alt_sayfa)
                
                await asyncio.sleep(0.1)  # Rate limiting için kısa bekleme
            
            if basarisiz_sayfalar:
                logger.warning(
                    f"{Renkler.UYARI}⚠️ {len(basarisiz_sayfalar)} alt sayfa kopyalanamadı:\n" +
                    "\n".join([f"- {url}" for url in basarisiz_sayfalar[:5]]) +
                    ("\n..." if len(basarisiz_sayfalar) > 5 else "") +
                    f"\nToplam: {len(basarisiz_sayfalar)}/{len(alt_sayfalar)} başarısız{Renkler.ENDC}"
                )
        
        # ZIP arşivi oluştur
        if mevcut_derinlik == 0:  # Sadece ana işlem için ZIP oluştur
            zip_path = f"{site_kayit_dizini}.zip"
            if create_zip_archive(site_kayit_dizini, zip_path):
                logger.info(f"{Renkler.YESIL}📦 ZIP arşivi oluşturuldu: {zip_path}{Renkler.ENDC}")
            else:
                logger.warning(f"{Renkler.UYARI}⚠️ ZIP arşivi oluşturulamadı: {zip_path}{Renkler.ENDC}")
        
        return True
    except IOError as e:
        logger.error(f"{Renkler.HATA}HTML dosyası ({url}) yazılamadı: {e}{Renkler.ENDC}")
        return False

def create_zip_archive(source_dir, output_zip_file):
    """Belirtilen dizini ve içeriğini bir ZIP dosyasına sıkıştırır."""
    if not os.path.exists(source_dir):
        logger.error(f"{Renkler.HATA}Kaynak dizin bulunamadı: {source_dir}{Renkler.ENDC}")
        return False
        
    try:
        total_size = sum(os.path.getsize(os.path.join(root, file))
                        for root, _, files in os.walk(source_dir)
                        for file in files)
        processed_size = 0
        
        logger.info(f"{Renkler.MAVI}📦 {source_dir} dizini {output_zip_file} olarak sıkıştırılıyor... (Toplam: {get_human_readable_size(total_size)}){Renkler.ENDC}")
        
        with zipfile.ZipFile(output_zip_file, 'w', zipfile.ZIP_DEFLATED) as zipf:
            for root, _, files in os.walk(source_dir):
                for file in files:
                    try:
                        file_path = os.path.join(root, file)
                        file_size = os.path.getsize(file_path)
                        
                        # Arşiv içindeki yol, source_dir'e göreceli olmalı
                        archive_name = os.path.relpath(file_path, os.path.join(source_dir, '..'))
                        zipf.write(file_path, archive_name)
                        
                        processed_size += file_size
                        progress = (processed_size / total_size) * 100
                        logger.info(f"{Renkler.MAVI}Sıkıştırılıyor: %{progress:.1f} ({get_human_readable_size(processed_size)}/{get_human_readable_size(total_size)}){Renkler.ENDC}")
                        
                    except Exception as e:
                        logger.warning(f"{Renkler.UYARI}Dosya sıkıştırılamadı ({file_path}): {e}{Renkler.ENDC}")
                        continue
                        
        final_size = os.path.getsize(output_zip_file)
        compression_ratio = (1 - (final_size / total_size)) * 100
        logger.info(
            f"{Renkler.YESIL}✅ ZIP arşivi başarıyla oluşturuldu:\n"
            f"📁 Kaynak boyutu: {get_human_readable_size(total_size)}\n"
            f"📦 Arşiv boyutu: {get_human_readable_size(final_size)}\n"
            f"📊 Sıkıştırma oranı: %{compression_ratio:.1f}{Renkler.ENDC}"
        )
        return True
        
    except Exception as e:
        logger.error(f"{Renkler.HATA}ZIP arşivi oluşturulurken hata: {e}{Renkler.ENDC}")
        if os.path.exists(output_zip_file):
            try:
                os.remove(output_zip_file)
                logger.info(f"{Renkler.UYARI}Hatalı ZIP dosyası temizlendi: {output_zip_file}{Renkler.ENDC}")
            except Exception as e2:
                logger.error(f"{Renkler.HATA}Hatalı ZIP dosyası temizlenemedi: {e2}{Renkler.ENDC}")
        return False

import unittest
import shutil

class TestPoutyuf(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.test_url = "https://example.com"
        self.test_dir = "test_kayit"
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)
        os.makedirs(self.test_dir, exist_ok=True)
        self.session = aiohttp.ClientSession(headers={'User-Agent': get_random_user_agent()})

    async def asyncTearDown(self):
        await self.session.close()
        if os.path.exists(self.test_dir):
            shutil.rmtree(self.test_dir)

    async def test_siteyi_kopyala_async(self):
        indirilen_varliklar = {}
        result = await siteyi_kopyala_async(self.test_url, self.test_dir, self.session, indirilen_varliklar)
        self.assertTrue(result)
        index_path = os.path.join(self.test_dir, "index.html")
        self.assertTrue(os.path.exists(index_path))

    async def test_varlik_kaydet_async(self):
        url = "https://www.example.com/favicon.ico"
        kayit_yolu = os.path.join(self.test_dir, "favicon.ico")
        result = await varlik_kaydet_async(self.session, url, kayit_yolu, "Resim")
        self.assertTrue(result)
        self.assertTrue(os.path.exists(kayit_yolu))

    def test_create_zip_archive(self):
        """ZIP arşivi oluşturma fonksiyonunu test eder."""
        zip_path = os.path.join(self.test_dir, "test_archive.zip")
        
        # Test için çeşitli dosyalar oluştur
        test_files = {
            "text.txt": "Test içeriği\n" * 100,
            "data.json": '{"test": "data"}' * 1000,
            "subdir/nested.txt": "Alt dizindeki dosya",
            "subdir/deep/file.txt": "Derin dizindeki dosya"
        }
        
        # Test dosyalarını oluştur
        for file_path, content in test_files.items():
            full_path = os.path.join(self.test_dir, file_path)
            os.makedirs(os.path.dirname(full_path), exist_ok=True)
            with open(full_path, "w", encoding="utf-8") as f:
                f.write(content)
        
        # ZIP oluştur ve test et
        result = create_zip_archive(self.test_dir, zip_path)
        self.assertTrue(result)
        self.assertTrue(os.path.exists(zip_path))
        
        # ZIP içeriğini kontrol et
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_files = zip_ref.namelist()
            for file_path in test_files.keys():
                self.assertIn(file_path.replace('\\', '/'), zip_files)
        
        # Sıkıştırma oranını kontrol et
        uncompressed_size = sum(os.path.getsize(os.path.join(self.test_dir, f)) 
                              for f in test_files.keys())
        compressed_size = os.path.getsize(zip_path)
        self.assertLess(compressed_size, uncompressed_size)
        
        # Hata durumlarını test et
        self.assertFalse(create_zip_archive("nonexistent_dir", "error.zip"))
        self.assertFalse(os.path.exists("error.zip"))

    async def test_siteyi_kopyala_invalid_url(self):
        indirilen_varliklar = {}
        invalid_url = "http://invalid.url.test"
        result = await siteyi_kopyala_async(invalid_url, self.test_dir, self.session, indirilen_varliklar)
        self.assertFalse(result)

    async def test_varlik_kaydet_invalid_url(self):
        invalid_url = "http://invalid.url.test/favicon.ico"
        kayit_yolu = os.path.join(self.test_dir, "favicon.ico")
        result = await varlik_kaydet_async(self.session, invalid_url, kayit_yolu, "Resim")
        self.assertFalse(result)

    async def test_varlik_kaydet_invalid_path(self):
        url = "https://www.example.com/favicon.ico"
        invalid_path = "/invalid_path/favicon.ico"
        result = await varlik_kaydet_async(self.session, url, invalid_path, "Resim")
        self.assertFalse(result)

    async def test_proxy_and_ssl(self):
        # Bu test, çalışan bir proxy sunucusu (örn: http://127.0.0.1:3128) ve
        # SSL doğrulamasının (artık varsayılan olarak etkin) nasıl çalıştığını test etmeyi amaçlar.
        # Gerçek bir proxy olmadan bu testin proxy kısmı tam olarak doğrulanamaz.
        # `trust_env=True` kullanıldığı için, test ortamında HTTP_PROXY ve HTTPS_PROXY
        # ortam değişkenleri ayarlanarak test edilebilir.
        # Şimdilik, temel bağlantıyı ve SSL'in (varsayılan) durumunu kontrol edelim.
        # proxy_url = os.environ.get("TEST_HTTP_PROXY") # Test için ortam değişkeni kullanılabilir
        connector = aiohttp.TCPConnector() # Varsayılan SSL
        async with aiohttp.ClientSession(connector=connector, headers={'User-Agent': get_random_user_agent()}, trust_env=True) as session:
            # if proxy_url:
            #     session.proxy = proxy_url # Bu şekilde proxy set edilmez, ya get içinde ya da env ile
            indirilen_varliklar = {}
            result = await siteyi_kopyala_async("https://example.com", self.test_dir, session, indirilen_varliklar)
            self.assertTrue(result) # example.com'a SSL ile erişilebilmeli

    async def test_alt_alan_adi_tarama(self):
        """Alt alan adı tarama özelliğini test eder."""
        # Geçerli domain için test
        alt_alan_adlari = await alt_alan_adlarini_bul("example.com")
        self.assertIsInstance(alt_alan_adlari, list)
        
        # Boş domain için test
        bos_sonuc = await alt_alan_adlarini_bul("")
        self.assertEqual(bos_sonuc, [])
        
        # Geçersiz domain için test
        gecersiz_sonuc = await alt_alan_adlarini_bul("invalid.domain.test")
        self.assertEqual(gecersiz_sonuc, [])
        
        # Özel karakterli domain için test
        ozel_sonuc = await alt_alan_adlarini_bul("example-site.com")
        self.assertIsInstance(ozel_sonuc, list)
        
        # Alt alan adı formatını kontrol et
        if alt_alan_adlari:
            for domain in alt_alan_adlari:
                # Alan adı formatını kontrol et (örn: sub.example.com)
                self.assertRegex(domain, r'^[a-zA-Z0-9-]+\.example\.com$')
                # www olmadığını kontrol et
                self.assertNotEqual(domain, "www.example.com")
        
    async def test_dropbox_yukleme(self):
        """Dropbox yükleme özelliğini test eder."""
        # Test dosyaları hazırla
        test_files = {
            "small.txt": "Test içeriği" * 100,  # Küçük dosya
            "medium.txt": "Test içeriği" * 10000,  # Orta boy dosya
            "large.txt": "Test içeriği" * 100000,  # Büyük dosya
        }
        
        for file_name, content in test_files.items():
            test_file = os.path.join(self.test_dir, file_name)
            with open(test_file, "w", encoding="utf-8") as f:
                f.write(content)
            
            # Dropbox yükleme testi
            result = await buyuk_dosyayi_buluta_yukle(test_file)
            
            if os.environ.get("DROPBOX_ACCESS_TOKEN"):
                # Token varsa başarılı yükleme beklenir
                self.assertIsNotNone(result)
                self.assertTrue(result.startswith("https://"))
                self.assertIn("dropbox.com", result)
            else:
                # Token yoksa None dönmeli
                self.assertIsNone(result)
        
        # Geçersiz dosya yolu testi
        invalid_result = await buyuk_dosyayi_buluta_yukle("nonexistent.txt")
        self.assertIsNone(invalid_result)
        
        # Boş dosya testi
        empty_file = os.path.join(self.test_dir, "empty.txt")
        with open(empty_file, "w") as f:
            pass
        empty_result = await buyuk_dosyayi_buluta_yukle(empty_file)
        if os.environ.get("DROPBOX_ACCESS_TOKEN"):
            self.assertIsNotNone(empty_result)
        else:
            self.assertIsNone(empty_result)
            
    async def test_coklu_site_kopyalama(self):
        """Çoklu site ve alt alan adı kopyalama özelliğini test eder."""
        test_cases = {
            "ana_site": {
                "url": "https://example.com",
                "derinlik": 2,
                "beklenen_dosyalar": ["index.html", "css", "js", "images"]
            },
            "alt_site": {
                "url": "https://blog.example.com",
                "derinlik": 1,
                "beklenen_dosyalar": ["index.html"]
            },
            "ozel_karakterli": {
                "url": "https://test-site.example.com",
                "derinlik": 1,
                "beklenen_dosyalar": ["index.html"]
            }
        }
        
        indirilen_varliklar = {}
        connector = aiohttp.TCPConnector()
        
        async with aiohttp.ClientSession(connector=connector, headers={'User-Agent': get_random_user_agent()}, trust_env=True) as session:
            for test_name, test_data in test_cases.items():
                # Test klasörünü hazırla
                site_klasor = os.path.join(self.test_dir, test_name)
                os.makedirs(site_klasor, exist_ok=True)
                
                # Siteyi kopyala
                result = await siteyi_kopyala_async(
                    test_data["url"],
                    site_klasor,
                    session,
                    indirilen_varliklar,
                    max_derinlik=test_data["derinlik"]
                )
                
                # Sonuçları kontrol et
                if result:
                    # Beklenen dosya ve klasörleri kontrol et
                    for beklenen in test_data["beklenen_dosyalar"]:
                        self.assertTrue(
                            os.path.exists(os.path.join(site_klasor, beklenen)),
                            f"{test_name}: {beklenen} bulunamadı"
                        )
                    
                    # HTML dosyasının içeriğini kontrol et
                    html_path = os.path.join(site_klasor, "index.html")
                    if os.path.exists(html_path):
                        async with aiofiles.open(html_path, 'r', encoding='utf-8') as f:
                            content = await f.read()
                            self.assertIn("<html", content.lower())
                            self.assertIn("</html>", content.lower())
                
                # Cache kontrolü
                self.assertIsInstance(indirilen_varliklar, dict)
                if result:
                    self.assertGreater(len(indirilen_varliklar), 0)
            
            # Geçersiz URL testi
            invalid_result = await siteyi_kopyala_async(
                "https://invalid.example.test",
                os.path.join(self.test_dir, "invalid"),
                session,
                indirilen_varliklar,
                max_derinlik=1
            )
            self.assertFalse(invalid_result)
            
            # Alt alan adı tarama ve kopyalama testi
            alt_alan_adlari = await alt_alan_adlarini_bul("example.com")
            if alt_alan_adlari:
                for alt_alan in alt_alan_adlari[:2]:  # İlk 2 alt alan adını test et
                    alt_alan_url = f"https://{alt_alan}"
                    alt_alan_klasor = os.path.join(self.test_dir, alt_alan.replace('.', '_'))
                    result = await siteyi_kopyala_async(
                        alt_alan_url,
                        alt_alan_klasor,
                        session,
                        indirilen_varliklar,
                        max_derinlik=1
                    )
                    self.assertIsInstance(result, bool)
                    if result:
                        self.assertTrue(os.path.exists(os.path.join(alt_alan_klasor, "index.html")))

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == 'test':
        unittest.main(argv=sys.argv[:1])
    else:
        asyncio.run(main_bot())
