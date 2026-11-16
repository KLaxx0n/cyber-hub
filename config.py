import os
import secrets
from dotenv import load_dotenv

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(BASE_DIR, '.env'), override=True)

class Config:
    # Güçlü gizli anahtar (Varsayılan tahmin edilebilir anahtar kaldırıldı)
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
    # Veritabanı Yapılandırması (PostgreSQL veya SQLite)
    _db_url = os.environ.get('DATABASE_URL')
    if _db_url and _db_url.startswith('postgres://'):
        _db_url = _db_url.replace('postgres://', 'postgresql://', 1)
    
    _sqlite_custom_path = os.environ.get('SQLITE_PATH')
    if _sqlite_custom_path:
        SQLALCHEMY_DATABASE_URI = _db_url or f'sqlite:///{_sqlite_custom_path}'
    else:
        SQLALCHEMY_DATABASE_URI = _db_url or f'sqlite:///{os.path.join(BASE_DIR, "cyberhub.db")}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    TEMPLATES_AUTO_RELOAD = True
    
    # Çerez Güvenlik Ayarları
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    
    # CSRF Koruma Ayarları
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600

    # E-Posta / SMTP Ayarları
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME') or 'gsefa5683@gmail.com'
    import base64
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD') or base64.b64decode('cXp1eHZncWxibmZmbXVmaQ==').decode()
