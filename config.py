import os
import secrets
from datetime import timedelta
from dotenv import load_dotenv

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
load_dotenv(os.path.join(BASE_DIR, '.env'), override=True)

class Config:
    # Kalıcı ve sabit gizli anahtar (Oturumların deploylarda düşmesini önler)
    SECRET_KEY = os.environ.get('SECRET_KEY') or "94c7a6f23b12850d754162e24e1d90479b422116da3e58fa266850bbdb7a7407"
    
    # Oturumların Kapanmaması İçin Kalıcı Oturum Ayarları (1 Yıl)
    PERMANENT_SESSION_LIFETIME = timedelta(days=365)
    SESSION_COOKIE_NAME = 'cyberhub_session'
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'
    REMEMBER_COOKIE_DURATION = timedelta(days=365)
    
    # Veritabanı Yapılandırması (PostgreSQL veya SQLite)
    _db_url = os.environ.get('DATABASE_URL')
    if _db_url:
        if _db_url.startswith('postgres://'):
            _db_url = _db_url.replace('postgres://', 'postgresql+psycopg2://', 1)
        elif _db_url.startswith('postgresql://') and not _db_url.startswith('postgresql+'):
            _db_url = _db_url.replace('postgresql://', 'postgresql+psycopg2://', 1)
    
    _sqlite_custom_path = os.environ.get('SQLITE_PATH')
    if _sqlite_custom_path:
        SQLALCHEMY_DATABASE_URI = _db_url or f'sqlite:///{_sqlite_custom_path}'
    else:
        SQLALCHEMY_DATABASE_URI = _db_url or f'sqlite:///{os.path.join(BASE_DIR, "cyberhub.db")}'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    TEMPLATES_AUTO_RELOAD = True
    
    # CSRF Koruma Ayarları
    WTF_CSRF_ENABLED = True
    WTF_CSRF_TIME_LIMIT = 3600

    # E-Posta / SMTP ve HTTP API Ayarları
    BREVO_API_KEY = os.environ.get('BREVO_API_KEY')
    RESEND_API_KEY = os.environ.get('RESEND_API_KEY')
    MAIL_SERVER = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = True
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME') or 'cyberhubsecurity.tr@gmail.com'
    import base64
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD') or base64.b64decode('ZW1mZHVnZWdkd3dycnRidQ==').decode()
