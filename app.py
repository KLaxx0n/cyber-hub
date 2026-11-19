import os
import re
import importlib
import secrets
import string
import hmac
import io
import base64
import pyotp
import qrcode
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlsplit

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_from_directory
from flask_wtf.csrf import CSRFProtect, CSRFError
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.middleware.proxy_fix import ProxyFix
from sqlalchemy import func

from config import Config
from models import db, User, Lab, UserLabProgress, LabWriteup, CyberEvent, UserFeedback
from seed_data import seed_database
from mail_service import send_verification_email, send_password_reset_email, send_feedback_notification_email
from lab_configs import MULTI_TASK_LABS, get_public_tasks
import team_config

SUPPORT_EMAIL = 'cyberhubsecurity.tr@gmail.com'

_team_config_mtime = None

def _load_team_context():
    global _team_config_mtime
    cfg_path = getattr(team_config, '__file__', None)
    if cfg_path and os.path.exists(cfg_path):
        mtime = os.path.getmtime(cfg_path)
        if _team_config_mtime is None:
            _team_config_mtime = mtime
        elif mtime != _team_config_mtime:
            importlib.reload(team_config)
            _team_config_mtime = mtime
    return team_config.get_team_context()

app = Flask(__name__)
app.config.from_object(Config)

# Render / Ters Proxy Desteği (HTTPS ve gerçek IP tespiti)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# Güvenlik Eklentileri
csrf = CSRFProtect(app)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["1000 per day", "200 per hour"],
    storage_uri="memory://"
)

db.init_app(app)

SUSPENDED_BLOCK_MSG = '🚨 Hesabınız askıya alınmıştır ve şu an giriş yapılamaz! Askıyı yalnızca Root (Süper Yönetici) kaldırabilir.'


def _find_user_by_login(login_id, allow_email_prefix=False):
    """Find a user by exact username/email first, optionally falling back to email prefix match."""
    clean = (login_id or '').strip().lower()
    if not clean:
        return None
    user = User.query.filter(
        (func.lower(User.username) == clean) |
        (func.lower(User.email) == clean)
    ).first()
    if user or not allow_email_prefix:
        return user
    return User.query.filter(func.lower(User.email).like(f"{clean}@%")).first()


def _reject_suspended_user():
    """Clear active session and block access for suspended accounts."""
    session.clear()
    if request.is_json or request.path.startswith('/api/'):
        return jsonify({'success': False, 'message': SUSPENDED_BLOCK_MSG}), 403
    flash(SUSPENDED_BLOCK_MSG, 'danger')
    return redirect(url_for('login'))

@app.before_request
def ensure_permanent_session():
    session.permanent = True
    if request.endpoint == 'static':
        return None
    uid = session.get('user_id')
    if uid:
        user = User.query.get(uid)
        if not user:
            session.clear()
            return None
        if user.is_suspended:
            return _reject_suspended_user()

@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    flash('Güvenlik oturumu yenilendi. Lütfen işlemi tekrar deneyin.', 'info')
    return redirect(request.referrer or url_for('index'))

# Ensure database tables and initial seed data exist
with app.app_context():
    seed_database(app)

# Helper: Open Redirect Koruması İçin Güvenli URL Denetimi
def is_safe_url(target):
    if not target:
        return False
    if target.startswith('/') and not target.startswith('//'):
        return True
    ref_url = urlsplit(request.host_url)
    test_url = urlsplit(target)
    return test_url.scheme in ('http', 'https') and ref_url.netloc == test_url.netloc

# Helper: Ayrılmış / Yasaklı Kullanıcı Adları
RESERVED_USERNAMES = {'admin', 'administrator', 'root', 'system', 'superuser', 'founder', 'moderator', 'support', 'sefa_admin', 'aziz_red'}

def _require_active_user(expired_msg='Oturum süreniz dolmuş veya hesap bulunamadı. Lütfen tekrar giriş yapınız.'):
    """Return active User for current session, or a Flask redirect/JSON response."""
    if 'user_id' not in session:
        msg = 'Bu sayfayı görüntülemek için lütfen önce giriş yapınız.'
        if request.is_json or request.path.startswith('/api/'):
            return None, (jsonify({'success': False, 'message': msg}), 401)
        flash(msg, 'warning')
        return None, redirect(url_for('login', next=request.url))
    user = User.query.get(session['user_id'])
    if not user:
        session.clear()
        if request.is_json or request.path.startswith('/api/'):
            return None, (jsonify({'success': False, 'message': expired_msg}), 401)
        flash(expired_msg, 'warning')
        return None, redirect(url_for('login'))
    if user.is_suspended:
        return None, _reject_suspended_user()
    return user, None

# Helper: Login Required Decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user, err_resp = _require_active_user()
        if err_resp is not None:
            return err_resp
        return f(*args, **kwargs)
    return decorated_function

# Helper: Lab Access Required Decorator (Blocks 'unregistered' / Kayıtsız role from labs)
def lab_access_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user, err_resp = _require_active_user()
        if err_resp is not None:
            return err_resp
        if user.is_unregistered:
            msg = 'Laboratuvarlara erişim izniniz yok. Hesabınız "Kayıtsız" rolünde olduğu için yöneticinin rolünüzü "Öğrenci" olarak onaylaması gerekmektedir.'
            if request.is_json or request.path.startswith('/api/'):
                return jsonify({'success': False, 'message': msg}), 403
            flash(msg, 'warning')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Helper: Leader Required Decorator (Team Leaders & SuperAdmins)
def leader_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user, err_resp = _require_active_user('Oturum geçersiz. Lütfen tekrar giriş yapınız.')
        if err_resp is not None:
            return err_resp
        if not user.is_team_leader:
            flash('Bu sayfaya erişim yetkiniz bulunmamaktadır. Yalnızca Takım Liderleri ve Süper Yöneticiler görüntüleyebilir.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Helper: SuperAdmin / Root Required Decorator (Highest Authority)
def superadmin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        user, err_resp = _require_active_user('Oturum geçersiz. Lütfen tekrar giriş yapınız.')
        if err_resp is not None:
            return err_resp
        if not user.is_superadmin:
            flash('Bu kritik işlem için yetkiniz yetersiz. Yalnızca Süper Yönetici (Root) gerçekleştirebilir.', 'danger')
            return redirect(url_for('admin_panel'))
        return f(*args, **kwargs)
    return decorated_function

# Context Processor for Nav and Auth State
@app.context_processor
def inject_user():
    current_user = None
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if not user or user.is_suspended:
            session.clear()
        else:
            current_user = user
    return dict(current_user=current_user, support_email=SUPPORT_EMAIL)

# HTTP Güvenlik Başlıkları (Security Headers)
@app.after_request
def set_security_headers(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    return response

# Rate Limit Hata Yakalayıcı (429 Too Many Requests)
@app.errorhandler(429)
def ratelimit_handler(e):
    if request.is_json or request.path.startswith('/api/'):
        return jsonify({'success': False, 'message': 'Çok fazla istek yapıldı. Lütfen biraz bekleyip tekrar deneyin.'}), 429
    flash('Kısa süre içinde çok fazla işlem denemesi yapıldı. Güvenliğiniz için lütfen biraz bekleyiniz.', 'danger')
    return redirect(url_for('index'))

# Helper: Password Complexity Check (en az 1 harf ve 1 rakam)
def validate_password_complexity(password):
    if len(password) < 6:
        return False, "Şifre en az 6 karakter uzunluğunda olmalıdır."
    if not re.search(r'[A-Za-z]', password):
        return False, "Şifre en az bir harf (a-z veya A-Z) içermelidir."
    if not re.search(r'\d', password):
        return False, "Şifre en az bir rakam (0-9) içermelidir."
    return True, "Şifre kurallara uygundur."

# Helper: Kriptografik Olarak Güvenli 6 Haneli Doğrulama Kodu Üretici
def generate_verification_code():
    chars = string.ascii_uppercase + string.digits
    return ''.join(secrets.choice(chars) for _ in range(6))

# ----------------- ROUTES ----------------- #

@app.route('/health')
def health_check():
    return jsonify(status="healthy", service="cyber-hub"), 200

def _get_platform_stats():
    total_users = User.query.filter_by(is_verified=True).count()
    red_labs = Lab.query.filter_by(category='red_team', is_published=True).count()
    blue_labs = Lab.query.filter_by(category='blue_team', is_published=True).count()
    purple_labs = Lab.query.filter_by(category='purple_team', is_published=True).count()
    total_labs = red_labs + blue_labs + purple_labs
    return {
        'total_users': total_users,
        'total_labs': total_labs,
        'red_labs': red_labs,
        'blue_labs': blue_labs,
        'purple_labs': purple_labs,
    }

@app.route('/')
def index():
    stats = _get_platform_stats()
    top_users = User.query.filter_by(is_verified=True).order_by(User.score.desc()).limit(5).all()
    team_ctx = _load_team_context()
    recent_feedbacks = UserFeedback.query.filter_by(is_public=True).order_by(UserFeedback.created_at.desc()).limit(4).all()
    feedback_count = UserFeedback.query.filter_by(is_public=True).count()
    return render_template('index.html',
                           **stats,
                           top_users=top_users,
                           team_ctx=team_ctx,
                           recent_feedbacks=recent_feedbacks,
                           feedback_count=feedback_count)

@app.route('/biz-kimiz')
def biz_kimiz():
    stats = _get_platform_stats()
    team_ctx = _load_team_context()
    return render_template('biz_kimiz.html', **stats, **team_ctx)

@app.route('/about')
def about():
    return redirect(url_for('biz_kimiz'))

FEEDBACK_CATEGORIES = ('Öneri', 'Hata Bildirimi', 'Yeni Lab Talebi', 'Teşekkür & Yorum', 'Genel')

@app.route('/geri-bildirim', methods=['GET', 'POST'])
@limiter.limit("12 per minute")
def feedback_page():
    active_user = None
    if 'user_id' in session:
        active_user = User.query.get(session['user_id'])

    if request.method == 'POST':
        sender_name = request.form.get('sender_name', '').strip()
        if not sender_name and active_user:
            sender_name = active_user.username
        sender_email = request.form.get('sender_email', '').strip().lower()
        category = request.form.get('category', 'Genel').strip()
        if category not in FEEDBACK_CATEGORIES:
            category = 'Genel'
        try:
            rating = max(1, min(5, int(request.form.get('rating', 5))))
        except (TypeError, ValueError):
            rating = 5
        message = request.form.get('message', '').strip()
        is_public = request.form.get('is_public') == 'on'

        form_data = {
            'sender_name': sender_name,
            'sender_email': sender_email,
            'category': category,
            'rating': rating,
            'message': message,
            'is_public': is_public,
        }

        if len(sender_name) < 2 or len(sender_name) > 80:
            flash('Lütfen adınızı veya kullanıcı adınızı (2-80 karakter) giriniz.', 'danger')
        elif sender_email and (len(sender_email) > 120 or '@' not in sender_email or '.' not in sender_email.split('@')[-1]):
            flash('Lütfen geçerli bir e-posta adresi giriniz veya alanı boş bırakınız.', 'danger')
        elif len(message) < 5 or len(message) > 1500:
            flash('Geri bildirim mesajınız en az 5, en fazla 1500 karakter olmalıdır.', 'danger')
        else:
            fb = UserFeedback(
                user_id=active_user.id if active_user else None,
                sender_name=sender_name,
                sender_email=sender_email or None,
                category=category,
                rating=rating,
                message=message,
                is_public=is_public,
            )
            db.session.add(fb)
            db.session.commit()

            mail_sent, _ = send_feedback_notification_email(
                sender_name=sender_name,
                sender_email=sender_email,
                category=category,
                rating=rating,
                message=message,
                target_email=SUPPORT_EMAIL,
            )
            if mail_sent:
                flash(f'Geri bildiriminiz alındı ve {SUPPORT_EMAIL} adresimize iletildi. Teşekkür ederiz!', 'success')
            else:
                flash(f'Geri bildiriminiz platforma kaydedildi! Doğrudan e-posta atmak isterseniz {SUPPORT_EMAIL} adresini kullanabilirsiniz.', 'success')
            return redirect(url_for('feedback_page') + '#geri-donusler')

        feedbacks = UserFeedback.query.filter_by(is_public=True).order_by(UserFeedback.created_at.desc()).limit(50).all()
        avg_rating = round(sum(f.rating or 5 for f in feedbacks) / len(feedbacks), 1) if feedbacks else 0
        return render_template('feedback.html',
                               feedbacks=feedbacks,
                               feedback_count=len(feedbacks),
                               avg_rating=avg_rating,
                               categories=FEEDBACK_CATEGORIES,
                               form_data=form_data)

    feedbacks = UserFeedback.query.filter_by(is_public=True).order_by(UserFeedback.created_at.desc()).limit(50).all()
    avg_rating = round(sum(f.rating or 5 for f in feedbacks) / len(feedbacks), 1) if feedbacks else 0
    return render_template('feedback.html',
                           feedbacks=feedbacks,
                           feedback_count=len(feedbacks),
                           avg_rating=avg_rating,
                           categories=FEEDBACK_CATEGORIES,
                           form_data=None)



@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("30 per minute")
def register():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user and not user.is_suspended:
            return redirect(url_for('dashboard'))
        else:
            session.clear()

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        if not username or not email or not password:
            flash('Lütfen tüm zorunlu alanları doldurun.', 'danger')
            return render_template('register.html', username=username, email=email)

        # Validate username format
        if len(username) < 3 or not re.match(r'^[a-zA-Z0-9_]+$', username):
            flash('Kullanıcı adı en az 3 karakter olmalı ve yalnızca harf, rakam ve alt çizgi içerebilir.', 'danger')
            return render_template('register.html', username=username, email=email)

        # Check reserved usernames
        if username.lower() in RESERVED_USERNAMES:
            flash('Bu kullanıcı adı sistem tarafından ayrılmıştır. Lütfen farklı bir kullanıcı adı seçiniz.', 'danger')
            return render_template('register.html', username=username, email=email)

        # Validate email format
        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
            flash('Geçerli bir e-posta adresi giriniz.', 'danger')
            return render_template('register.html', username=username, email=email)

        # Case-insensitive username uniqueness check
        if User.query.filter(func.lower(User.username) == username.lower()).first():
            flash('Bu kullanıcı adı zaten kullanılmaktadır.', 'danger')
            return render_template('register.html', username=username, email=email)

        if User.query.filter_by(email=email).first():
            flash('Bu e-posta adresiyle zaten bir kayıt bulunmaktadır.', 'danger')
            return render_template('register.html', username=username, email=email)

        # Check password match
        if password != confirm_password:
            flash('Girilen şifreler birbiriyle uyuşmuyor.', 'danger')
            return render_template('register.html', username=username, email=email)

        # Validate password complexity (Regex harf + rakam)
        is_valid_pw, pw_msg = validate_password_complexity(password)
        if not is_valid_pw:
            flash(pw_msg, 'danger')
            return render_template('register.html', username=username, email=email)

        # Generate Cryptographically Secure Verification Code + 15 min expiry
        code = generate_verification_code()
        expires_at = datetime.utcnow() + timedelta(minutes=15)

        is_root = (username.lower() in ['sefa_gumus', 'sefagumus', 'sefa']) or (email.lower() == 'gsefa5683@gmail.com')
        # E-posta doğrulama kapatıldı: Tüm yeni kayıtlar anında aktif ve doğrulanmış başlar
        new_user = User(
            username=username,
            email=email,
            is_verified=True,
            verification_code=None,
            verification_code_expires_at=None,
            is_leader=True if is_root else False,
            is_founder=True if is_root else False,
            role='root' if is_root else 'unregistered',
            score=0,
            is_suspended=False,
            failed_login_attempts=0
        )
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        # Oturumu doğrudan aç ve kullanıcıyı panele yönlendir (bekleme ve kod engeli yok)
        session.clear()
        session['user_id'] = new_user.id
        session.permanent = True
        if is_root:
            flash(f'🎉 Kaydınız başarıyla tamamlandı! Hoş geldiniz, {new_user.username}.', 'success')
        else:
            flash(f'🎉 Kaydınız alındı, hoş geldiniz {new_user.username}! Hesabınız şu anda "Kayıtsız" rolündedir; yönetici tarafından "Öğrenci" rolüne onaylandığında laboratuvarlara erişebilirsiniz.', 'info')
        return redirect(url_for('dashboard'))

    return render_template('register.html')

@app.route('/resend-verification', methods=['POST'])
@limiter.limit("20 per minute")
def resend_verification():
    email = request.form.get('email', '').strip().lower()
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('Kullanıcı bulunamadı.', 'danger')
        return redirect(url_for('register'))
    if user.is_suspended:
        flash(SUSPENDED_BLOCK_MSG, 'danger')
        return redirect(url_for('login'))
    if user.is_verified:
        flash('Hesabınız zaten doğrulanmış. Giriş yapabilirsiniz.', 'info')
        return redirect(url_for('login'))

    new_code = generate_verification_code()
    user.verification_code = new_code
    user.verification_code_expires_at = datetime.utcnow() + timedelta(minutes=15)
    db.session.commit()

    email_sent, email_msg = send_verification_email(email, user.username, new_code)
    session['pending_verify_email'] = email
    if email_sent:
        flash(f'Yeni doğrulama kodunuz {email} adresine tekrar gönderildi. Lütfen gelen kutunuzu (ve Spam klasörünü) kontrol ediniz.', 'success')
    else:
        flash(f'Yeni doğrulama kodunuz oluşturuldu. Lütfen gelen kutunuzu (ve Spam klasörünü) kontrol ediniz.', 'info')

    return redirect(url_for('verify', email=email))

@app.route('/verify', methods=['GET', 'POST'])
@limiter.limit("30 per minute")
def verify():
    email = request.args.get('email', '') or request.form.get('email', '') or session.get('pending_verify_email', '')

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        code = request.form.get('code', '').strip().upper()

        if not email:
            flash('Lütfen e-posta adresinizi giriniz.', 'danger')
            return render_template('verify.html', email=email)

        if not code:
            flash('Lütfen 6 haneli doğrulama kodunu giriniz.', 'danger')
            return render_template('verify.html', email=email)

        user = User.query.filter_by(email=email).first()
        if not user:
            flash('Bu e-posta adresiyle kayıtlı bir hesap bulunamadı.', 'danger')
            return render_template('verify.html', email=email)

        if user.is_suspended:
            flash(SUSPENDED_BLOCK_MSG, 'danger')
            return render_template('verify.html', email=email)

        if user.is_verified:
            flash('Hesabınız zaten onaylanmış! Giriş yapabilirsiniz.', 'success')
            return redirect(url_for('login'))

        # Doğrulama kodu kontrolü (Birebir eşleşme ve 15 dk süre kontrolü)
        is_valid_code = False
        if user.verification_code and secrets.compare_digest(user.verification_code.upper(), code):
            if user.verification_code_expires_at and datetime.utcnow() > user.verification_code_expires_at:
                flash('Doğrulama kodunun geçerlilik süresi (15 dakika) dolmuştur. Lütfen "Kodu Tekrar Gönder" butonuna basınız.', 'warning')
                return render_template('verify.html', email=email)
            is_valid_code = True

        if is_valid_code:
            user.is_verified = True
            user.verification_code = None
            user.verification_code_expires_at = None
            user.failed_login_attempts = 0
            db.session.commit()
            
            # Doğrulama başarılı - Oturumu güvenle aç ve kullanıcıyı panele al
            session.pop('pending_verify_email', None)
            session.clear()
            session.permanent = True
            session['user_id'] = user.id
            session['username'] = user.username
            flash(f'Tebrikler Ajan {user.username}! E-posta doğrulamanız başarıyla tamamlandı ve hesabınız aktifleştirildi.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Hatalı doğrulama kodu! Lütfen e-postanıza (veya Spam klasörünüze) gelen 6 haneli kodu kontrol ediniz.', 'danger')
            return render_template('verify.html', email=email)

    return render_template('verify.html', email=email)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("30 per minute")
def login():
    if 'user_id' in session:
        user = User.query.get(session['user_id'])
        if user and not user.is_suspended:
            return redirect(url_for('dashboard'))
        else:
            session.clear()

    if request.method == 'POST':
        login_id = request.form.get('login_id', '').strip()
        password = request.form.get('password', '').strip()

        if not login_id or not password:
            flash('Lütfen kullanıcı adı/e-posta ve şifrenizi girin.', 'danger')
            return render_template('login.html', login_id=login_id)

        user = _find_user_by_login(login_id, allow_email_prefix=True)

        if not user:
            flash('Bu kullanıcı adı veya e-posta ile kayıtlı bir hesap bulunamadı.', 'danger')
            return render_template('login.html', login_id=login_id)

        # 1. HESAP ASKI VE GÜVENLİK KONTROLÜ (Askıya alınmış hesap Root askıyı kaldırana kadar giriş yapamaz)
        if user.is_suspended:
            flash(SUSPENDED_BLOCK_MSG, 'danger')
            return render_template('login.html', login_id=login_id)

        # 2. ŞİFRE DOĞRULAMA (Giriş ekranında 3 kez hatalı girilirse hesap askıya alınır)
        if not user.check_password(password):
            user.failed_login_attempts = (user.failed_login_attempts or 0) + 1
            if user.failed_login_attempts >= 3:
                user.is_suspended = True
                user.reset_token = None
                user.reset_token_expires_at = None
                db.session.commit()
                flash('🚨 Şifrenizi 3 kez üst üste hatalı girdiniz! Hesabınız güvenlik için askıya alındı ve giriş kapatıldı. Askıyı yalnızca Root (Süper Yönetici) kaldırabilir.', 'danger')
            else:
                remaining = 3 - user.failed_login_attempts
                db.session.commit()
                flash(f'Girdiğiniz şifre hatalı! Kalan giriş hakkınız: {remaining}.', 'danger')
            return render_template('login.html', login_id=login_id)

        # 3. BAŞARILI GİRİŞ - Hatalı deneme sayacını sıfırla (yalnızca askıda olmayan hesaplar buraya ulaşır)
        if (user.failed_login_attempts or 0) > 0:
            user.failed_login_attempts = 0
            db.session.commit()

        # E-posta doğrulama kaldırıldı: Hesap doğrulanmamışsa bile otomatik onayla
        if not user.is_verified:
            user.is_verified = True
            db.session.commit()

        # Root (Süper Yönetici) kullanıcıların rol ve yetkilerini garantiye al
        if (user.username and user.username.lower() in ['sefa_gumus', 'sefagumus', 'sefa']) or (user.email and user.email.lower() == 'gsefa5683@gmail.com'):
            user.role = 'root'
            user.is_founder = True
            user.is_leader = True
            user.is_verified = True
            user.failed_login_attempts = 0
            db.session.commit()

        # 2FA Kontrolü (İki Adımlı Doğrulama Aktifse ara doğrulama ekranına yönlendir)
        if user.two_factor_enabled and user.totp_secret:
            session.clear()
            session['pending_2fa_user_id'] = user.id
            flash('İki Adımlı Doğrulama (2FA) aktif. Lütfen Google Authenticator uygulamanızdaki 6 haneli kodu giriniz.', 'info')
            return redirect(url_for('login_2fa'))

        # Login success - Oturum fiksasyonu koruması ve Kalıcı Oturum
        session.clear()
        session.permanent = True
        session['user_id'] = user.id
        session['username'] = user.username
        flash(f'Hoş geldin, Ajan {user.username}! Sisteme güvenli bağlantı kuruldu.', 'success')
        
        # Açık Yönlendirme (Open Redirect) Koruması
        next_url = request.args.get('next')
        if next_url and is_safe_url(next_url):
            return redirect(next_url)
        return redirect(url_for('dashboard'))

    return render_template('login.html')

@app.route('/login/2fa', methods=['GET', 'POST'])
def login_2fa():
    pending_user_id = session.get('pending_2fa_user_id')
    if not pending_user_id:
        flash('Lütfen önce kullanıcı adı ve şifrenizle giriş yapınız.', 'warning')
        return redirect(url_for('login'))

    user = User.query.get(pending_user_id)
    if not user or user.is_suspended or not user.two_factor_enabled or not user.totp_secret:
        session.clear()
        if user and user.is_suspended:
            flash(SUSPENDED_BLOCK_MSG, 'danger')
        return redirect(url_for('login'))

    if request.method == 'POST':
        otp_code = request.form.get('otp_code', '').strip().replace(' ', '')
        if not otp_code or len(otp_code) != 6:
            flash('Lütfen 6 haneli doğrulama kodunu eksiksiz giriniz.', 'danger')
            return render_template('login_2fa.html', username=user.username)

        totp = pyotp.TOTP(user.totp_secret)
        if totp.verify(otp_code, valid_window=1): # ±30 saniye tolerans
            session.clear()
            session.permanent = True
            session['user_id'] = user.id
            session['username'] = user.username
            flash(f'2FA doğrulaması başarılı! Hoş geldin, Ajan {user.username}.', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Geçersiz veya süresi dolmuş 2FA kodu. Lütfen Authenticator uygulamasını kontrol edip tekrar deneyiniz.', 'danger')
            return render_template('login_2fa.html', username=user.username)

    return render_template('login_2fa.html', username=user.username)

@app.route('/2fa/setup', methods=['GET', 'POST'])
@login_required
def two_factor_setup():
    user = User.query.get(session['user_id'])
    if user.two_factor_enabled:
        flash('İki Adımlı Doğrulama (2FA) hesabınızda zaten aktif durumda.', 'info')
        return redirect(url_for('dashboard'))

    # Üretilmiş secret yoksa oluştur
    if not user.totp_secret:
        user.totp_secret = pyotp.random_base32()
        db.session.commit()

    totp = pyotp.TOTP(user.totp_secret)
    provisioning_uri = totp.provisioning_uri(name=user.email, issuer_name='NOHU Cyber-Hub')

    # Data URI QR Kod oluştur
    qr = qrcode.QRCode(version=1, box_size=7, border=2)
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color="#020617", back_color="#ffffff")
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    qr_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')
    qr_data_uri = f"data:image/png;base64,{qr_b64}"

    if request.method == 'POST':
        otp_code = request.form.get('otp_code', '').strip().replace(' ', '')
        if totp.verify(otp_code, valid_window=1):
            user.two_factor_enabled = True
            db.session.commit()
            flash('Tebrikler! İki Adımlı Doğrulama (2FA) başarıyla aktifleştirildi. Hesabınız artık zırhlı!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Girilen 6 haneli kod doğrulanamadı. Lütfen Authenticator uygulamanızdaki güncel kodu deneyiniz.', 'danger')

    return render_template('two_factor_setup.html', user=user, secret=user.totp_secret, qr_data_uri=qr_data_uri)

@app.route('/2fa/disable', methods=['POST'])
@login_required
def two_factor_disable():
    user = User.query.get(session['user_id'])
    password = request.form.get('password', '').strip()

    if not user.check_password(password):
        flash('2FA korumasını kapatmak için şifrenizi doğru girmelisiniz.', 'danger')
        return redirect(url_for('dashboard'))

    user.two_factor_enabled = False
    user.totp_secret = None
    db.session.commit()
    flash('İki Adımlı Doğrulama (2FA) başarıyla devre dışı bırakıldı.', 'warning')
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    flash('Oturum başarıyla sonlandırıldı. Güvenli çıkış yapıldı.', 'info')
    return redirect(url_for('index'))

# ----------------- ŞİFRE YÖNETİMİ & SIFIRLAMA ROTLARI ----------------- #

@app.route('/change-password', methods=['POST'])
@login_required
@csrf.exempt
def change_password():
    user = User.query.get(session['user_id'])
    current_password = request.form.get('current_password', '').strip()
    new_password = request.form.get('new_password', '').strip()
    confirm_password = request.form.get('confirm_password', '').strip()

    if not current_password or not new_password or not confirm_password:
        flash('Lütfen tüm şifre alanlarını eksiksiz doldurunuz.', 'danger')
        return redirect(url_for('dashboard') + '#security-settings')

    # Mevcut şifre doğrulaması
    if not user.check_password(current_password):
        flash('Mevcut şifrenizi hatalı girdiniz! Şifrenizi unuttuysanız aşağıdaki "Şifremi Unuttum" seçeneğini kullanabilirsiniz.', 'danger')
        return redirect(url_for('dashboard') + '#security-settings')

    # Yeni şifre eşleşme kontrolü
    if new_password != confirm_password:
        flash('Yeni şifreler birbiriyle uyuşmuyor. Lütfen tekrar deneyiniz.', 'danger')
        return redirect(url_for('dashboard') + '#security-settings')

    # Yeni şifre eskisinin aynısı olamaz
    if current_password == new_password:
        flash('Yeni şifreniz mevcut şifrenizle aynı olamaz.', 'warning')
        return redirect(url_for('dashboard') + '#security-settings')

    # Şifre karmaşıklık kontrolü
    is_valid_pw, pw_msg = validate_password_complexity(new_password)
    if not is_valid_pw:
        flash(pw_msg, 'danger')
        return redirect(url_for('dashboard') + '#security-settings')

    # Şifreyi güncelle ve oturum hatalarını temizle
    user.set_password(new_password)
    user.failed_login_attempts = 0
    db.session.commit()

    flash('🔐 Şifreniz başarıyla güncellendi! Yeni şifreniz anında aktif edildi.', 'success')
    return redirect(url_for('dashboard') + '#security-settings')

@app.route('/dashboard/forgot-password-request', methods=['POST'])
@login_required
@csrf.exempt
def dashboard_forgot_password_request():
    user = User.query.get(session['user_id'])
    reset_code = generate_verification_code()
    user.reset_token = reset_code
    user.reset_token_expires_at = datetime.utcnow() + timedelta(minutes=15)
    db.session.commit()

    sent, mail_msg = send_password_reset_email(user.email, user.username, reset_code)
    if sent:
        flash(f"6 haneli şifre sıfırlama kodunuz kayıtlı e-posta adresinize ({user.email}) gönderildi.", 'success')
    else:
        print(f"[*] (GELİŞTİRİCİ KONSOLU) Şifre Sıfırlama Kodu: {reset_code}")
        flash(f"Şifre sıfırlama kodunuz üretildi: [ {reset_code} ]", 'info')

    return redirect(url_for('reset_password', email=user.email))

@app.route('/forgot-password', methods=['GET', 'POST'])
@csrf.exempt
@limiter.limit("15 per minute")
def forgot_password():
    if request.method == 'POST':
        login_id = request.form.get('login_id', '').strip()
        if not login_id:
            flash('Lütfen kullanıcı adı veya e-posta adresinizi giriniz.', 'danger')
            return render_template('forgot_password.html')

        user = _find_user_by_login(login_id)

        if not user:
            flash('Bu kullanıcı adı veya e-posta ile kayıtlı bir hesap bulunamadı.', 'danger')
            return render_template('forgot_password.html', login_id=login_id)

        if user.is_suspended:
            flash(SUSPENDED_BLOCK_MSG, 'danger')
            return redirect(url_for('login'))

        reset_code = generate_verification_code()
        user.reset_token = reset_code
        user.reset_token_expires_at = datetime.utcnow() + timedelta(minutes=15)
        db.session.commit()

        sent, mail_msg = send_password_reset_email(user.email, user.username, reset_code)
        if sent:
            print(f"[+] (GELİŞTİRİCİ KONSOLU) Şifre sıfırlama e-postası gönderildi: {user.email}")
            flash(f"6 haneli şifre sıfırlama kodu {user.email} adresinize gönderildi.", 'success')
        elif not app.debug:
            print(f"[*] (GELİŞTİRİCİ KONSOLU) Şifre Sıfırlama Kodu: {reset_code}")
            flash('E-posta şu an gönderilemedi. Korumalı hesaplar için lütfen yönetici ile iletişime geçiniz.', 'warning')
            return redirect(url_for('login'))
        else:
            print(f"[*] (GELİŞTİRİCİ KONSOLU) Şifre Sıfırlama Kodu: {reset_code}")
            flash(f"Şifre sıfırlama kodunuz üretildi: [ {reset_code} ]", 'info')

        return redirect(url_for('reset_password', email=user.email))

    prefill_email = request.args.get('email', '')
    return render_template('forgot_password.html', login_id=prefill_email)

@app.route('/reset-password', methods=['GET', 'POST'])
@csrf.exempt
@limiter.limit("15 per minute")
def reset_password():
    if request.method == 'POST':
        login_id = request.form.get('email', '').strip()
        code = request.form.get('code', '').strip().upper()
        new_password = request.form.get('new_password', '').strip()
        confirm_password = request.form.get('confirm_password', '').strip()

        if not login_id or not code or not new_password or not confirm_password:
            flash('Lütfen tüm alanları eksiksiz doldurunuz.', 'danger')
            return render_template('reset_password.html', email=login_id)

        user = _find_user_by_login(login_id)

        if not user:
            flash('Kullanıcı hesabı bulunamadı.', 'danger')
            return render_template('reset_password.html', email=login_id)

        if user.is_suspended:
            flash(SUSPENDED_BLOCK_MSG, 'danger')
            return redirect(url_for('login'))

        # Kod kontrolü
        if not user.reset_token or user.reset_token.strip().upper() != code:
            flash('Girilen 6 haneli güvenlik kodu hatalı!', 'danger')
            return render_template('reset_password.html', email=login_id)

        # Süre kontrolü (15 dakika)
        if user.reset_token_expires_at and user.reset_token_expires_at < datetime.utcnow():
            flash('Güvenlik kodunun 15 dakikalık süresi dolmuş. Lütfen yeni bir kod talep ediniz.', 'danger')
            return redirect(url_for('forgot_password', email=user.email))

        # Şifre eşleşme kontrolü
        if new_password != confirm_password:
            flash('Girilen yeni şifreler birbiriyle uyuşmuyor.', 'danger')
            return render_template('reset_password.html', email=login_id)

        # Şifre karmaşıklık kuralları
        is_valid_pw, pw_msg = validate_password_complexity(new_password)
        if not is_valid_pw:
            flash(pw_msg, 'danger')
            return render_template('reset_password.html', email=login_id)

        # Şifreyi güncelle (askıya alma durumu yalnızca Root tarafından kaldırılabilir)
        user.set_password(new_password)
        user.reset_token = None
        user.reset_token_expires_at = None
        user.failed_login_attempts = 0
        db.session.commit()

        flash('🎉 Şifreniz başarıyla sıfırlandı! Yeni şifrenizle giriş yapabilirsiniz.', 'success')
        return redirect(url_for('login'))

    email = request.args.get('email', '')
    return render_template('reset_password.html', email=email)

@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session.get('user_id'))
    if not user:
        session.clear()
        flash('Oturum süreniz doldu veya hesap bulunamadı. Lütfen tekrar giriş yapınız.', 'warning')
        return redirect(url_for('login'))
    
    # Calculate user rank among verified active users
    rank = User.query.filter(User.is_verified == True, User.score > user.score).count() + 1
    
    # User's solved labs
    completed_progress = UserLabProgress.query.filter_by(user_id=user.id, is_completed=True).order_by(UserLabProgress.completed_at.desc()).all()
    completed_lab_ids = [p.lab_id for p in completed_progress]

    # Category stats
    published_red_ids = [l.id for l in Lab.query.filter_by(category='red_team', is_published=True).all()]
    published_blue_ids = [l.id for l in Lab.query.filter_by(category='blue_team', is_published=True).all()]
    total_red = len(published_red_ids) or 1
    total_blue = len(published_blue_ids) or 1

    completed_red = sum(1 for lid in completed_lab_ids if lid in published_red_ids)
    completed_blue = sum(1 for lid in completed_lab_ids if lid in published_blue_ids)

    red_percent = int((completed_red / total_red) * 100)
    blue_percent = int((completed_blue / total_blue) * 100)

    # Badges earned
    badges = []
    if user.score >= 50:
        badges.append({'name': 'İlk Adım', 'desc': 'İlk laboratuvarını başarıyla tamamladın.', 'icon': 'fa-solid fa-flag'})
    if completed_red >= 1:
        badges.append({'name': 'Red Operatör', 'desc': 'İlk Red Team zafiyetini sömürdün.', 'icon': 'fa-solid fa-skull-crossbones', 'color': 'text-red-400'})
    if completed_blue >= 1:
        badges.append({'name': 'Blue Muhafız', 'desc': 'İlk savunma ve analiz labını çözdün.', 'icon': 'fa-solid fa-shield-halved', 'color': 'text-blue-400'})
    if user.score >= 300:
        badges.append({'name': 'Kıdemli Uzman', 'desc': '300+ puan barajını aştın.', 'icon': 'fa-solid fa-trophy', 'color': 'text-yellow-400'})

    return render_template('dashboard.html',
                           user=user,
                           rank=rank,
                           completed_progress=completed_progress,
                           completed_red=completed_red,
                           total_red=total_red,
                           red_percent=red_percent,
                           completed_blue=completed_blue,
                           total_blue=total_blue,
                           blue_percent=blue_percent,
                           badges=badges)

# ==========================================
# PROJE LİDERİ / ADMIN YÖNETİM PANELİ
# ==========================================
@app.route('/admin')
@leader_required
def admin_panel():
    all_users = User.query.order_by(User.created_at.desc()).all()
    total_users = len(all_users)
    verified_users = sum(1 for u in all_users if u.is_verified)
    unverified_users = total_users - verified_users
    red_count = sum(1 for u in all_users if u.assigned_team == 'red_team')
    blue_count = sum(1 for u in all_users if u.assigned_team == 'blue_team')
    superadmin_count = sum(1 for u in all_users if u.is_superadmin)
    leader_count = sum(1 for u in all_users if u.role == 'leader' and not u.is_superadmin)
    student_count = sum(1 for u in all_users if (u.role == 'student' or not u.role) and not u.is_superadmin and not u.is_team_leader)
    unregistered_count = sum(1 for u in all_users if u.is_unregistered)
    total_completed = UserLabProgress.query.filter_by(is_completed=True).count()
    total_score = sum(u.score for u in all_users)
    suspended_count = sum(1 for u in all_users if u.is_suspended)
    feedbacks = UserFeedback.query.order_by(UserFeedback.created_at.desc()).all()
    
    return render_template('admin.html',
                           users=all_users,
                           total_users=total_users,
                           verified_users=verified_users,
                           unverified_users=unverified_users,
                           suspended_count=suspended_count,
                           red_count=red_count,
                           blue_count=blue_count,
                           superadmin_count=superadmin_count,
                           leader_count=leader_count,
                           student_count=student_count,
                           unregistered_count=unregistered_count,
                           total_completed=total_completed,
                           total_score=total_score,
                           feedbacks=feedbacks)

@app.route('/admin/delete-feedback/<int:feedback_id>', methods=['POST'])
@superadmin_required
def admin_delete_feedback(feedback_id):
    fb = UserFeedback.query.get_or_404(feedback_id)
    db.session.delete(fb)
    db.session.commit()
    flash('Geri bildirim mesajı Root yetkisiyle silindi.', 'info')
    return_to = request.form.get('return_to', 'admin')
    if return_to == 'feedback':
        return redirect(url_for('feedback_page') + '#geri-donusler')
    if return_to == 'index':
        return redirect(url_for('index') + '#geri-bildirim')
    return redirect(url_for('admin_panel') + '#admin-feedbacks')

@app.route('/admin/set-team/<int:user_id>', methods=['POST'])
@leader_required
@csrf.exempt
def admin_set_team(user_id):
    target_user = User.query.get_or_404(user_id)
    new_team = request.form.get('team', 'unassigned')
    if new_team not in ['red_team', 'blue_team', 'purple_team', 'unassigned']:
        flash('Geçersiz takım seçimi.', 'danger')
        return redirect(url_for('admin_panel'))
    
    target_user.assigned_team = new_team
    db.session.commit()

    team_labels = {
        'red_team': 'Red Team (Saldırı)',
        'blue_team': 'Blue Team (Savunma)',
        'purple_team': 'Purple Team (Karma)',
        'unassigned': 'Atanmamış'
    }
    flash(f"'{target_user.username}' öğrencisi başarıyla {team_labels.get(new_team)} grubuna atandı.", 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/verify/<int:user_id>', methods=['GET', 'POST'])
@superadmin_required
@csrf.exempt
def admin_verify_user(user_id):
    target_user = User.query.get_or_404(user_id)
    target_user.is_verified = True
    target_user.verification_code = None
    target_user.verification_code_expires_at = None
    db.session.commit()
    flash(f"'{target_user.username}' kullanıcısı başarıyla doğrulandı.", 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/delete/<int:user_id>', methods=['GET', 'POST'])
@superadmin_required
@csrf.exempt
def admin_delete_user(user_id):
    target_user = User.query.get_or_404(user_id)
    if target_user.id == session.get('user_id'):
        flash('Kendi yönetici hesabınızı silemezsiniz.', 'danger')
        return redirect(url_for('admin_panel'))
    if target_user.is_superadmin:
        flash('Süper Yönetici (Root) hesabı silinemez.', 'danger')
        return redirect(url_for('admin_panel'))
        
    username = target_user.username
    db.session.delete(target_user)
    db.session.commit()
    flash(f"'{username}' kullanıcısı ve tüm kayıtları Süper Yönetici yetkisiyle silindi.", 'info')
    return redirect(url_for('admin_panel'))

@app.route('/admin/toggle-suspend/<int:user_id>', methods=['GET', 'POST'])
@superadmin_required
@csrf.exempt
def admin_toggle_suspend(user_id):
    current_u = User.query.get(session.get('user_id'))
    target_user = User.query.get_or_404(user_id)

    if target_user.id == current_u.id and not target_user.is_suspended:
        flash('Kendi yönetici hesabınızı askıya alamazsınız.', 'warning')
        return redirect(url_for('admin_panel'))

    if target_user.is_suspended:
        target_user.is_suspended = False
        target_user.failed_login_attempts = 0
        db.session.commit()
        flash(f"'{target_user.username}' kullanıcısının hesap askısı Süper Yönetici tarafından kaldırıldı. Kullanıcı artık sisteme giriş yapabilir.", 'success')
    else:
        target_user.is_suspended = True
        target_user.failed_login_attempts = 3
        target_user.reset_token = None
        target_user.reset_token_expires_at = None
        db.session.commit()
        flash(f"'{target_user.username}' hesabı Süper Yönetici tarafından askıya alındı.", 'warning')

    return redirect(url_for('admin_panel'))

@app.route('/admin/set-role/<int:user_id>', methods=['POST'])
@superadmin_required
@csrf.exempt
def admin_set_role(user_id):
    target_user = User.query.get_or_404(user_id)
    current_u = User.query.get(session.get('user_id'))
    new_role = request.form.get('role', 'student')
    
    if new_role not in ['unregistered', 'student', 'leader', 'superadmin', 'root']:
        flash('Geçersiz rol seçimi.', 'danger')
        return redirect(url_for('admin_panel'))
        
    # Root rolünü normalize et
    if new_role in ['superadmin', 'root']:
        canonical_role = 'root'
        target_user.role = 'root'
        target_user.is_leader = True
        target_user.is_founder = True
    elif new_role == 'leader':
        canonical_role = 'leader'
        target_user.role = 'leader'
        target_user.is_leader = True
        target_user.is_founder = False
    elif new_role == 'unregistered':
        canonical_role = 'unregistered'
        target_user.role = 'unregistered'
        target_user.is_leader = False
        target_user.is_founder = False
    else: # student
        canonical_role = 'student'
        target_user.role = 'student'
        target_user.is_leader = False
        target_user.is_founder = False

    db.session.commit()
    
    role_names = {
        'root': 'Root (Süper Yönetici)',
        'superadmin': 'Root (Süper Yönetici)',
        'leader': 'Takım Lideri',
        'student': 'Öğrenci',
        'unregistered': 'Kayıtsız'
    }
    flash(f"'{target_user.username}' kullanıcısının rolü '{role_names.get(canonical_role)}' olarak başarıyla güncellendi.", 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/adjust-score/<int:user_id>', methods=['POST'])
@superadmin_required
@csrf.exempt
def admin_adjust_score(user_id):
    target_user = User.query.get_or_404(user_id)
    try:
        score_delta = int(request.form.get('score_delta', 0))
    except (ValueError, TypeError):
        flash('Geçersiz puan değeri.', 'danger')
        return redirect(url_for('admin_panel'))
        
    target_user.score = max(0, target_user.score + score_delta)
    db.session.commit()
    flash(f"'{target_user.username}' kullanıcısına {score_delta:+d} puan uygulandı. Güncel puan: {target_user.score} P", 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/toggle-leader/<int:user_id>', methods=['GET', 'POST'])
@superadmin_required
@csrf.exempt
def admin_toggle_leader(user_id):
    current_u = User.query.get(session.get('user_id'))
    target_user = User.query.get_or_404(user_id)

    # Prevent removing founder status
    if target_user.is_founder and target_user.is_leader:
        flash(f"'{target_user.username}' kurucu liderdir, yetkisi kaldırılamaz.", 'warning')
        return redirect(url_for('admin_panel'))

    # Prevent removing own leadership
    if target_user.id == current_u.id:
        flash('Kendi yönetici yetkinizi kaldıramazsınız.', 'warning')
        return redirect(url_for('admin_panel'))

    # Toggle leadership
    target_user.is_leader = not bool(target_user.is_leader)
    target_user.role = 'leader' if target_user.is_leader else 'student'
    db.session.commit()

    if target_user.is_leader:
        flash(f"'{target_user.username}' kullanıcısına başarıyla Takım Lideri yetkisi verildi.", 'success')
    else:
        flash(f"'{target_user.username}' kullanıcısının Takım Lideri yetkisi geri alındı.", 'info')

    return redirect(url_for('admin_panel'))

    return redirect(url_for('admin_panel'))

def _render_team_labs(category, template_name):
    """Render published labs for a team category with user task progress and warnings."""
    labs = Lab.query.filter_by(category=category, is_published=True).order_by(Lab.id.asc()).all()
    user_completed_ids = []
    user_progress_map = {}
    if 'user_id' in session:
        progresses = UserLabProgress.query.filter_by(user_id=session['user_id']).all()
        for p in progresses:
            if p.is_completed:
                user_completed_ids.append(p.lab_id)
            user_progress_map[p.lab_id] = {
                'solved_count': len(p.get_solved_tasks()),
                'earned_points': p.earned_points or 0,
                'is_completed': bool(p.is_completed)
            }
    task_counts = {
        slug: len(cfg.get('tasks', []))
        for slug, cfg in MULTI_TASK_LABS.items()
    }
    lab_warnings = {
        slug: cfg['card_warning']
        for slug, cfg in MULTI_TASK_LABS.items()
        if cfg.get('card_warning')
    }
    lab_guides = {
        slug: cfg['guide_pdf']
        for slug, cfg in MULTI_TASK_LABS.items()
        if cfg.get('guide_pdf')
    }
    lab_videos = {
        slug: cfg['guide_video']
        for slug, cfg in MULTI_TASK_LABS.items()
        if cfg.get('guide_video')
    }
    return render_template(
        template_name,
        labs=labs,
        user_completed_ids=user_completed_ids,
        user_progress_map=user_progress_map,
        task_counts=task_counts,
        lab_warnings=lab_warnings,
        lab_guides=lab_guides,
        lab_videos=lab_videos
    )

@app.route('/red-team')
def red_team():
    return _render_team_labs('red_team', 'red_team.html')

@app.route('/blue-team')
def blue_team():
    return _render_team_labs('blue_team', 'blue_team.html')

@app.route('/purple-team')
def purple_team():
    labs = Lab.query.filter_by(category='purple_team').all()
    user_completed_ids = []
    if 'user_id' in session:
        user_completed_ids = [p.lab_id for p in UserLabProgress.query.filter_by(user_id=session['user_id'], is_completed=True).all()]
    return render_template('purple_team.html', labs=labs, user_completed_ids=user_completed_ids)

@app.route('/lab/<slug>')
@lab_access_required
def lab_detail(slug):
    lab = Lab.query.filter_by(slug=slug).first_or_404()
    user = User.query.get(session['user_id'])
    if not lab.is_published and not user.is_superadmin:
        flash('Bu laboratuvar henüz yayına açılmamıştır.', 'warning')
        return redirect(url_for('red_team' if lab.category == 'red_team' else ('blue_team' if lab.category == 'blue_team' else 'purple_team')))
    
    progress = UserLabProgress.query.filter_by(user_id=user.id, lab_id=lab.id).first()
    if not progress:
        progress = UserLabProgress(user_id=user.id, lab_id=lab.id, started_at=datetime.utcnow())
        db.session.add(progress)
        db.session.commit()
    elif not progress.started_at:
        progress.started_at = datetime.utcnow()
        db.session.commit()

    is_solved = progress.is_completed if progress else False

    # First blood kullanıcısı kim?
    first_blood = lab.first_blood
    first_blood_user = first_blood.user.username if first_blood and first_blood.user else None

    # Writeup sayısı
    writeup_count = lab.writeups.count()

    if lab.lab_type == 'multi_task' and slug in MULTI_TASK_LABS:
        cfg = MULTI_TASK_LABS[slug]
        tasks = get_public_tasks(slug)
        solved_task_ids = progress.get_solved_tasks() if progress else []
        initial_score = sum(t['points'] for t in tasks if t['id'] in solved_task_ids)
        return render_template(
            'lab_multi_task.html',
            lab=lab,
            lab_config=cfg,
            tasks=tasks,
            solved_task_ids=solved_task_ids,
            initial_score=initial_score,
            is_solved=is_solved,
            progress=progress,
            first_blood_user=first_blood_user,
            writeup_count=writeup_count,
            target_url=url_for(cfg['target_endpoint'])
        )

    return render_template('lab_detail.html', 
                           lab=lab, 
                           is_solved=is_solved, 
                           progress=progress, 
                           first_blood_user=first_blood_user,
                           writeup_count=writeup_count)

def _get_accessible_lab_or_redirect(slug, fallback_endpoint):
    """Return the Lab if published or current user is superadmin; otherwise redirect."""
    lab = Lab.query.filter_by(slug=slug).first_or_404()
    user = User.query.get(session['user_id'])
    if not lab.is_published and not user.is_superadmin:
        flash('Bu hedef kaynak henüz erişime açılmamıştır.', 'warning')
        return None, redirect(url_for(fallback_endpoint))
    return lab, None

@app.route('/lab/red-bayrak-avi-1/target')
@lab_access_required
def bayrak_avi_1_target():
    _, denied = _get_accessible_lab_or_redirect('red-bayrak-avi-1', 'red_team')
    if denied:
        return denied
    return render_template('labs/bayrak_avi_1_target.html')

@app.route('/lab/red-ohsint-2/target')
@lab_access_required
def ohsint_2_target():
    _, denied = _get_accessible_lab_or_redirect('red-ohsint-2', 'red_team')
    if denied:
        return denied
    assets_dir = os.path.join(app.root_path, 'lab_assets')
    return send_from_directory(assets_dir, 'numune.jpg', as_attachment=True, download_name='numune.jpg')

@app.route('/lab/blue-soc-olay-1/target')
@lab_access_required
def blue_soc_olay_1_target():
    _, denied = _get_accessible_lab_or_redirect('blue-soc-olay-1', 'blue_team')
    if denied:
        return denied
    logs_dir = os.path.join(app.root_path, 'lab_assets', 'blue_soc_olay_1')
    with open(os.path.join(logs_dir, 'access.log'), 'r', encoding='utf-8') as f:
        access_lines = [line.rstrip('\r\n') for line in f if line.strip()]
    with open(os.path.join(logs_dir, 'auth.log'), 'r', encoding='utf-8') as f:
        auth_lines = [line.rstrip('\r\n') for line in f if line.strip()]

    stats = {
        'access_total': len(access_lines),
        'http_errors': sum(1 for l in access_lines if re.search(r'" (401|403|404|405|500) ', l)),
        'http_200': sum(1 for l in access_lines if '" 200 ' in l),
        'auth_total': len(auth_lines),
        'ssh_failed': sum(1 for l in auth_lines if 'Failed password' in l),
        'ssh_accepted': sum(1 for l in auth_lines if 'Accepted ' in l),
    }
    return render_template(
        'labs/blue_soc_olay_1_target.html',
        access_lines=access_lines,
        auth_lines=auth_lines,
        stats=stats
    )

@app.route('/lab/blue-soc-olay-1/download/<filename>')
@lab_access_required
def blue_soc_olay_1_download(filename):
    if filename not in {'access.log', 'auth.log'}:
        return jsonify({'success': False, 'message': 'Dosya bulunamadı.'}), 404
    _, denied = _get_accessible_lab_or_redirect('blue-soc-olay-1', 'blue_team')
    if denied:
        return denied
    logs_dir = os.path.join(app.root_path, 'lab_assets', 'blue_soc_olay_1')
    return send_from_directory(logs_dir, filename, as_attachment=True, download_name=filename)

@app.route('/leaderboard')
def leaderboard():
    users = User.query.filter_by(is_verified=True).order_by(User.score.desc(), User.created_at.asc()).all()
    
    red_users = [u for u in users if u.assigned_team == 'red_team']
    blue_users = [u for u in users if u.assigned_team == 'blue_team']
    purple_users = [u for u in users if u.assigned_team == 'purple_team']
    
    red_score = sum(u.score for u in red_users)
    blue_score = sum(u.score for u in blue_users)
    purple_score = sum(u.score for u in purple_users)
    total_team_score = red_score + blue_score + purple_score
    if total_team_score == 0:
        total_team_score = 1
    
    red_pct = round((red_score / total_team_score) * 100, 1)
    blue_pct = round((blue_score / total_team_score) * 100, 1)
    purple_pct = round((purple_score / total_team_score) * 100, 1)
    
    team_scores = [
        {'name': 'Red Team', 'slug': 'red_team', 'score': red_score, 'count': len(red_users), 'pct': red_pct, 'color': 'red', 'border': 'border-red-600', 'bg': 'bg-red-950/80', 'text': 'text-red-400', 'icon': 'fa-crosshairs'},
        {'name': 'Blue Team', 'slug': 'blue_team', 'score': blue_score, 'count': len(blue_users), 'pct': blue_pct, 'color': 'blue', 'border': 'border-blue-600', 'bg': 'bg-blue-950/80', 'text': 'text-blue-400', 'icon': 'fa-shield-halved'},
        {'name': 'Purple Team', 'slug': 'purple_team', 'score': purple_score, 'count': len(purple_users), 'pct': purple_pct, 'color': 'purple', 'border': 'border-purple-600', 'bg': 'bg-purple-950/80', 'text': 'text-purple-400', 'icon': 'fa-bolt'}
    ]
    team_scores.sort(key=lambda x: x['score'], reverse=True)
    
    return render_template('leaderboard.html', 
                           users=users,
                           team_scores=team_scores,
                           red_score=red_score,
                           blue_score=blue_score,
                           purple_score=purple_score,
                           red_pct=red_pct,
                           blue_pct=blue_pct,
                           purple_pct=purple_pct)

# ----------------- ETKİNLİKLER & CTF TAKVİMİ (Madde 6) ----------------- #

def _parse_event_datetime(date_str):
    """Parse HTML datetime-local or YYYY-MM-DD strings into a naive datetime."""
    for fmt in ('%Y-%m-%dT%H:%M', '%Y-%m-%d'):
        try:
            return datetime.strptime(date_str, fmt)
        except ValueError:
            continue
    return None

def _extract_event_form():
    """Extract and validate CyberEvent form fields shared by add/edit routes."""
    title = request.form.get('title', '').strip()
    description = request.form.get('description', '').strip()
    event_type = request.form.get('event_type', 'CTF').strip() or 'CTF'
    location = request.form.get('location', '').strip() or 'NÖHÜ Siber Lab'
    date_str = request.form.get('event_date', '').strip()
    end_date_str = request.form.get('end_date', '').strip()
    external_link = request.form.get('external_link', '').strip() or None
    organizer = request.form.get('organizer', '').strip() or 'NÖHÜ Siber Güvenlik Kulübü'

    if not title or not description or not date_str:
        return None, 'Lütfen etkinlik başlığı, açıklaması ve tarihini eksiksiz giriniz.'

    event_date = _parse_event_datetime(date_str)
    if not event_date:
        return None, 'Geçersiz başlangıç tarihi formatı.'

    end_date = None
    if end_date_str:
        end_date = _parse_event_datetime(end_date_str)
        if not end_date:
            return None, 'Geçersiz bitiş tarihi formatı.'
        if end_date < event_date:
            return None, 'Bitiş tarihi başlangıç tarihinden önce olamaz.'

    return {
        'title': title,
        'description': description,
        'event_type': event_type,
        'location': location,
        'event_date': event_date,
        'end_date': end_date,
        'external_link': external_link,
        'organizer': organizer,
    }, None

@app.route('/events')
def events_page():
    all_events = CyberEvent.query.order_by(CyberEvent.event_date.asc()).all()
    upcoming = sorted(
        [e for e in all_events if not e.is_past],
        key=lambda e: (e.is_ongoing, e.event_date)
    )
    past = [e for e in all_events if e.is_past]
    countdown_event = next((e for e in upcoming if not e.is_ongoing), None)
    return render_template(
        'events.html',
        upcoming_events=upcoming,
        past_events=past,
        countdown_event=countdown_event
    )

@app.route('/admin/event/add', methods=['POST'])
@leader_required
@csrf.exempt
def admin_add_event():
    data, error = _extract_event_form()
    if error:
        flash(error, 'danger')
        return redirect(url_for('events_page'))

    ev = CyberEvent(**data)
    db.session.add(ev)
    db.session.commit()
    flash(f"'{ev.title}' etkinliği başarıyla takvime eklendi.", 'success')
    return redirect(url_for('events_page'))

@app.route('/admin/event/edit/<int:event_id>', methods=['POST'])
@leader_required
@csrf.exempt
def admin_edit_event(event_id):
    ev = CyberEvent.query.get_or_404(event_id)
    data, error = _extract_event_form()
    if error:
        flash(error, 'danger')
        return redirect(url_for('events_page'))

    for key, val in data.items():
        setattr(ev, key, val)

    db.session.commit()
    flash(f"'{ev.title}' etkinliği başarıyla güncellendi.", 'success')
    return redirect(url_for('events_page'))

@app.route('/admin/event/delete/<int:event_id>', methods=['GET', 'POST'])
@leader_required
@csrf.exempt
def admin_delete_event(event_id):
    ev = CyberEvent.query.get_or_404(event_id)
    title = ev.title
    db.session.delete(ev)
    db.session.commit()
    flash(f"'{title}' etkinliği takvimden silindi.", 'info')
    return redirect(url_for('events_page'))

# ----------------- LAB SIMULATION & FLAG SUBMIT APIS ----------------- #

@app.route('/api/submit-flag', methods=['POST'])
@lab_access_required
@csrf.exempt
@limiter.limit("20 per minute")
def submit_flag():
    data = request.get_json() or {}
    lab_id = data.get('lab_id')
    submitted_flag = data.get('flag', '').strip()

    if not lab_id or not submitted_flag:
        return jsonify({'success': False, 'message': 'Eksik parametre gönderildi.'}), 400

    lab = Lab.query.get(lab_id)
    if not lab:
        return jsonify({'success': False, 'message': 'Laboratuvar bulunamadı.'}), 404

    user = User.query.get(session['user_id'])
    if not lab.is_published and not user.is_superadmin:
        return jsonify({'success': False, 'message': 'Bu laboratuvar henüz aktif değildir.'}), 403
    if lab.lab_type == 'multi_task':
        return jsonify({'success': False, 'message': 'Bu laboratuvar çoklu görev (Task) yapısına sahiptir; lütfen görev kartlarından bayrak gönderiniz.'}), 400
    progress = UserLabProgress.query.filter_by(user_id=user.id, lab_id=lab.id).first()

    if not progress:
        progress = UserLabProgress(user_id=user.id, lab_id=lab.id, attempts=1)
        db.session.add(progress)
    else:
        progress.attempts += 1

    # Check if already completed
    if progress.is_completed:
        return jsonify({
            'success': True,
            'already_completed': True,
            'message': 'Bu laboratuvarı daha önce zaten tamamladınız! Puanınız profilinizde kayıtlıdır.'
        })

    # Validate flag with timing-attack safe comparison (hmac.compare_digest)
    if hmac.compare_digest(submitted_flag.encode('utf-8'), lab.flag.encode('utf-8')):
        # First Blood kontrolü: Bu labı platformda daha önce çözen var mı?
        prior_solvers = UserLabProgress.query.filter_by(lab_id=lab.id, is_completed=True).count()
        is_first = (prior_solvers == 0)
        first_blood_bonus = 50 if is_first else 0

        # Dinamik Hız Bonusu: Labı ne kadar kısa sürede tamamlarsa o kadar yüksek ekstra puan kazanır
        time_limit = lab.time_limit_sec or 600
        now = datetime.utcnow()
        started_at = progress.started_at or now

        client_remaining = data.get('remaining_seconds')
        if client_remaining is not None:
            try:
                remaining_sec = max(0, min(time_limit, int(client_remaining)))
                elapsed_sec = max(1, time_limit - remaining_sec)
            except (ValueError, TypeError):
                elapsed_sec = max(1, int((now - started_at).total_seconds()))
                remaining_sec = max(0, time_limit - elapsed_sec)
        else:
            elapsed_sec = max(1, int((now - started_at).total_seconds()))
            remaining_sec = max(0, time_limit - elapsed_sec)

        # Taban puanın %50'sine kadar hız bonusu (kalan süre oranında)
        max_speed_bonus = int(lab.points * 0.50)
        speed_bonus = int(round(max_speed_bonus * (remaining_sec / time_limit))) if time_limit > 0 else 0

        total_earned = lab.points + first_blood_bonus + speed_bonus

        progress.is_completed = True
        progress.is_first_blood = is_first
        progress.speed_bonus = speed_bonus
        progress.solve_time_sec = elapsed_sec
        progress.earned_points = total_earned
        progress.completed_at = now
        user.score += total_earned
        db.session.commit()

        mins = elapsed_sec // 60
        secs = elapsed_sec % 60
        time_str = f"{mins:02d}:{secs:02d}"

        bonus_details = [f"+{lab.points} Taban Puan"]
        if speed_bonus > 0:
            bonus_details.append(f"⚡ +{speed_bonus} Hız Bonusu ({time_str} sürede)")
        if is_first:
            bonus_details.append("🩸 +50 İlk Kan Bonusu")

        msg = f"TEBRİKLER! Bayrak başarıyla doğrulandı! ({' + '.join(bonus_details)} = Toplam +{total_earned} Puan)"

        return jsonify({
            'success': True,
            'already_completed': False,
            'is_first_blood': is_first,
            'speed_bonus': speed_bonus,
            'elapsed_sec': elapsed_sec,
            'time_str': time_str,
            'earned_points': total_earned,
            'new_score': user.score,
            'message': msg
        })
    else:
        db.session.commit()
        return jsonify({
            'success': False,
            'message': 'Hatalı bayrak (Flag)! Tekrar analiz edin veya ipucunu inceleyin.'
        })

@app.route('/api/lab-task-submit/<slug>', methods=['POST'])
@lab_access_required
@csrf.exempt
@limiter.limit("40 per minute")
def submit_lab_task(slug):
    """Validate an individual task flag for a multi-task lab and award incremental points."""
    lab = Lab.query.filter_by(slug=slug).first_or_404()
    user = User.query.get(session['user_id'])
    if not lab.is_published and not user.is_superadmin:
        return jsonify({'success': False, 'message': 'Bu laboratuvar henüz aktif değildir.'}), 403

    cfg = MULTI_TASK_LABS.get(slug)
    if not cfg:
        return jsonify({'success': False, 'message': 'Çoklu görev yapılandırması bulunamadı.'}), 404

    data = request.get_json() or {}
    task_id = (data.get('task_id') or '').strip()
    submitted_flag = (data.get('flag') or '').strip()

    if not task_id or not submitted_flag:
        return jsonify({'success': False, 'message': 'Lütfen geçerli bir bayrak giriniz.'}), 400

    task = next((t for t in cfg['tasks'] if t['id'] == task_id), None)
    if not task:
        return jsonify({'success': False, 'message': 'Geçersiz görev kimliği.'}), 404

    progress = UserLabProgress.query.filter_by(user_id=user.id, lab_id=lab.id).first()
    if not progress:
        progress = UserLabProgress(
            user_id=user.id,
            lab_id=lab.id,
            attempts=1,
            solved_tasks='[]',
            earned_points=0
        )
        db.session.add(progress)
    else:
        progress.attempts = (progress.attempts or 0) + 1

    solved_tasks = progress.get_solved_tasks()
    candidates = task.get('accepted_flags') or [task['flag']]
    if not cfg.get('case_sensitive', True):
        is_match = any(
            hmac.compare_digest(submitted_flag.lower().encode('utf-8'), cand.lower().encode('utf-8'))
            for cand in candidates
        )
    else:
        is_match = any(
            hmac.compare_digest(submitted_flag.encode('utf-8'), cand.encode('utf-8'))
            for cand in candidates
        )

    if not is_match:
        db.session.commit()
        return jsonify({
            'success': False,
            'message': 'Yanlış cevap! Tekrar deneyin.'
        })

    if task_id in solved_tasks:
        db.session.commit()
        return jsonify({
            'success': True,
            'already_solved_task': True,
            'task_id': task_id,
            'task_points': task['points'],
            'solved_tasks': solved_tasks,
            'total_tasks': len(cfg['tasks']),
            'earned_points': progress.earned_points or 0,
            'lab_completed': bool(progress.is_completed),
            'newly_completed_lab': False,
            'is_first_blood': bool(progress.is_first_blood),
            'bonus_points': 0,
            'new_score': user.score,
            'message': 'Doğru cevap! Bu görevi daha önce tamamladığınız için mevcut puanınız korunuyor.'
        })

    solved_tasks.append(task_id)
    progress.set_solved_tasks(solved_tasks)
    task_pts = task['points']
    progress.earned_points = (progress.earned_points or 0) + task_pts
    user.score = (user.score or 0) + task_pts

    bonus_points = 0
    speed_bonus = 0
    newly_completed_lab = False
    if len(solved_tasks) == len(cfg['tasks']) and not progress.is_completed:
        prior_solvers = UserLabProgress.query.filter(
            UserLabProgress.lab_id == lab.id,
            UserLabProgress.is_completed == True,
            UserLabProgress.user_id != user.id
        ).count()
        is_first = (prior_solvers == 0)
        first_blood_bonus = 50 if is_first else 0

        # Dinamik Hız Bonusu
        time_limit = lab.time_limit_sec or 900
        now = datetime.utcnow()
        started_at = progress.started_at or now

        client_remaining = data.get('remaining_seconds')
        if client_remaining is not None:
            try:
                remaining_sec = max(0, min(time_limit, int(client_remaining)))
                elapsed_sec = max(1, time_limit - remaining_sec)
            except (ValueError, TypeError):
                elapsed_sec = max(1, int((now - started_at).total_seconds()))
                remaining_sec = max(0, time_limit - elapsed_sec)
        else:
            elapsed_sec = max(1, int((now - started_at).total_seconds()))
            remaining_sec = max(0, time_limit - elapsed_sec)

        max_speed_bonus = int(lab.points * 0.50)
        speed_bonus = int(round(max_speed_bonus * (remaining_sec / time_limit))) if time_limit > 0 else 0

        total_bonus = first_blood_bonus + speed_bonus
        bonus_points = total_bonus

        progress.is_completed = True
        progress.is_first_blood = is_first
        progress.speed_bonus = speed_bonus
        progress.solve_time_sec = elapsed_sec
        progress.completed_at = now
        progress.earned_points += bonus_points
        user.score += bonus_points
        newly_completed_lab = True

    db.session.commit()

    first_blood = lab.first_blood
    first_blood_username = first_blood.user.username if first_blood and first_blood.user else None

    if newly_completed_lab:
        bonus_texts = [f"+{task_pts} Görev Puanı"]
        if speed_bonus > 0:
            bonus_texts.append(f"⚡ +{speed_bonus} Hız Bonusu")
        if progress.is_first_blood:
            bonus_texts.append("🩸 +50 İlk Kan Bonusu")
        msg = f"🎉 Tebrikler! Tüm görevler tamamlandı! ({' + '.join(bonus_texts)})"
    else:
        msg = f'Tebrikler! Doğru cevap (+{task_pts} Puan).'

    return jsonify({
        'success': True,
        'already_solved_task': False,
        'task_id': task_id,
        'task_points': task_pts,
        'solved_tasks': solved_tasks,
        'total_tasks': len(cfg['tasks']),
        'earned_points': progress.earned_points,
        'lab_completed': bool(progress.is_completed),
        'newly_completed_lab': newly_completed_lab,
        'is_first_blood': bool(progress.is_first_blood),
        'bonus_points': bonus_points,
        'new_score': user.score,
        'first_blood_username': first_blood_username,
        'message': msg
    })

# ----------------- KADEMELİ İPUCU SİSTEMİ (Madde 3) ----------------- #

@app.route('/api/unlock-hint', methods=['POST'])
@lab_access_required
@csrf.exempt
def unlock_hint():
    data = request.get_json() or {}
    lab_id = data.get('lab_id')
    hint_num = int(data.get('hint_num', 1))

    lab = Lab.query.get_or_404(lab_id)
    user = User.query.get(session['user_id'])
    progress = UserLabProgress.query.filter_by(user_id=user.id, lab_id=lab.id).first()
    if not progress:
        progress = UserLabProgress(user_id=user.id, lab_id=lab.id)
        db.session.add(progress)

    if hint_num == 1:
        progress.hint1_unlocked = True
        db.session.commit()
        return jsonify({
            'success': True,
            'hint_num': 1,
            'hint_text': lab.get_hint1(),
            'cost': 0
        })
    elif hint_num == 2:
        cost = 10
        if not progress.hint2_unlocked:
            if user.score < cost:
                return jsonify({
                    'success': False,
                    'message': f'İleri ipucunu açmak için en az {cost} puana sahip olmalısınız. Mevcut puanınız: {user.score}'
                }), 400
            user.score = max(0, user.score - cost)
            progress.hint2_unlocked = True
            db.session.commit()

        return jsonify({
            'success': True,
            'hint_num': 2,
            'hint_text': lab.get_hint2(),
            'cost': cost,
            'new_score': user.score
        })
    return jsonify({'success': False, 'message': 'Geçersiz ipucu numarası.'}), 400

# ----------------- ÇÖZÜM RAPORLARI / WRITEUPS (Madde 3) ----------------- #

@app.route('/api/submit-writeup', methods=['POST'])
@lab_access_required
@csrf.exempt
def submit_writeup():
    data = request.get_json() or {}
    lab_id = data.get('lab_id')
    title = data.get('title', '').strip()
    content = data.get('content', '').strip()

    if not lab_id or not title or not content:
        return jsonify({'success': False, 'message': 'Lütfen başlık ve çözüm içeriğini eksiksiz doldurun.'}), 400

    lab = Lab.query.get_or_404(lab_id)
    user = User.query.get(session['user_id'])

    # Sadece labı çözmüş olanlar writeup yazabilir
    if not user.has_completed_lab(lab.id) and not user.is_superadmin:
        return jsonify({'success': False, 'message': 'Yalnızca bu laboratuvarı tamamlamış ajanlar writeup paylaşabilir.'}), 403

    writeup = LabWriteup(
        user_id=user.id,
        lab_id=lab.id,
        title=title,
        content=content
    )
    db.session.add(writeup)
    db.session.commit()

    return jsonify({
        'success': True,
        'message': 'Çözüm raporunuz (Writeup) başarıyla toplulukla paylaşıldı!'
    })

@app.route('/api/lab-writeups/<int:lab_id>', methods=['GET'])
@lab_access_required
def get_lab_writeups(lab_id):
    user = User.query.get(session['user_id'])
    lab = Lab.query.get_or_404(lab_id)

    # Spoiler koruması: Labı çözmemiş olan göremez (Süper Yönetici hariç)
    if not user.has_completed_lab(lab.id) and not user.is_superadmin:
        return jsonify({
            'success': False,
            'solved': False,
            'message': 'Spoiler Koruması: Çözüm raporlarını (Writeups) okuyabilmek için önce bu laboratuvarı kendiniz tamamlamalısınız.'
        }), 403

    writeups = LabWriteup.query.filter_by(lab_id=lab.id).order_by(LabWriteup.created_at.desc()).all()
    results = []
    for w in writeups:
        results.append({
            'id': w.id,
            'title': w.title,
            'content': w.content,
            'author': w.author.username,
            'created_at': w.created_at.strftime('%d.%m.%Y %H:%M'),
            'upvotes': w.upvotes
        })

    return jsonify({
        'success': True,
        'solved': True,
        'writeups': results
    })

# Interactive in-lab simulators (for rich lab interaction)
@app.route('/api/lab-action/<slug>', methods=['POST'])
@lab_access_required
@csrf.exempt
def lab_action(slug):
    lab = Lab.query.filter_by(slug=slug).first_or_404()
    user = User.query.get(session['user_id'])
    if not lab.is_published and not user.is_superadmin:
        return jsonify({'success': False, 'message': 'Bu laboratuvar henüz aktif değildir.'}), 403
    data = request.get_json() or {}
    payload = data.get('payload', '').strip()

    # SQL Injection Simulation
    if lab.slug == 'red-sqli-basic':
        sqli_patterns = ["' or '1'='1", "' or 1=1", "admin' --", "' union select", "' or true --"]
        lowered = payload.lower()
        if any(p in lowered for p in sqli_patterns):
            return jsonify({
                'success': True,
                'vulnerable': True,
                'output': [
                    {'id': 1, 'name': 'Laptop Dell XPS', 'category': 'Donanım', 'price': '35.000 TL'},
                    {'id': 2, 'name': 'Mekanik Klavye RGB', 'category': 'Aksesuar', 'price': '2.500 TL'},
                    {'id': 99, 'name': '*** SISTEM GIZLI YEDEK KAYDI ***', 'category': 'DATABASE_SECRET', 'price': 'FLAG{sql1_inj3ct10n_succ3ss_4z1z}'}
                ],
                'log': f"[SQL DEBUG] Executed query: SELECT * FROM products WHERE name LIKE '%{payload}%' -> Return count: 3 (AUTH_BYPASS_DETECTED)"
            })
        else:
            return jsonify({
                'success': True,
                'vulnerable': False,
                'output': [
                    {'id': 1, 'name': f'Sonuç: "{payload}" ile eşleşen ürün bulunamadı.', 'category': '-', 'price': '-'}
                ],
                'log': f"[SQL DEBUG] Executed query: SELECT * FROM products WHERE name LIKE '%{payload}%' -> Return count: 0"
            })

    # XSS Simulation
    elif lab.slug == 'red-xss-reflected':
        if '<script>' in payload.lower() or 'onerror=' in payload.lower() or 'onload=' in payload.lower():
            return jsonify({
                'success': True,
                'triggered': True,
                'alert_message': 'XSS Başarılı! Simüle Edilen Yönetici Oturum Çerezi: admin_session_token=FLAG{xss_cr0ss_s1t3_scr1pt1ng_2026}; path=/; HttpOnly=False',
                'raw_render': payload
            })
        else:
            return jsonify({
                'success': True,
                'triggered': False,
                'raw_render': payload,
                'message': 'Girdi filtrelenmeden yazıldı ancak çalıştırılabilir bir XSS payload (script veya event handler) tespit edilmedi.'
            })

    # Phishing Header Simulation
    elif lab.slug == 'red-phishing-analysis':
        return jsonify({
            'success': True,
            'headers': {
                'From': '"Microsoft Security Team" <security-alert@micr0s0ft-security-auth.net>',
                'To': 'victim.user@sirket.com',
                'Subject': 'ACIL: Hesabiniz 24 Saat Icinde Askıya Alınacak',
                'SPF': 'FAIL (micr0s0ft-security-auth.net: domain does not match official SPF)',
                'DKIM': 'NONE',
                'Return-Path': '<attacker_dropzone@evil-c2-server.ru>',
                'Form_Action_URL': 'https://login.micr0s0ft-security-auth.net/harvest.php?c2_secret=FLAG{ph1sh1ng_h34d3r_4n4lys1s_2026}'
            }
        })

    # Blue Team - Log Analysis Simulation
    elif lab.slug == 'blue-log-analysis':
        filter_term = payload.lower()
        all_logs = [
            '192.168.1.45 - - [15/Nov/2026:02:40:11] "GET /index.html HTTP/1.1" 200 4521',
            '192.168.1.45 - - [15/Nov/2026:02:40:15] "GET /assets/style.css HTTP/1.1" 200 1204',
            '45.33.32.156 - - [15/Nov/2026:03:00:01] "GET /robots.txt HTTP/1.1" 404 162',
            '45.33.32.156 - - [15/Nov/2026:03:00:02] "GET /admin HTTP/1.1" 404 162',
            '45.33.32.156 - - [15/Nov/2026:03:00:03] "GET /wp-login.php HTTP/1.1" 404 162',
            '45.33.32.156 - - [15/Nov/2026:03:00:04] "GET /phpmyadmin HTTP/1.1" 404 162',
            '45.33.32.156 - - [15/Nov/2026:03:00:05] "GET /backup.sql HTTP/1.1" 404 162',
            '45.33.32.156 - - [15/Nov/2026:03:00:06] "GET /admin-secret-backup.zip HTTP/1.1" 200 894512 [X-Flag: FLAG{blu3_l0g_4n4lys1s_d3t3ct3d}]',
            '10.0.0.12 - - [15/Nov/2026:03:05:10] "GET /api/health HTTP/1.1" 200 35',
        ]
        if filter_term:
            filtered = [l for l in all_logs if filter_term in l.lower()]
        else:
            filtered = all_logs
        return jsonify({'success': True, 'logs': filtered})

    # Blue Team - Forensics Simulation
    elif lab.slug == 'blue-digital-forensics':
        return jsonify({
            'success': True,
            'hex_view': [
                '00000000  FF D8 FF E0 00 10 4A 46  49 46 00 01 01 01 00 48  |......JFIF.....H|',
                '00000010  00 48 00 00 FF DB 00 43  00 08 06 06 07 06 05 08  |.H.....C........|',
                '00000020  07 07 07 09 09 08 0A 0C  14 0D 0C 0B 0B 0C 19 12  |................|',
                '000000F0  C0 25 32 4E 76 89 FF D9  46 4C 41 47 7B 64 31 67  |.%2Nv..FLAG{d1g|',
                '00000100  31 74 34 6C 5F 66 30 72  36 6E 73 31 63 73 5F 63  |1t4l_f0r6ns1cs_c|',
                '00000110  34 72 76 33 64 5F 66 31  6C 33 7D 0A 00 00 00 00  |4rv3d_f1l3}.....|'
            ],
            'note': 'JPEG dosyasının standart sonlandırıcı baytları FF D9 değeridir. Bu değerin ardındaki verileri inceleyin!'
        })

    # Blue Team - Firewall Simulation
    elif lab.slug == 'blue-firewall-defense':
        rule = payload.lower()
        if 'drop' in rule and ('45.33.32.156' in rule or 'input' in rule):
            return jsonify({
                'success': True,
                'blocked': True,
                'message': 'GÜVENLİK DUVARI KURALLARI UYGULANDI! Saldırgan paketleri başarıyla engellendi. FLAG: FLAG{f1r3w4ll_d3f3nd_blu3_t34m}'
            })
        else:
            return jsonify({
                'success': True,
                'blocked': False,
                'message': 'Kural uygulanamadı veya yetersiz filtreleme. Örnek doğru kural: iptables -A INPUT -s 45.33.32.156 -j DROP'
            })

    return jsonify({'success': False, 'message': 'Bilinmeyen simülasyon türü.'})

if __name__ == '__main__':
    debug_mode = os.environ.get('FLASK_DEBUG', 'True').lower() in ('true', '1')
    port = int(os.environ.get('PORT', 5000))
    host = os.environ.get('HOST', '0.0.0.0')
    print(f"[*] Siber Güvenlik Eğitim Platformu Başlatılıyor... (Debug Modu: {debug_mode})")
    print(f"[*] Adres: http://{host}:{port}")
    app.run(host=host, port=port, debug=debug_mode)
