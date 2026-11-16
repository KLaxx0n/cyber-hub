import os
import re
import secrets
import string
import hmac
from datetime import datetime, timedelta
from functools import wraps
from urllib.parse import urlsplit

from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from sqlalchemy import func

from config import Config
from models import db, User, Lab, UserLabProgress
from seed_data import seed_database
from mail_service import send_verification_email

app = Flask(__name__)
app.config.from_object(Config)

# Güvenlik Eklentileri
csrf = CSRFProtect(app)
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["1000 per day", "200 per hour"],
    storage_uri="memory://"
)

db.init_app(app)

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

# Helper: Login Required Decorator
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Bu sayfayı görüntülemek için lütfen önce giriş yapınız.', 'warning')
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

# Helper: Leader Required Decorator (Team Leaders & SuperAdmins)
def leader_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Bu sayfayı görüntülemek için lütfen önce giriş yapınız.', 'warning')
            return redirect(url_for('login', next=request.url))
        user = User.query.get(session['user_id'])
        if not user or not user.is_team_leader:
            flash('Bu sayfaya erişim yetkiniz bulunmamaktadır. Yalnızca Takım Liderleri ve Süper Yöneticiler görüntüleyebilir.', 'danger')
            return redirect(url_for('dashboard'))
        return f(*args, **kwargs)
    return decorated_function

# Helper: SuperAdmin / Root Required Decorator (Highest Authority)
def superadmin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            flash('Bu sayfayı görüntülemek için lütfen önce giriş yapınız.', 'warning')
            return redirect(url_for('login', next=request.url))
        user = User.query.get(session['user_id'])
        if not user or not user.is_superadmin:
            flash('Bu kritik işlem için yetkiniz yetersiz. Yalnızca Süper Yönetici (Root) gerçekleştirebilir.', 'danger')
            return redirect(url_for('admin_panel'))
        return f(*args, **kwargs)
    return decorated_function

# Context Processor for Nav and Auth State
@app.context_processor
def inject_user():
    current_user = None
    if 'user_id' in session:
        current_user = User.query.get(session['user_id'])
    return dict(current_user=current_user)

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

@app.route('/')
def index():
    total_users = User.query.filter_by(is_verified=True).count()
    total_labs = Lab.query.count()
    red_labs = Lab.query.filter_by(category='red_team').count()
    blue_labs = Lab.query.filter_by(category='blue_team').count()
    top_users = User.query.filter_by(is_verified=True).order_by(User.score.desc()).limit(5).all()
    return render_template('index.html', 
                           total_users=total_users, 
                           total_labs=total_labs,
                           red_labs=red_labs,
                           blue_labs=blue_labs,
                           top_users=top_users)

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')

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

        # Create user (Always non-founder by default)
        new_user = User(
            username=username,
            email=email,
            is_verified=False,
            verification_code=code,
            verification_code_expires_at=expires_at,
            is_leader=False,
            is_founder=False,
            score=0
        )
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        # Send Verification Email via SMTP
        email_sent, email_msg = send_verification_email(email, username, code)
        if email_sent:
            flash(f'Kayıt başarılı! 6 haneli doğrulama kodunuz {email} adresine gönderildi. Lütfen gelen kutunuzu kontrol ediniz.', 'success')
        else:
            flash(f'Kayıt oluşturuldu fakat e-posta iletilemedi: {email_msg}', 'warning')
        
        return redirect(url_for('verify', email=email))

    return render_template('register.html')

@app.route('/resend-verification', methods=['POST'])
@limiter.limit("3 per minute")
def resend_verification():
    email = request.form.get('email', '').strip().lower()
    user = User.query.filter_by(email=email).first()
    if not user:
        flash('Kullanıcı bulunamadı.', 'danger')
        return redirect(url_for('register'))
    if user.is_verified:
        flash('Hesabınız zaten doğrulanmış. Giriş yapabilirsiniz.', 'info')
        return redirect(url_for('login'))

    new_code = generate_verification_code()
    user.verification_code = new_code
    user.verification_code_expires_at = datetime.utcnow() + timedelta(minutes=15)
    db.session.commit()

    email_sent, email_msg = send_verification_email(email, user.username, new_code)
    if email_sent:
        flash(f'Yeni doğrulama kodunuz {email} adresine tekrar gönderildi.', 'success')
    else:
        flash(f'Yeni kod oluşturuldu fakat e-posta iletilemedi: {email_msg}', 'warning')
        
    return redirect(url_for('verify', email=email))

@app.route('/verify', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def verify():
    email = request.args.get('email', '') or request.form.get('email', '')

    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        code = request.form.get('code', '').strip().upper()

        user = User.query.filter_by(email=email).first()
        if not user:
            flash('Kullanıcı bulunamadı. Lütfen e-posta adresinizi kontrol edin.', 'danger')
            return render_template('verify.html', email=email)

        if user.is_verified:
            flash('Hesabınız zaten onaylanmış! Giriş yapabilirsiniz.', 'success')
            return redirect(url_for('login'))

        if not user.verification_code or not user.verification_code_expires_at:
            flash('Geçerli bir doğrulama kodu bulunamadı. Lütfen "Kodu Tekrar Gönder" butonuna tıklayınız.', 'danger')
            return render_template('verify.html', email=email)

        # 15 dakikalık süre aşımı kontrolü
        if datetime.utcnow() > user.verification_code_expires_at:
            flash('Doğrulama kodunun geçerlilik süresi (15 dakika) dolmuştur. Lütfen yeni kod talep ediniz.', 'danger')
            return render_template('verify.html', email=email)

        # Zamanlama saldırılarına karşı güvenli karşılaştırma (Constant time compare)
        if secrets.compare_digest(user.verification_code.upper(), code.upper()):
            user.is_verified = True
            user.verification_code = None
            user.verification_code_expires_at = None
            db.session.commit()
            flash('Hesabınız başarıyla doğrulandı! Şimdi giriş yapabilirsiniz.', 'success')
            return redirect(url_for('login'))
        else:
            flash('Hatalı doğrulama kodu! Lütfen e-postanıza gelen kodu kontrol ediniz.', 'danger')
            return render_template('verify.html', email=email)

    return render_template('verify.html', email=email)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("6 per minute")
def login():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        login_id = request.form.get('login_id', '').strip()
        password = request.form.get('password', '')

        if not login_id or not password:
            flash('Lütfen kullanıcı adı/e-posta ve şifrenizi girin.', 'danger')
            return render_template('login.html', login_id=login_id)

        user = User.query.filter((func.lower(User.username) == login_id.lower()) | (func.lower(User.email) == login_id.lower())).first()

        if not user or not user.check_password(password):
            flash('Geçersiz kullanıcı adı/e-posta veya şifre.', 'danger')
            return render_template('login.html', login_id=login_id)

        if not user.is_verified:
            flash('Hesabınız henüz onaylanmamış. Lütfen e-postanıza gönderilen doğrulama kodunu girin.', 'warning')
            # demo_code URL sızıntısı giderildi - sadece e-posta ile yönlendiriliyor
            return redirect(url_for('verify', email=user.email))

        # Login success - Oturum fiksasyonu koruması
        session.clear()
        session['user_id'] = user.id
        session['username'] = user.username
        flash(f'Hoş geldin, Ajan {user.username}! Sisteme güvenli bağlantı kuruldu.', 'success')
        
        # Açık Yönlendirme (Open Redirect) Koruması
        next_url = request.args.get('next')
        if next_url and is_safe_url(next_url):
            return redirect(next_url)
        return redirect(url_for('dashboard'))

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('Oturum başarıyla sonlandırıldı. Güvenli çıkış yapıldı.', 'info')
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    
    # Calculate user rank among verified active users
    rank = User.query.filter(User.is_verified == True, User.score > user.score).count() + 1
    
    # User's solved labs
    completed_progress = UserLabProgress.query.filter_by(user_id=user.id, is_completed=True).order_by(UserLabProgress.completed_at.desc()).all()
    completed_lab_ids = [p.lab_id for p in completed_progress]

    # Category stats
    total_red = Lab.query.filter_by(category='red_team').count() or 1
    total_blue = Lab.query.filter_by(category='blue_team').count() or 1

    completed_red = Lab.query.filter(Lab.id.in_(completed_lab_ids), Lab.category == 'red_team').count() if completed_lab_ids else 0
    completed_blue = Lab.query.filter(Lab.id.in_(completed_lab_ids), Lab.category == 'blue_team').count() if completed_lab_ids else 0

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
    leader_count = sum(1 for u in all_users if u.is_team_leader and not u.is_superadmin)
    student_count = sum(1 for u in all_users if not u.is_team_leader)
    total_completed = UserLabProgress.query.filter_by(is_completed=True).count()
    total_score = sum(u.score for u in all_users)
    
    return render_template('admin.html',
                           users=all_users,
                           total_users=total_users,
                           verified_users=verified_users,
                           unverified_users=unverified_users,
                           red_count=red_count,
                           blue_count=blue_count,
                           superadmin_count=superadmin_count,
                           leader_count=leader_count,
                           student_count=student_count,
                           total_completed=total_completed,
                           total_score=total_score)

@app.route('/admin/set-team/<int:user_id>', methods=['POST'])
@leader_required
def admin_set_team(user_id):
    target_user = User.query.get_or_404(user_id)
    new_team = request.form.get('team', 'unassigned')
    if new_team not in ['red_team', 'blue_team', 'unassigned']:
        flash('Geçersiz takım seçimi.', 'danger')
        return redirect(url_for('admin_panel'))
    
    target_user.assigned_team = new_team
    db.session.commit()

    team_labels = {
        'red_team': 'Red Team (Saldırı)',
        'blue_team': 'Blue Team (Savunma)',
        'unassigned': 'Atanmamış'
    }
    flash(f"'{target_user.username}' öğrencisi başarıyla {team_labels.get(new_team)} grubuna atandı.", 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/verify/<int:user_id>', methods=['POST'])
@leader_required
def admin_verify_user(user_id):
    target_user = User.query.get_or_404(user_id)
    target_user.is_verified = True
    target_user.verification_code = None
    target_user.verification_code_expires_at = None
    db.session.commit()
    flash(f"'{target_user.username}' kullanıcısı lider onayıyla başarıyla doğrulandı.", 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/delete/<int:user_id>', methods=['POST'])
@superadmin_required
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

@app.route('/admin/set-role/<int:user_id>', methods=['POST'])
@superadmin_required
def admin_set_role(user_id):
    target_user = User.query.get_or_404(user_id)
    current_u = User.query.get(session.get('user_id'))
    new_role = request.form.get('role', 'student')
    
    if new_role not in ['student', 'leader', 'superadmin']:
        flash('Geçersiz rol seçimi.', 'danger')
        return redirect(url_for('admin_panel'))
        
    if target_user.id == current_u.id and new_role != 'superadmin':
        flash('Kendi Süper Yönetici yetkinizi kaldıramazsınız.', 'danger')
        return redirect(url_for('admin_panel'))

    if target_user.is_founder and new_role != 'superadmin':
        flash('Kurucu hesapların Süper Yönetici rolü düşürülemez.', 'warning')
        return redirect(url_for('admin_panel'))
        
    target_user.role = new_role
    target_user.is_leader = (new_role in ['leader', 'superadmin'])
    db.session.commit()
    
    role_names = {
        'superadmin': 'Süper Yönetici (Root)',
        'leader': 'Takım Lideri',
        'student': 'Öğrenci'
    }
    flash(f"'{target_user.username}' kullanıcısının rolü '{role_names.get(new_role)}' olarak güncellendi.", 'success')
    return redirect(url_for('admin_panel'))

@app.route('/admin/adjust-score/<int:user_id>', methods=['POST'])
@superadmin_required
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

@app.route('/admin/toggle-leader/<int:user_id>', methods=['POST'])
@superadmin_required
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

@app.route('/red-team')
def red_team():
    labs = Lab.query.filter_by(category='red_team').all()
    user_completed_ids = []
    if 'user_id' in session:
        user_completed_ids = [p.lab_id for p in UserLabProgress.query.filter_by(user_id=session['user_id'], is_completed=True).all()]
    return render_template('red_team.html', labs=labs, user_completed_ids=user_completed_ids)

@app.route('/blue-team')
def blue_team():
    labs = Lab.query.filter_by(category='blue_team').all()
    user_completed_ids = []
    if 'user_id' in session:
        user_completed_ids = [p.lab_id for p in UserLabProgress.query.filter_by(user_id=session['user_id'], is_completed=True).all()]
    return render_template('blue_team.html', labs=labs, user_completed_ids=user_completed_ids)

@app.route('/lab/<slug>')
@login_required
def lab_detail(slug):
    lab = Lab.query.filter_by(slug=slug).first_or_404()
    user = User.query.get(session['user_id'])
    
    progress = UserLabProgress.query.filter_by(user_id=user.id, lab_id=lab.id).first()
    is_solved = progress.is_completed if progress else False

    return render_template('lab_detail.html', lab=lab, is_solved=is_solved, progress=progress)

@app.route('/leaderboard')
def leaderboard():
    users = User.query.filter_by(is_verified=True).order_by(User.score.desc(), User.created_at.asc()).all()
    return render_template('leaderboard.html', users=users)

# ----------------- LAB SIMULATION & FLAG SUBMIT APIS ----------------- #

@app.route('/api/submit-flag', methods=['POST'])
@login_required
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
        progress.is_completed = True
        progress.earned_points = lab.points
        progress.completed_at = datetime.utcnow()
        user.score += lab.points
        db.session.commit()

        return jsonify({
            'success': True,
            'already_completed': False,
            'earned_points': lab.points,
            'new_score': user.score,
            'message': f'TEBRİKLER! Bayrak başarıyla doğrulandı. +{lab.points} Puan kazandınız!'
        })
    else:
        db.session.commit()
        return jsonify({
            'success': False,
            'message': 'Hatalı bayrak (Flag)! Tekrar analiz edin veya ipucunu inceleyin.'
        })

# Interactive in-lab simulators (for rich lab interaction)
@app.route('/api/lab-action/<slug>', methods=['POST'])
@login_required
@csrf.exempt
def lab_action(slug):
    lab = Lab.query.filter_by(slug=slug).first_or_404()
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
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() in ('true', '1')
    print(f"[*] Siber Güvenlik Eğitim Platformu Başlatılıyor... (Debug Modu: {debug_mode})")
    print("[*] Adres: http://127.0.0.1:5000")
    app.run(host='127.0.0.1', port=5000, debug=debug_mode)
