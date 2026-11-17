from datetime import datetime, timedelta
from models import db, Lab, User
from werkzeug.security import generate_password_hash

def seed_database(app):
    with app.app_context():
        db.create_all()

        # Otomatik Tablo Sütun Migrasyonu (PostgreSQL & SQLite Uyumlu)
        def safe_add_column(engine, table_name, column_name, column_def):
            from sqlalchemy import inspect, text
            try:
                inspector = inspect(engine)
                if table_name in inspector.get_table_names():
                    columns = [c['name'] for c in inspector.get_columns(table_name)]
                    if column_name not in columns:
                        with engine.connect() as conn:
                            conn.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_def}"))
                            conn.commit()
                        print(f"[+] Sütun eklendi: {table_name}.{column_name}")
            except Exception as e:
                print(f"[!] Sütun kontrolü ({table_name}.{column_name}): {e}")

        # Users tablosu sütunları
        safe_add_column(db.engine, 'users', 'failed_login_attempts', 'INTEGER DEFAULT 0')
        safe_add_column(db.engine, 'users', 'is_suspended', 'BOOLEAN DEFAULT FALSE')
        safe_add_column(db.engine, 'users', 'reset_token', 'VARCHAR(64)')
        safe_add_column(db.engine, 'users', 'reset_token_expires_at', 'TIMESTAMP')
        safe_add_column(db.engine, 'users', 'totp_secret', 'VARCHAR(64)')
        safe_add_column(db.engine, 'users', 'two_factor_enabled', 'BOOLEAN DEFAULT FALSE')

        # Labs tablosu sütunları
        safe_add_column(db.engine, 'labs', 'hint1', 'TEXT')
        safe_add_column(db.engine, 'labs', 'hint2', 'TEXT')

        # UserLabProgress tablosu sütunları
        safe_add_column(db.engine, 'user_lab_progress', 'is_first_blood', 'BOOLEAN DEFAULT FALSE')
        safe_add_column(db.engine, 'user_lab_progress', 'hint1_unlocked', 'BOOLEAN DEFAULT FALSE')
        safe_add_column(db.engine, 'user_lab_progress', 'hint2_unlocked', 'BOOLEAN DEFAULT FALSE')

        # Predefined Labs based on project report
        labs_data = [
            # RED TEAM LABS
            {
                'slug': 'red-sqli-basic',
                'title': 'OWASP Top 10: SQL Injection Zafiyeti',
                'category': 'red_team',
                'sub_category': 'OWASP Top 10 & Flag Hunting',
                'difficulty': 'Başlangıç',
                'points': 100,
                'time_limit_sec': 600, # 10 minutes
                'description': 'Web uygulamalarında en sık rastlanan kritik açıklardan biri olan SQL Injection (A03:2021) mantığını kavrayın ve yetkisiz veri çekimi gerçekleştirin.',
                'scenario': 'Hedef web uygulamasında ürün arama filtresi doğrudan SQL sorgusu oluşturmaktadır: SELECT * FROM products WHERE name LIKE \'%{input}%\'. Girdi filtresi bulunmamaktadır.',
                'instructions': 'Arama çubuğuna özel karakterler ve Boolean mantık ifadeleri (\' OR \'1\'=\'1) girerek gizli "Gizli_Sistem_Kayitlari" tablosundaki verileri sızdırın ve gizli Flag değerine ulaşın.',
                'hint': 'SQL sorgularını manipüle etmek için tırnak işareti (\') ve her zaman doğru olan bir koşul (OR 1=1) kullanmayı deneyin.',
                'hint1': 'SQL sorgularını manipüle etmek için tırnak işareti (\') ve her zaman doğru olan bir koşul (OR 1=1) kullanmayı deneyin.',
                'hint2': 'Kritik İpucu (-10 Puan): Arama çubuğuna \' OR \'1\'=\'1 payloadını girerek arka plandaki WHERE filtresini devre dışı bırakabilir ve gizli tablodaki FLAG değerini listeleyebilirsiniz.',
                'flag': 'FLAG{sql1_inj3ct10n_succ3ss_4z1z}',
                'lab_type': 'sqli'
            },
            {
                'slug': 'red-xss-reflected',
                'title': 'OWASP Top 10: Reflected XSS (Siteler Arası Betik)',
                'category': 'red_team',
                'sub_category': 'OWASP Top 10 & Flag Hunting',
                'difficulty': 'Orta',
                'points': 150,
                'time_limit_sec': 480, # 8 minutes
                'description': 'Kullanıcı girdisinin HTML encode edilmeden ekrana basılması durumunda JavaScript kodu çalıştırılması ve oturum hırsızlığı simülasyonu.',
                'scenario': 'Geri bildirim formunda girilen kullanıcı adı ve mesaj parametreleri herhangi bir sanitize işlemine tabi tutulmadan doğrudan tarayıcı DOM nesnesine yazdırılmaktadır.',
                'instructions': 'Ziyaretçi adına <script>alert(document.cookie)</script> veya modern bir payload yerleştirerek simüle edilen XSS botunu tetikleyin ve admin token flagini yakalayın.',
                'hint': '<script> veya <img src=x onerror=...> etiketleri DOM enjeksiyonu için kullanılabilir.',
                'hint1': '<script> veya <img src=x onerror=...> etiketleri DOM enjeksiyonu için kullanılabilir.',
                'hint2': 'Kritik İpucu (-10 Puan): Ziyaretçi adına <script>alert(document.cookie)</script> yazıp gönderdiğinizde simülatör yönetici botunu çalıştıracak ve alert mesajında admin oturum bayrağını (FLAG{xss...}) döndürecektir.',
                'flag': 'FLAG{xss_cr0ss_s1t3_scr1pt1ng_2026}',
                'lab_type': 'xss'
            },
            {
                'slug': 'red-phishing-analysis',
                'title': 'Sosyal Mühendislik & Oltalama (Phishing) Simülatörü',
                'category': 'red_team',
                'sub_category': 'Sosyal Mühendislik',
                'difficulty': 'Orta',
                'points': 150,
                'time_limit_sec': 600, # 10 minutes
                'description': 'Hazırlanmış sahte bir web portalı ve oltalama e-postası üzerinden saldırı vektörünü, sahte alan adını ve saldırgan sunucusunu analiz edin.',
                'scenario': 'Şirket çalışanlarına "Hesabınız askıya alınacak, acil şifre yenileyin" konulu sahte bir Microsoft 365 e-postası iletilmiştir. E-postadaki link sahte bir login sayfasına yönlendirmektedir.',
                'instructions': 'E-posta başlıklarını (SPF, DKIM, Return-Path) ve sahte login sayfasının kaynak kodunu inceleyin. Saldırganın form action adresinde gizlediği izleme kodunu (Flag) bulun.',
                'hint': 'E-posta kaynak kodundaki (Header) "Return-Path" ve formun POST edildiği URL adresine dikkat edin.',
                'hint1': 'E-posta kaynak kodundaki (Header) "Return-Path" ve formun POST edildiği URL adresine dikkat edin.',
                'hint2': 'Kritik İpucu (-10 Puan): E-posta kaynak detaylarında Return-Path adresinin gerçek Microsoft olmayıp saldırgan C2 sunucusuna (phish-trap.xyz) çıktığını ve form action adresinde FLAG parametresinin iletildiğini görebilirsiniz.',
                'flag': 'FLAG{ph1sh1ng_h34d3r_4n4lys1s_2026}',
                'lab_type': 'phishing'
            },

            # BLUE TEAM LABS
            {
                'slug': 'blue-log-analysis',
                'title': 'Sunucu Log Analizi & Saldırı Tespiti',
                'category': 'blue_team',
                'sub_category': 'Log Analizi & Savunma',
                'difficulty': 'Başlangıç',
                'points': 100,
                'time_limit_sec': 600, # 10 minutes
                'description': 'Gerçek bir Linux sunucusu Nginx/Apache erişim loglarını (access.log) inceleyerek saldırgan IP adresini ve saldırı tekniğini belirleyin.',
                'scenario': 'Sistem yöneticisi gece 03:00 sularında sunucu yükünün aşırı arttığını fark etmiştir. Log kayıtlarında binlerce 404 ve 200 HTTP yanıtı bulunmaktadır.',
                'instructions': 'Verilen log kayıtlarını filtreleyin. Dizin taraması (directory brute force) yapan ve sonunda /admin-secret-backup.zip dosyasına erişen saldırganın IP adresini ve dosya imzasındaki Flag değerini bulun.',
                'hint': 'En çok istek atan IP adresini bulun ve 200 OK koduyla indirdiği gizli dosyanın yanıtına bakın.',
                'hint1': 'En çok istek atan IP adresini bulun ve 200 OK koduyla indirdiği gizli dosyanın yanıtına bakın.',
                'hint2': 'Kritik İpucu (-10 Puan): 192.168.1.105 IP adresi Gobuster ile tarama yapmış ve /admin-secret-backup.zip dosyasını başarıyla indirmiştir. Dosya hash/indirme logunda FLAG{blue_log...} yer almaktadır.',
                'flag': 'FLAG{blu3_l0g_4n4lys1s_d3t3ct3d}',
                'lab_type': 'log_analysis'
            },
            {
                'slug': 'blue-digital-forensics',
                'title': 'Digital Forensics (Rəqəmsal Kriminalistika) & Dosya Kurtarma',
                'category': 'blue_team',
                'sub_category': 'Dijital Adli Bilişim',
                'difficulty': 'İleri',
                'points': 200,
                'time_limit_sec': 720, # 12 minutes
                'description': 'Silinmiş dosyaların analizi, Hex dump incelemesi, dosya başlıkları (Magic Bytes / File Signatures) ve gizlenmiş delil verisini kurtarma.',
                'scenario': 'Ele geçirilen bir şüpheli bellek dökümünde bir JPEG dosyasının sonuna Base64 şifrelenmiş veri eklenmiş ve dosya tablosundan silinmiştir.',
                'instructions': 'Verilen ham Hex dökümünü inceleyin. JPEG dosya bitiş imzasını (FF D9) bulun ve ardından gelen gizli kanıt dizgisini deşifre ederek Bayrağa (Flag) ulaşın.',
                'hint': 'Hex görünümünde FFD9 sonrasındaki karakterleri ASCII ve Base64 çözücüye aktarın.',
                'hint1': 'Hex görünümünde FFD9 sonrasındaki karakterleri ASCII ve Base64 çözücüye aktarın.',
                'hint2': 'Kritik İpucu (-10 Puan): FFD9 baytından hemen sonra başlayan RkxBR3tkMWcx... dizgisi Base64 kodludur; decode edildiğinde doğrudan adli bilişim bayrağını verir.',
                'flag': 'FLAG{d1g1t4l_f0r3ns1cs_c4rv3d_f1l3}',
                'lab_type': 'forensics'
            },
            {
                'slug': 'blue-firewall-defense',
                'title': 'Aktif Savunma: Güvenlik Duvarı & Kural Yapılandırma',
                'category': 'blue_team',
                'sub_category': 'Ağ Güvenliği & Savunma',
                'difficulty': 'Orta',
                'points': 120,
                'time_limit_sec': 480, # 8 minutes
                'description': 'Tehdit altındaki sistem için gelen şüpheli TCP/SYN paketlerini filtreleyen doğru firewall kurallarını oluşturma ve servisi koruma.',
                'scenario': 'Sunucu belirli bir IP bloğundan gelen yoğun SYN Flood ve SSH Port 22 brute force saldırısıyla karşı karşıyadır.',
                'instructions': 'Doğru iptables kuralını seçin/uygulayın: Saldırgan subnetini engelleyin ve meşru web trafiğine (Port 80/443) izin vererek savunmayı tamamlayın.',
                'hint': 'iptables -A INPUT -s <IP> -j DROP ve SSH için port 22 rate-limiting kuralları kullanılmalıdır.',
                'hint1': 'iptables -A INPUT -s <IP> -j DROP ve SSH için port 22 rate-limiting kuralları kullanılmalıdır.',
                'hint2': 'Kritik İpucu (-10 Puan): 10.0.0.0/24 subnetinden gelen web saldırılarını engelleyen "iptables -A INPUT -s 10.0.0.0/24 -p tcp --dport 80 -j DROP" kuralını seçiniz.',
                'flag': 'FLAG{f1r3w4ll_d3f3nd_blu3_t34m}',
                'lab_type': 'firewall'
            },
            # PURPLE TEAM LABS
            {
                'slug': 'purple-malware-analysis',
                'title': 'Zararlı Yazılım Analizi & Statik Tersine Mühendislik',
                'category': 'purple_team',
                'sub_category': 'Malware Analysis & Reverse Engineering',
                'difficulty': 'İleri',
                'points': 200,
                'time_limit_sec': 600,
                'description': 'Zararlı yazılım örneklerini (malware binary) statik analiz ve dizgi ayıklama yöntemiyle inceleyin, C2 komuta kontrol sunucusunu ve bayrağı ortaya çıkarın.',
                'scenario': 'Ağda tespit edilen şüpheli arka kapı yazılımı (updater_agent.bin) güvenlik ortamına alındı. Kodun bağlantı kurduğu C2 alan adı ve gömülü bayrak deşifre edilmelidir.',
                'instructions': 'Zararlı yazılımın ikili (binary) verisi içerisindeki fonksiyon imzalarını ve Base64/XOR ile gizlenmiş dizgileri inceleyerek gizli FLAG değerine ulaşın.',
                'hint': 'Statik analiz araçlarında dizgileri tarayarak FLAG{...} formatındaki gizli bayrağı arayın.',
                'hint1': 'Statik analiz araçlarında dizgileri tarayarak FLAG{...} formatındaki gizli bayrağı arayın.',
                'hint2': 'Kritik İpucu (-10 Puan): Binary içindeki .rdata segmentinde "c2_connect_beacon" fonksiyonu parametresinde açık ASCII metni olarak FLAG{purpl3_m4lw4r3_r3v3rs3_4n4lys1s} yer almaktadır.',
                'flag': 'FLAG{purpl3_m4lw4r3_r3v3rs3_4n4lys1s}',
                'lab_type': 'standard'
            },
            {
                'slug': 'purple-atomic-emulation',
                'title': 'Atomic Tehdit Emülasyonu & Tespit Doğrulama',
                'category': 'purple_team',
                'sub_category': 'Adversary Emulation & MITRE ATT&CK',
                'difficulty': 'Orta',
                'points': 150,
                'time_limit_sec': 540,
                'description': 'MITRE ATT&CK T1059 (Komut ve Betik Yorumlayıcı) tekniği simülasyonunu çalıştırarak savunma katmanının (SIEM/EDR) saldırıyı yakalayıp yakalamadığını test edin.',
                'scenario': 'Saldırganlar sistem üzerinde PowerShell ile dosyasız zararlı çalıştırmaktadır. Purple Team testinde saldırı ve savunma telemetrileri eş zamanlı analiz edilir.',
                'instructions': 'Purple Team senaryosunda saldırı adımlarını emüle edin, ardından SIEM tespit günlüğünü inceleyerek oluşturulan telemetri bayrağını teslim edin.',
                'hint': 'PowerShell Script Block Logging (Event ID 4104) olay kaydını inceleyin.',
                'hint1': 'PowerShell Script Block Logging (Event ID 4104) olay kaydını inceleyin.',
                'hint2': 'Kritik İpucu (-10 Puan): EDR telemetri çıktısındaki "Execution Flag Detected:" satırında yer alan FLAG{purpl3_4t0m1c_t3st_c2_d3t3ct} değerini bayrak kutusuna giriniz.',
                'flag': 'FLAG{purpl3_4t0m1c_t3st_c2_d3t3ct}',
                'lab_type': 'standard'
            }
        ]

        for lab_info in labs_data:
            existing = Lab.query.filter_by(slug=lab_info['slug']).first()
            if not existing:
                new_lab = Lab(**lab_info)
                db.session.add(new_lab)
            else:
                existing.hint1 = lab_info.get('hint1', existing.hint)
                existing.hint2 = lab_info.get('hint2')

        # Varsayılan Siber Etkinlikler ve CTF Takvimi (Madde 6)
        from models import CyberEvent
        if CyberEvent.query.count() == 0:
            events_data = [
                {
                    'title': 'NÖHÜ Siber Kamp 2026: Web Exploitation Workshop',
                    'description': 'SQLi, XSS, SSRF ve modern web zaafiyetlerinin pratik sömürü teknikleri canlı lab uygulamaları ile ele alınacaktır.',
                    'event_type': 'Workshop',
                    'location': 'NÖHÜ Mühendislik Fakültesi Lab 301 & Discord',
                    'event_date': datetime.utcnow() + timedelta(days=5, hours=4),
                    'external_link': 'https://siber.ohu.edu.tr',
                    'organizer': 'NÖHÜ Siber Güvenlik Kulübü'
                },
                {
                    'title': 'TEKNOFEST 2026 Hack-Karadeniz Hazırlık CTF',
                    'description': 'TEKNOFEST Siber Güvenlik Yarışması için NÖHÜ temsilci takım seçmeleri ve eleme bayrak kapmaca maratonu.',
                    'event_type': 'CTF',
                    'location': 'Çevrimiçi / CTF Platformu',
                    'event_date': datetime.utcnow() + timedelta(days=12, hours=8),
                    'external_link': 'https://teknofest.org',
                    'organizer': 'NÖHÜ Siber Savunma Koordinatörlüğü'
                },
                {
                    'title': 'SOC & Adli Bilişim (DFIR) Semineri',
                    'description': 'Siber Güvenlik Operasyon Merkezi (SOC) analisti rolü, tehdit avcılığı ve bellek imajı analizi temalı uzman sunumu.',
                    'event_type': 'Seminer',
                    'location': 'NÖHÜ Kongre ve Kültür Merkezi Salon B',
                    'event_date': datetime.utcnow() + timedelta(days=18, hours=2),
                    'external_link': None,
                    'organizer': 'NÖHÜ Siber Güvenlik Kulübü'
                }
            ]
            for ev in events_data:
                db.session.add(CyberEvent(**ev))

        # Predefined default users (Sefa_Gumus Süper Yönetici, KLaxx0n Takım Lideri)
        users_data = [
            {
                'username': 'Sefa_Gumus',
                'email': 'gsefa5683@gmail.com',
                'password_hash': 'scrypt:32768:8:1$9An1lonMBKeJkdew$4b5f2082fdf506c66373712f0618df48f1ea1e18b733859b78e40cdb472b27e7b59e42d6b14a4a2ecad14740bac3c7ab0bc38f99f43675b61333dac39e81925f',
                'is_verified': True,
                'score': 0,
                'is_leader': True,
                'is_founder': True,
                'role': 'root',
                'assigned_team': 'blue_team',
                'is_suspended': False,
                'failed_login_attempts': 0
            },
            {
                'username': 'KLaxx0n',
                'email': 'jacjsparrow07@gmail.com',
                'password_hash': 'scrypt:32768:8:1$ZO6Ad06i968jnM4x$72a1a145ca272994204032836122420f54829a34434e1625c303736a47331f47880bac73dd5322b4c91d09ed6887d7aef82fe2e3114ffc15793e51ef99825769',
                'is_verified': True,
                'score': 0,
                'is_leader': True,
                'is_founder': False,
                'role': 'leader',
                'assigned_team': 'blue_team',
                'is_suspended': False,
                'failed_login_attempts': 0
            }
        ]

        for u_info in users_data:
            existing_user = User.query.filter(
                (User.username == u_info['username']) | (User.email == u_info['email'])
            ).first()
            if not existing_user:
                new_user = User(**u_info)
                db.session.add(new_user)
            else:
                existing_user.is_verified = True
                if not existing_user.password_hash:
                    existing_user.password_hash = u_info['password_hash']
                existing_user.role = u_info['role']
                existing_user.is_leader = u_info['is_leader']
                existing_user.is_founder = u_info['is_founder']
                existing_user.is_suspended = False
                existing_user.failed_login_attempts = 0

        db.session.commit()
        print("[+] Veritabani basariyla olusturuldu ve ornek veriler yuklendi.")

if __name__ == '__main__':
    from flask import Flask
    from config import Config
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)
    seed_database(app)
