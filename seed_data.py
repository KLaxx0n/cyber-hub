from models import db, Lab, User
from werkzeug.security import generate_password_hash

def seed_database(app):
    with app.app_context():
        db.create_all()

        # Otomatik Tablo Sütun Migrasyonu (SQLite ALTER TABLE)
        try:
            from sqlalchemy import inspect, text
            inspector = inspect(db.engine)
            if 'users' in inspector.get_table_names():
                columns = [c['name'] for c in inspector.get_columns('users')]
                with db.engine.connect() as conn:
                    if 'failed_login_attempts' not in columns:
                        conn.execute(text("ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER DEFAULT 0"))
                    if 'is_suspended' not in columns:
                        conn.execute(text("ALTER TABLE users ADD COLUMN is_suspended BOOLEAN DEFAULT 0"))
                    conn.commit()
        except Exception as mig_err:
            print(f"[!] Sütun migrasyon kontrolü: {mig_err}")

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
                'flag': 'FLAG{purpl3_4t0m1c_t3st_c2_d3t3ct}',
                'lab_type': 'standard'
            }
        ]

        for lab_info in labs_data:
            existing = Lab.query.filter_by(slug=lab_info['slug']).first()
            if not existing:
                new_lab = Lab(**lab_info)
                db.session.add(new_lab)

        # Predefined default users
        users_data = [
            {
                'username': 'Sefa_Gumus',
                'email': 'gsefa5683@gmail.com',
                'password_hash': generate_password_hash('23Sefa'),
                'is_verified': True,
                'score': 0,
                'is_leader': True,
                'is_founder': True,
                'role': 'superadmin',
                'assigned_team': 'blue_team'
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
                existing_user.password_hash = u_info['password_hash']
                existing_user.role = u_info.get('role', existing_user.role)
                existing_user.is_leader = u_info.get('is_leader', existing_user.is_leader)
                existing_user.is_founder = u_info.get('is_founder', existing_user.is_founder)

        db.session.commit()
        print("[+] Veritabani basariyla olusturuldu ve ornek veriler yuklendi.")

if __name__ == '__main__':
    from flask import Flask
    from config import Config
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)
    seed_database(app)
