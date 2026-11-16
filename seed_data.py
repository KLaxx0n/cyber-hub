from models import db, Lab, User
from werkzeug.security import generate_password_hash

def seed_database(app):
    with app.app_context():
        db.create_all()

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
                'username': 'sefa',
                'email': 'gsefa5683@gmail.com',
                'password_hash': 'scrypt:32768:8:1$wGtXe6gXF9pTFL2j$777c665f7194f45ebd5946f43472ff6473407eaadeb31d65950aa7c5764c0c9bf573706e575b02a5fe42f1742491728bff4d7a2d16fd42e708d7048139d7f55f',
                'is_verified': True,
                'score': 0,
                'is_leader': True,
                'is_founder': True,
                'role': 'superadmin',
                'assigned_team': 'blue_team'
            },
            {
                'username': 'KLaxx0n',
                'email': 'jajcsparrow07@gmail.com',
                'password_hash': 'scrypt:32768:8:1$xmrIjst1M06BQEOB$c82bc097ffcf318b6d8f84cf4dc010a66826c9f4a9a1f80fc49b2eb6240349b53e75d8cb7d5de76133c35578b0f3f055fb0ac004eeb743442facd005c11a949a',
                'is_verified': True,
                'score': 100,
                'is_leader': False,
                'is_founder': False,
                'role': 'student',
                'assigned_team': 'blue_team'
            }
        ]

        for u_info in users_data:
            existing_user = User.query.filter_by(username=u_info['username']).first()
            if not existing_user:
                new_user = User(**u_info)
                db.session.add(new_user)

        db.session.commit()
        print("[+] Veritabani basariyla olusturuldu ve ornek veriler yuklendi.")

if __name__ == '__main__':
    from flask import Flask
    from config import Config
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)
    seed_database(app)
