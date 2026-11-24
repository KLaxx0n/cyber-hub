from datetime import datetime, timedelta
from models import db, Lab, User, UserFeedback
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

        # NULL değerleri temizle (Askıya alma hatalarını önlemek için)
        try:
            from sqlalchemy import text
            with db.engine.connect() as conn:
                conn.execute(text("UPDATE users SET is_suspended = FALSE WHERE is_suspended IS NULL"))
                conn.execute(text("UPDATE users SET failed_login_attempts = 0 WHERE failed_login_attempts IS NULL"))
                conn.commit()
        except Exception as e:
            print(f"[!] Users sanitize check: {e}")

        # Labs tablosu sütunları
        safe_add_column(db.engine, 'labs', 'hint1', 'TEXT')
        safe_add_column(db.engine, 'labs', 'hint2', 'TEXT')
        safe_add_column(db.engine, 'labs', 'is_published', 'BOOLEAN DEFAULT TRUE')

        # UserLabProgress tablosu sütunları
        safe_add_column(db.engine, 'user_lab_progress', 'is_first_blood', 'BOOLEAN DEFAULT FALSE')
        safe_add_column(db.engine, 'user_lab_progress', 'hint1_unlocked', 'BOOLEAN DEFAULT FALSE')
        safe_add_column(db.engine, 'user_lab_progress', 'hint2_unlocked', 'BOOLEAN DEFAULT FALSE')
        safe_add_column(db.engine, 'user_lab_progress', 'solved_tasks', "TEXT DEFAULT '[]'")
        safe_add_column(db.engine, 'user_lab_progress', 'started_at', 'TIMESTAMP')
        safe_add_column(db.engine, 'user_lab_progress', 'speed_bonus', 'INTEGER DEFAULT 0')
        safe_add_column(db.engine, 'user_lab_progress', 'solve_time_sec', 'INTEGER DEFAULT 0')

        # CyberEvents tablosu sütunları
        safe_add_column(db.engine, 'cyber_events', 'end_date', 'TIMESTAMP')

        # Predefined Labs based on project report
        labs_data = [
            # RED TEAM LABS
            {
                'slug': 'red-bayrak-avi-1',
                'title': 'Bayrak Avı 1',
                'category': 'red_team',
                'sub_category': 'Flag Hunting & Kaynak Analizi',
                'difficulty': 'Kolay',
                'points': 100,
                'time_limit_sec': 600, # 10 dakika
                'description': 'Web sızma testi ve kaynak kod analizi yaparak gizli bayrakları (flag) bulabilir misin?',
                'scenario': 'Hedef kuruma ait web sayfasının (hedef_site.html) geliştirici notları, stil blokları ve istemci tarafı betikleri incelenmeden yayına alındığı tespit edildi.',
                'instructions': 'Hedef siteyi yeni sekmede açın. Görünmez yazıları ortaya çıkarın; HTML, CSS ve JavaScript kaynak kodlarını inceleyerek 4 görevin her birine ait FLAG{...} değerini teslim edin. (Her görev 25 puan, toplam 100 puan, baraj 50 puandır.)',
                'hint': 'Hedef sitede CTRL+A ile gizli yazıları seçmeyi ve CTRL+U / Geliştirici Araçları (F12) ile kaynak kodları incelemeyi deneyin.',
                'hint1': 'Hedef sitede CTRL+A tuşlarıyla sayfa üzerindeki görünmez yazıları seçebilir, CTRL+U veya F12 (Öğeyi Denetle) ile HTML, CSS ve JavaScript kaynak kodlarını inceleyebilirsiniz.',
                'hint2': 'Kritik İpucu (-10 Puan): Task 1 için .invisible-flag sınıfına, Task 2 için HTML yorum satırına (GOREV_2), Task 3 için <style> içindeki GOREV_3_CSS_BAYRAGI notuna, Task 4 için <script> içindeki gizliSistemAnahtari değişkenine odaklanın.',
                'flag': 'FLAG{bayrak_avi_1_multi_task_completed}',
                'lab_type': 'multi_task',
                'is_published': True
            },
            {
                'slug': 'red-ohsint-2',
                'title': 'OhSINT: Açık Kaynak İstihbaratı',
                'category': 'red_team',
                'sub_category': 'OSINT & Meta Veri Analizi',
                'difficulty': 'Orta',
                'points': 100,
                'time_limit_sec': 900, # 15 dakika
                'description': 'Verilen fotoğraf dosyasını inceleyerek OhSINT sorularını yanıtlayın ve ExifTool ile meta verileri analiz edin.',
                'scenario': 'Şüpheli bir kullanıcıya ait örnek fotoğraf dosyası (numune.jpg) elde edildi. Açık kaynak istihbaratı (OSINT) ve EXIF meta veri analizi teknikleriyle hedef hakkında kritik bilgilere ulaşılması gerekmektedir.',
                'instructions': 'İnceleme dosyasını (numune.jpg) indirin. ExifTool (Windows PowerShell veya Kali terminal) ve açık kaynak istihbarat araçlarıyla 6 görevin her birine ait cevabı teslim edin. (Toplam 100 puan, baraj 50 puandır.)',
                'hint': 'ExifTool ile numune.jpg dosyasının meta verilerini (Copyright, File Permissions) ve BSSID bilgisini wigle.net üzerinde araştırın.',
                'hint1': 'Terminalde "exiftool numune.jpg" komutunu çalıştırarak telif hakkı (Copyright) ve dosya izinleri (File Permissions) bilgilerine ulaşabilirsiniz. Elde ettiğiniz kullanıcı adını arama motorları, GitHub ve wigle.net üzerinde araştırın.',
                'hint2': 'Kritik İpucu (-10 Puan): Task 1 için avatar türü (cat), Task 2 için şehir (London), Task 3 için e-posta (OWoodflint@gmail.com), Task 4 için geliştirici platformu (Github), Task 5 için dosya izinleri (-rw-rw-r--), Task 6 için Wi-Fi SSID (UnileverWiFI) değerlerini inceleyin.',
                'flag': 'FLAG{ohsint_lab_2_multi_task_completed}',
                'lab_type': 'multi_task',
                'is_published': True
            },
            {
                'slug': 'red-hayalet-kapi-3',
                'title': 'Operasyon: Hayalet Kapı',
                'category': 'red_team',
                'sub_category': 'Keşif (Recon) & Nmap / Gobuster',
                'difficulty': 'Orta',
                'points': 100,
                'time_limit_sec': 720, # 12 dakika
                'description': 'Simüle Kali terminalinde dosya sisteminde gezinip bayrağı bulun; ardından Nmap ve Gobuster ile hedef sunucunun servislerini ve gizli dizinlerini keşfedin.',
                'scenario': 'Hedef sunucu (10.10.42.19) üzerinde yetkisiz bir yönetim kapısı ve unutulmuş yedek dosyaları bulunduğu şüphesi var. Red Team operatörü olarak keşif (reconnaissance) aşamasını tamamlamanız gerekmektedir.',
                'instructions': 'Hedef terminali yeni sekmede açın. Önce nohu klasöründeki bayrağı okuyun, ardından Nmap (-sV, -sC) ve Gobuster (dir -u) taramalarıyla 5 görevin her birine ait cevabı teslim edin. (Her görev 20 puan, toplam 100 puan, baraj 50 puandır.)',
                'hint': 'Terminalde help yazarak komutları görün; nmap -sV / -sC ve gobuster dir -u http://10.10.42.19 çıktılarını inceleyin.',
                'hint1': 'Terminalde "cd nohu" ve "cat flag.txt" ile bayrağı okuyun. Servis sürümleri için "nmap -sV 10.10.42.19", http-title için "nmap -sC 10.10.42.19", gizli dizinler için "gobuster dir -u http://10.10.42.19" komutlarını çalıştırın.',
                'hint2': 'Kritik İpucu (-10 Puan): Task 2 için nginx 1.24.0, Task 3 için Nohu Simulation Gateway, Task 4 için 302 dönen /shadow_auth yolu, Task 5 için /backups/ altındaki snapshot_2026.tar.gz dosyasına odaklanın.',
                'flag': 'FLAG{hayalet_kapi_lab_3_multi_task_completed}',
                'lab_type': 'multi_task',
                'is_published': True
            },
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
                'lab_type': 'sqli',
                'is_published': False
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
                'lab_type': 'xss',
                'is_published': False
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
                'lab_type': 'phishing',
                'is_published': False
            },

            # BLUE TEAM LABS
            {
                'slug': 'blue-soc-olay-1',
                'title': 'SOC Vakası 1: Gece Yarısı İhlal Avı',
                'category': 'blue_team',
                'sub_category': 'SOC & Olay Müdahalesi',
                'difficulty': 'Kolay',
                'points': 100,
                'time_limit_sec': 900, # 15 dakika
                'description': 'Gerçekçi Nginx access.log ve Linux auth.log kayıtlarını korele ederek saldırgan IP adresini, ele geçirilen SSH hesabını, web shelli, veri sızıntısını ve kalıcılık bayrağını tespit edin.',
                'scenario': '18 Kasım 2026 gecesi kurum sunucusunda (srv-web-01) olağandışı ağ trafiği ve şüpheli sistem komutları tespit edildi. SIEM ön uyarısının ardından access.log ve auth.log kayıtları SOC olay müdahale konsoluna aktarıldı.',
                'instructions': 'SOC Olay İnceleme Konsolunu yeni sekmede açın (harici araç gerektirmez; dilerseniz .log dosyalarını indirip yerelde de inceleyebilirsiniz). 5 aşamalı saldırı zincirini analiz ederek her görevin cevabını teslim edin. (Her görev 20 puan, toplam 100 puan, baraj 60 puandır.)',
                'hint': 'access.log içinde 404 dizin taraması ve 200 OK /uploads/ veya /backups/ isteklerini; auth.log içinde "Accepted password" ve Base64 kodlu sudo komutunu inceleyin.',
                'hint1': 'SOC Konsolunda hızlı filtreleme çiplerini kullanın: access.log içinde 404 yanıtları üreten IP adresini bulun, ardından aynı IP için auth.log üzerinde "Accepted password" ve "sudo" satırlarını arayın.',
                'hint2': 'Kritik İpucu (-10 Puan): Task 1 için 185.220.101.47, Task 2 için deploy_svc, Task 3 için sys_health.php, Task 4 için prod_users_dump_2026.sql.gz, Task 5 için auth.log sudo satırındaki Base64 kodunu SOC Base64 Çözücü ile çözün.',
                'flag': 'FLAG{blue_soc_olay_1_multi_task_completed}',
                'lab_type': 'multi_task',
                'is_published': True
            },
            {
                'slug': 'blue-wireshark-1',
                'title': 'Ağ Trafiği ve Paket Analizi (Mini-Wireshark)',
                'category': 'blue_team',
                'sub_category': 'Ağ Güvenliği & Paket Analizi',
                'difficulty': 'Kolay',
                'points': 100,
                'time_limit_sec': 900,
                'description': 'Gerçek bir ağ trafiği dökümünü (PCAP) inceleyerek açık metin parolaları, şüpheli DNS sorgularını, port taramalarını, gizli veri sızıntılarını ve ARP zehirlenmesini tespit edin.',
                'scenario': 'Şirket ağında olağandışı hareketlilik şüphesiyle ağ trafiği izlemeye alınmıştır. İnceleme için yakalanan ağ paketleri Mini-Wireshark analiz konsoluna aktarılmıştır.',
                'instructions': 'Mini-Wireshark Paket İnceleme Konsolunu yeni sekmede açın. Paketleri listeleyin, protokol filtrelerini (HTTP, DNS, TCP, ARP) kullanarak inceleyin ve 5 soruşturma görevini tamamlayın.',
                'hint': 'Filtre çubuğuna protokol adlarını (http, dns, syn, arp) yazarak ilgili paketleri kolayca filtreleyebilirsiniz.',
                'hint1': 'Açık metin parola için 6 nolu HTTP POST paketine, C2 için 8 nolu DNS paketine, port taraması için 10-13 nolu SYN paketlerine bakın.',
                'hint2': 'Kritik İpucu (-10 Puan): Parola MaviTakim2026!, DNS c2-stealth-updater.darkweb-leak.xyz, IP 192.168.1.88, Flag FLAG{Agi_Izleyen_Kazanir_2026}, Sahte MAC 00:0c:29:88:fe:99.',
                'flag': 'FLAG{blue_wireshark_packet_analysis_completed}',
                'lab_type': 'multi_task',
                'is_published': True
            },
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
                'lab_type': 'log_analysis',
                'is_published': False
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
                'lab_type': 'forensics',
                'is_published': False
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
                'lab_type': 'firewall',
                'is_published': False
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
                existing.is_published = lab_info.get('is_published', True)
                if lab_info.get('lab_type') == 'multi_task':
                    existing.title = lab_info['title']
                    existing.sub_category = lab_info['sub_category']
                    existing.difficulty = lab_info['difficulty']
                    existing.points = lab_info['points']
                    existing.time_limit_sec = lab_info['time_limit_sec']
                    existing.description = lab_info['description']
                    existing.scenario = lab_info['scenario']
                    existing.instructions = lab_info['instructions']
                    existing.hint = lab_info['hint']
                    existing.lab_type = lab_info['lab_type']

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

        # NÖHÜ (ohu.edu.tr) Resmi Güncel Etkinlikleri (Mevcut kayıtları bozmadan idempotent eklenir)
        ohu_events_data = [
            {
                'title': 'SANAR 2026: 5. Uluslararası Spor, Antropoloji, Beslenme, Anatomi ve Radyoloji Kongresi',
                'description': 'Niğde Ömer Halisdemir Üniversitesi ev sahipliğinde; Nevşehir Hacı Bektaş Veli, Ankara, Yüksek İhtisas, Kapadokya ve Kayseri Üniversiteleri paydaşlığında 19–21 Kasım 2026 tarihlerinde düzenlenen 5. Uluslararası Spor, Antropoloji, Beslenme, Anatomi ve Radyoloji Kongresi (SANAR 2026). Kongre sayfası: https://ohu.edu.tr/sanar',
                'event_type': 'Kongre',
                'location': 'Şehit Ömer Halisdemir Kongre ve Kültür Merkezi',
                'event_date': datetime(2026, 11, 19, 9, 0),
                'end_date': datetime(2026, 11, 21, 17, 0),
                'external_link': 'https://www.ohu.edu.tr/etkinlik/5-uluslararasi-spor-antropoloji-beslenme-anatomi-ve-radyoloji-kongresi/11263',
                'organizer': 'Niğde Ömer Halisdemir Üniversitesi'
            },
            {
                'title': 'Plates Eğitimi',
                'description': 'NÖHÜ Spor Kulübü tarafından her Salı ve Perşembe saat 11:45\'te Merkez Kampüs Spor Salonu\'nda düzenlenen pilates eğitimi. Üniversitemiz kadın personeli ve personel yakınlarına yöneliktir. (Afiş dönemi: 17 Ekim – 24 Aralık 2026; resmi etkinlik takvimi bitişi: 17.06.2027.)',
                'event_type': 'Spor',
                'location': 'Merkez Kampüs Spor Salonu',
                'event_date': datetime(2026, 11, 17, 11, 45),
                'end_date': datetime(2027, 6, 17, 11, 45),
                'external_link': 'https://www.ohu.edu.tr/etkinlik/plates-egitimi/11270',
                'organizer': 'NÖHÜ Spor Kulübü'
            },
            {
                'title': 'Spor Aktiviteleri Devam Ediyor',
                'description': 'Spor Dostu Kampüs uygulaması kapsamında NÖHÜ Spor Koordinatörlüğü ve NÖHÜ Spor Kulübü iş birliğiyle 19.10.2026 – 01.01.2027 tarihleri arasında düzenlenen haftalık spor etkinlikleri: bisiklet, kort tenis, badminton, squash, sağlıklı yaşam yürüyüşü, tekerlekli paten, masa tenisi, boks, temel hareket eğitimi, kick boks, step aerobik, pilates ve dart.',
                'event_type': 'Spor',
                'location': 'Merkez Kampüs Spor Alanları & Bor Yerleşkesi',
                'event_date': datetime(2026, 10, 19, 9, 0),
                'end_date': datetime(2027, 1, 1, 17, 0),
                'external_link': 'https://www.ohu.edu.tr/etkinlik/spor-aktiviteleri-devam-ediyor/11264',
                'organizer': 'NÖHÜ Spor Koordinatörlüğü & NÖHÜ Spor Kulübü'
            }
        ]
        for ohu_ev in ohu_events_data:
            existing_ev = CyberEvent.query.filter(
                (CyberEvent.title == ohu_ev['title']) |
                (CyberEvent.external_link == ohu_ev['external_link'])
            ).first()
            if not existing_ev:
                db.session.add(CyberEvent(**ohu_ev))
            elif existing_ev.end_date is None and ohu_ev.get('end_date'):
                existing_ev.end_date = ohu_ev['end_date']

        # Predefined default user (Süper Yönetici)
        users_data = [
            {
                'username': 'admin',
                'email': 'admin@cyberhub.local',
                'password_hash': generate_password_hash('Admin1234'),
                'is_verified': True,
                'score': 0,
                'is_leader': True,
                'is_founder': True,
                'role': 'root',
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
                existing_user.password_hash = u_info['password_hash']
                existing_user.role = u_info['role']
                existing_user.is_leader = u_info['is_leader']
                existing_user.is_founder = u_info['is_founder']
                existing_user.is_suspended = False
                existing_user.failed_login_attempts = 0

        # Tüm mevcut ve yeni hesapları doğrudan onaylı/aktif duruma getir
        User.query.filter_by(is_verified=False).update({User.is_verified: True})

        db.session.commit()
        print("[+] Veritabani basariyla olusturuldu ve ornek veriler yuklendi.")

if __name__ == '__main__':
    from flask import Flask
    from config import Config
    app = Flask(__name__)
    app.config.from_object(Config)
    db.init_app(app)
    seed_database(app)
