"""Configuration and task definitions for multi-task interactive labs."""

MULTI_TASK_LABS = {
    'red-bayrak-avi-1': {
        'pass_threshold': 50,
        'target_endpoint': 'bayrak_avi_1_target',
        'target_label': 'hedef_site.html',
        'target_icon': '🎯',
        'target_title': 'Hedef Sunucu / Web Sitesi',
        'target_desc_before': 'Aşağıdaki bağlantıya tıklayarak hedef sızma test alanını (',
        'target_desc_after': ') yeni sekmede açın.',
        'target_button_text': 'HEDEF SİTEYİ AÇ',
        'target_is_download': False,
        'quick_tips_title': 'Hızlı Analiz Kısayolları:',
        'quick_tips': [
            ('CTRL+A', 'Gizli metinleri seçme'),
            ('CTRL+U', 'Sayfa kaynağını görüntüleme'),
            ('F12', 'Geliştirici Araçları (DevTools)'),
        ],
        'input_placeholder': 'FLAG{...}',
        'solved_input_label': '✓ Doğru Bayrak Kaydedildi',
        'writeup_title_placeholder': 'Örn: Bayrak Avı 1 - Kaynak Kod Analizi Çözüm Rehberi',
        'writeup_content_placeholder': '1. Görev: CTRL+A ile beyaz metin açığa çıkarıldı...\n2. Görev: HTML yorum satırı incelendi...',
        'case_sensitive': True,
        'kicker': 'NØHU RED TEAM // LAB 01',
        'icon_emoji': '🏴‍☠️',
        'tasks': [
            {
                'id': 'q1',
                'number': 1,
                'title': 'Beyaz Ekrandaki Gizli Yazı (#ffffff)',
                'question': 'Hedef web sitesinin beyaz arka planı üzerine beyaz renkle (#ffffff) gizlenmiş ilk bayrak nedir?',
                'hint': 'Hedef sitede CTRL+A tuşlarına basarak tüm sayfayı seçin (veya fare ile metnin altındaki boş alanı tarayın).',
                'points': 25,
                'flag': 'FLAG{beyaz_ekranda_gizli_yazi_ffffff}'
            },
            {
                'id': 'q2',
                'number': 2,
                'title': 'HTML Kaynak Yorum Satırı',
                'question': 'Hedef web sitesinin HTML kaynak kodlarında yorum satırı şeklinde unutulan ikinci bayrak nedir?',
                'hint': "Hedef sitede CTRL+U tuşlarına basın veya sağ tıklayıp 'Sayfa Kaynağını Görüntüle' seçeneğini kullanın.",
                'points': 25,
                'flag': 'FLAG{html_kodlari_arasinda_gizli_2026}'
            },
            {
                'id': 'q3',
                'number': 3,
                'title': 'CSS Stil Kodları Arasındaki Not',
                'question': 'Hedef web sitesinin stil etiketleri içerisindeki CSS kodları arasına gizlenmiş üçüncü bayrak nedir?',
                'hint': 'Sayfa kaynağındaki CSS kodları arasında /* GOREV_3_CSS_BAYRAGI */ satırını arayın.',
                'points': 25,
                'flag': 'FLAG{css_kodlari_arasinda_bulundu}'
            },
            {
                'id': 'q4',
                'number': 4,
                'title': 'JavaScript Konsol / Değişken Analizi',
                'question': 'Hedef web sitesinin script etiketleri içerisindeki JavaScript kodlarında tanımlanan gizli değişkenin dördüncü bayrağı nedir?',
                'hint': "Sayfa kaynağının en altındaki script bloğunda 'gizliSistemAnahtari' değişkenine bakın.",
                'points': 25,
                'flag': 'FLAG{javascript_kodlarinda_bulundu_ok}'
            }
        ]
    },
    'red-ohsint-2': {
        'pass_threshold': 50,
        'target_endpoint': 'ohsint_2_target',
        'target_label': 'numune.jpg',
        'target_icon': '📥',
        'target_title': 'İnceleme Dosyası',
        'target_desc_before': 'Aşağıdaki butona tıklayarak laboratuvar fotoğrafını (',
        'target_desc_after': ') indirin ve terminalde exiftool numune.jpg komutunu çalıştırarak analiz edin.',
        'target_button_text': 'FOTOĞRAFI İNDİR',
        'target_is_download': True,
        'target_download_name': 'numune.jpg',
        'quick_tips_title': 'Hızlı Analiz Komutları:',
        'quick_tips': [
            ('exiftool numune.jpg', 'Meta veri (EXIF) analizi'),
            ('ls -l numune.jpg', 'Dosya izinlerini görüntüleme'),
            ('wigle.net', 'BSSID / kablosuz ağ araması'),
        ],
        'input_placeholder': 'Cevabınızı yazın...',
        'solved_input_label': '✓ Doğru Cevap Kaydedildi',
        'writeup_title_placeholder': 'Örn: OhSINT Lab 2 - ExifTool & OSINT Çözüm Rehberi',
        'writeup_content_placeholder': '1. Görev: Copyright alanından kullanıcı adı bulundu...\n2. Görev: WiGLE üzerinden BSSID konumu tespit edildi...',
        'case_sensitive': False,
        'kicker': 'NØHU RED TEAM // LAB 02',
        'icon_emoji': '🕵️‍♂️',
        'card_warning': {
            'title': 'Gerekli Araç Uyarısı',
            'text': 'Bu lab için bilgisayarınıza ExifTool indirmeniz gerekir (Windows PowerShell veya Kali terminalinden kurup kullanabilirsiniz).'
        },
        'guide_pdf': {
            'filename': 'guides/red_team_lab2_ohsint_ogrenim_rehberi.pdf',
            'label': 'OhSINT & ExifTool Hazırlık Rehberi',
            'desc': 'Labı başlatmadan önce sesli video anlatımı izleyebilir veya ExifTool, Linux dosya izinleri ve WiGLE.net PDF rehberini inceleyebilirsiniz.'
        },
        'guide_video': {
            'filename': 'videos/red_team_lab2_ohsint_egitim_videosu.mp4',
            'poster': 'videos/red_team_lab2_ohsint_poster.jpg',
            'label': 'OhSINT & ExifTool Video Anlatım (06:06)',
            'short_label': 'Video Anlatım (06:06)',
            'desc': 'Sesli ve animasyonlu eğitim videosuyla EXIF analizi, ExifTool kurulumu, POSIX dosya izinleri ve WiGLE.net yöntemlerini izleyip bölümler arasında geçiş yapın.',
            'duration': '06:06',
            'chapters': [
                {'title': 'Giriş', 'time': 0},
                {'title': '1. OSINT & EXIF', 'time': 21},
                {'title': '2. ExifTool', 'time': 66},
                {'title': '3. Dosya İzinleri', 'time': 121},
                {'title': '4. Kullanıcı Avı', 'time': 181},
                {'title': '5. BSSID & WiGLE', 'time': 234},
                {'title': '6. Çözüm Akışı', 'time': 287},
                {'title': 'Sık Hatalar', 'time': 323},
            ],
        },
        'tasks': [
            {
                'id': 'q1',
                'number': 1,
                'title': 'Telif Hakkı / Yazar Bilgisi',
                'question': "What is this user's avatar of? / Telif sahibi (Copyright) kimdir?",
                'hint': "Exiftool çıktısındaki 'Copyright' alanına bakın (OhSINT odasındaki kedi avatarı mantığı).",
                'points': 17,
                'flag': 'cat'
            },
            {
                'id': 'q2',
                'number': 2,
                'title': 'Kullanıcının Şehri',
                'question': 'What city is this person in?',
                'hint': 'Exiftooldan aldığınız kullanıcıdan wigle.net (BSSID) üzerinden bulabilirsiniz.',
                'points': 17,
                'flag': 'London'
            },
            {
                'id': 'q3',
                'number': 3,
                'title': 'Kişisel E-posta Adresi',
                'question': 'What is his personal email address?',
                'hint': 'Exiftool çıktısındaki Copyright değerine bakın (Örn: ogrenci@gmail.com).',
                'points': 17,
                'flag': 'OWoodflint@gmail.com'
            },
            {
                'id': 'q4',
                'number': 4,
                'title': 'E-postanın Bulunduğu Site',
                'question': 'What site did you find his email address on?',
                'hint': 'Yazarın adını arattığınızda en çok karşılaşılan geliştirici platformu (Örn: github).',
                'points': 17,
                'flag': 'Github'
            },
            {
                'id': 'q5',
                'number': 5,
                'title': 'Dosya İzinleri (File Permissions)',
                'question': "İndirilen numune.jpg dosyasının Linux terminalindeki 'File Permissions' izni nedir?",
                'hint': "Exiftool çıktısındaki 'File Permissions' satırına bakın.",
                'points': 16,
                'flag': '-rw-rw-r--'
            },
            {
                'id': 'q6',
                'number': 6,
                'title': 'Bağlandığı WAP SSID',
                'question': 'What is the SSID of the WAP he connected to?',
                'hint': 'OhSINT senaryosuna göre varsayılan ağ adını öğrenmek için wigle.net kullanabilirsiniz.',
                'points': 16,
                'flag': 'UnileverWiFI'
            }
        ]
    },
    'red-hayalet-kapi-3': {
        'pass_threshold': 50,
        'target_endpoint': 'hayalet_kapi_3_target',
        'target_label': 'Kali Terminali (10.10.42.19)',
        'target_icon': '👻',
        'target_title': 'Hedef Terminal / Keşif Konsolu',
        'target_desc_before': 'Aşağıdaki bağlantıya tıklayarak simüle ',
        'target_desc_after': ' ortamını yeni sekmede açın ve keşif komutlarını çalıştırın.',
        'target_button_text': 'TERMİNALİ AÇ',
        'target_is_download': False,
        'quick_tips_title': 'Hızlı Keşif Komutları:',
        'quick_tips': [
            ('ls / cd / cat', 'Dosya sisteminde gezinme ve okuma'),
            ('nmap -sV / -sC', 'Servis sürümü ve script taraması'),
            ('gobuster dir -u', 'Web dizin / dosya keşfi'),
        ],
        'input_placeholder': 'Cevabınızı yazın...',
        'solved_input_label': '✓ Doğru Cevap Kaydedildi',
        'writeup_title_placeholder': 'Örn: Hayalet Kapı Lab 3 - Nmap & Gobuster Keşif Rehberi',
        'writeup_content_placeholder': '1. Görev: cd nohu ve cat flag.txt ile bayrak okundu...\n2. Görev: nmap -sV ile 80/tcp servis sürümü tespit edildi...',
        'case_sensitive': False,
        'kicker': 'NØHU RED TEAM // LAB 03',
        'icon_emoji': '👻',
        'card_warning': {
            'title': 'Gerekli Araç Bilgisi',
            'text': 'Bu labı bitirebilmek için önce Nmap ve Gobuster araçlarının ne olduğunu, ne işe yaradığını ve temel parametrelerini (-sV, -sC, dir -u) öğrenip okumanız önerilir.'
        },
        'tasks': [
            {
                'id': 'q1',
                'number': 1,
                'title': 'nohu Klasöründeki Bayrak',
                'question': "Klasörler arasından 'nohu' klasörüne girip içindeki dosyayı okuduğunda karşına çıkan FLAG{...} değeri nedir?",
                'hint': 'Önce ls ve pwd ile konumunu kontrol et, cd nohu ile klasöre geç ve içindeki dosyayı cat ile oku.',
                'points': 20,
                'flag': 'FLAG{hayalet_kapi_nohu_flag_99}'
            },
            {
                'id': 'q2',
                'number': 2,
                'title': 'Nmap: Web Servisi ve Sürümü',
                'question': 'Nmap servis sürüm taraması çıktısına göre 80/tcp portunda çalışan web sunucusu ve sürümü nedir? (Örnek: nginx 1.24.0)',
                'hint': 'Hedef IP üzerinde servis sürüm bilgisi üreten Nmap parametresini (-sV) dene.',
                'points': 20,
                'flag': 'nginx 1.24.0'
            },
            {
                'id': 'q3',
                'number': 3,
                'title': 'Nmap: Script Taraması Başlığı',
                'question': 'Nmap varsayılan script taramasında HTTP servisi için raporlanan başlık (http-title) nedir?',
                'hint': 'Varsayılan script taraması (-sC) çıktısındaki http-title satırını incele.',
                'points': 20,
                'flag': 'Nohu Simulation Gateway'
            },
            {
                'id': 'q4',
                'number': 4,
                'title': 'Gobuster: Gizli Yönetim Yolu',
                'question': 'Gobuster dizin taramasında yönlendirme (302) döndüren gizli yol hangisidir?',
                'hint': 'Hedef URL üzerinde dizin taraması çalıştır ve 302 durum koduna bak.',
                'points': 20,
                'flag': '/shadow_auth',
                'accepted_flags': ['/shadow_auth', 'shadow_auth', '/shadow_auth/']
            },
            {
                'id': 'q5',
                'number': 5,
                'title': 'Gobuster: Yedek Arşiv Dosyası',
                'question': 'Gobuster dizin taramasında /backups/ altında listelenen arşiv dosyasının adı nedir?',
                'hint': 'Dizin tarama çıktısındaki /backups/ ile başlayan satıra dikkat et.',
                'points': 20,
                'flag': 'snapshot_2026.tar.gz',
                'accepted_flags': ['snapshot_2026.tar.gz', '/backups/snapshot_2026.tar.gz']
            }
        ]
    },
    'blue-soc-olay-1': {
        'pass_threshold': 60,
        'target_endpoint': 'blue_soc_olay_1_target',
        'target_label': 'SOC Olay Konsolu (access.log & auth.log)',
        'target_icon': '🛡️',
        'target_title': 'SOC Olay İnceleme Konsolu',
        'target_desc_before': 'Aşağıdaki bağlantıya tıklayarak ',
        'target_desc_after': ' panelini yeni sekmede açın. Harici araç kurmadan logları filtreleyebilir, dilerseniz .log dosyalarını indirebilirsiniz.',
        'target_button_text': 'SOC KONSOLUNU AÇ',
        'target_is_download': False,
        'quick_tips_title': 'SOC Hızlı Analiz İpuçları:',
        'quick_tips': [
            ('404 / gobuster', 'Web dizin taraması tespiti'),
            ('Accepted password', 'Başarılı SSH parola girişi'),
            ('base64 -d', 'Gizli kalıcılık payloadı çözümü'),
        ],
        'input_placeholder': 'Cevabınızı yazın...',
        'solved_input_label': '✓ Doğru Cevap Kaydedildi',
        'writeup_title_placeholder': 'Örn: SOC Vakası 1 - Log Korelasyonu & İhlal Analizi',
        'writeup_content_placeholder': '1. Görev: access.log içinde 404 taraması yapan IP tespit edildi...\n2. Görev: auth.log üzerinde Accepted password satırı incelendi...',
        'case_sensitive': False,
        'kicker': 'NØHU BLUE TEAM // LAB 01',
        'icon_emoji': '🛡️',
        'guide_pdf': {
            'filename': 'guides/blue_team_lab1_soc_hazirlik_rehberi.pdf',
            'label': 'SOC & Log Analizi Hazırlık Rehberi (PDF)',
            'desc': 'Labı başlatmadan önce Nginx access.log, Linux auth.log ve Base64 analiz temellerini okuyabilirsiniz.'
        },
        'tasks': [
            {
                'id': 'q1',
                'number': 1,
                'title': 'Saldırganın Kaynak IP Adresi',
                'question': 'Web sunucusuna yoğun dizin taraması (404) ve SSH parola kırma (brute-force) saldırısı düzenleyen dış saldırgan IP adresi nedir?',
                'hint': 'access.log içinde art arda 404 yanıtı alan ve auth.log içinde çok sayıda "Failed password" kaydı üreten IP adresini bulun.',
                'points': 20,
                'flag': '185.220.101.47'
            },
            {
                'id': 'q2',
                'number': 2,
                'title': 'Ele Geçirilen SSH Hesabı',
                'question': 'auth.log kayıtlarına göre saldırgan başarısız denemelerin ardından hangi sistem kullanıcısının hesabına parola ile ("Accepted password") giriş yapmıştır?',
                'hint': 'auth.log sekmesinde "Accepted password" ifadesini filtreleyerek saldırgan IP ile eşleşen kullanıcı adını inceleyin.',
                'points': 20,
                'flag': 'deploy_svc'
            },
            {
                'id': 'q3',
                'number': 3,
                'title': 'Sunucuya Yüklenen Zararlı Web Shell',
                'question': 'Saldırgan /api/v1/upload uç noktası üzerinden sunucuya bir web shell yükleyip uzaktan komut (?cmd=) çalıştırmıştır. Zararlı dosyanın adı (uzantısıyla birlikte, örn: shell.php) nedir?',
                'hint': 'access.log içinde POST /api/v1/upload sonrasında gelen /uploads/ ve ?cmd= isteklerine bakın.',
                'points': 20,
                'flag': 'sys_health.php',
                'accepted_flags': ['sys_health.php', '/uploads/sys_health.php']
            },
            {
                'id': 'q4',
                'number': 4,
                'title': 'Sızdırılan Veritabanı Yedek Dosyası',
                'question': 'Saldırgan sunucudaki kritik bir veritabanı yedeğini dışarıya çekmiştir (Data Exfiltration). access.log üzerinde ~4.8 MB boyutla indirilen bu dosyanın adı (uzantısıyla birlikte) nedir?',
                'hint': 'access.log içinde "Yüksek Boyut" filtresini kullanın veya /backups/ yoluna yapılan 200 OK GET isteğini inceleyin.',
                'points': 20,
                'flag': 'prod_users_dump_2026.sql.gz',
                'accepted_flags': ['prod_users_dump_2026.sql.gz', '/backups/prod_users_dump_2026.sql.gz']
            },
            {
                'id': 'q5',
                'number': 5,
                'title': 'Kalıcılık Komutundaki Gizli IOC Bayrağı',
                'question': 'Saldırgan auth.log içinde sudo yetkisiyle Base64 kodlu bir zamanlanmış görev (cron) kalıcılığı oluşturmuştur. Base64 metnini SOC konsolundaki çözücü ile çözerek içerideki FLAG{...} bayrağını bulun.',
                'hint': 'auth.log içinde "sudo" veya "base64" kelimesini arayın; echo ile pipe edilen Base64 dizgisini alt kısımdaki SOC Base64 Çözücüye yapıştırın.',
                'points': 20,
                'flag': 'FLAG{blue_soc_olay_2026}'
            }
        ]
    }
}


def get_public_tasks(slug):
    """Return task definitions for a multi-task lab without exposing flag answers."""
    cfg = MULTI_TASK_LABS.get(slug)
    if not cfg:
        return []
    return [
        {
            'id': t['id'],
            'number': t['number'],
            'title': t['title'],
            'question': t['question'],
            'hint': t['hint'],
            'points': t['points'],
        }
        for t in cfg['tasks']
    ]
