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
