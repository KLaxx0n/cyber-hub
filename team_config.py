"""Ekip, akademik profil, aktif çalışmalar ve fotoğraf galerisi yapılandırması.

Fotoğraf eklemek için görselleri `static/img/team/` klasörüne aşağıdaki
dosya adlarıyla bırakmanız yeterlidir; sistem dosyayı otomatik algılar:
  - sefa.jpg
  - aziz.jpg
  - halil_ibrahim.jpg
  - murat.jpg
  - gallery_1.jpg, gallery_2.jpg, gallery_3.jpg
"""

import os

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
TEAM_IMG_DIR = os.path.join(BASE_DIR, 'static', 'img', 'team')


def _photo_url_if_exists(filename):
    """Return static relative path if the image file exists on disk."""
    if not filename:
        return None
    full_path = os.path.join(TEAM_IMG_DIR, filename)
    if os.path.isfile(full_path):
        return f'img/team/{filename}'
    return None


ACADEMIC_INFO = {
    'university': 'Niğde Ömer Halisdemir Üniversitesi (NÖHÜ)',
    'faculty': 'Bilgisayar ve Bilişim Bilimleri Fakültesi',
    'department': 'Bilgi Teknolojileri Güvenliği Bölümü',
    'project_name': 'NÖHÜ Siber Güvenlik Eğitim & CTF Platformu',
    'tagline': 'Teorik bilişim ve siber güvenlik bilgisini izole, gerçekçi laboratuvar senaryolarıyla pratiğe dönüştüren öğrenci geliştirme ekibi.',
    'pillars': [
        {
            'title': 'Ofansif Güvenlik & Sızma Testi',
            'icon': 'fa-solid fa-crosshairs',
            'accent': 'red',
            'desc': 'OWASP Top 10 web zafiyetleri (SQLi, XSS), kaynak kod analizi, açık kaynak istihbaratı (OSINT) ve CTF bayrak avı teknikleri.'
        },
        {
            'title': 'Defansif Güvenlik & SOC',
            'icon': 'fa-solid fa-shield-halved',
            'accent': 'sky',
            'desc': 'Sunucu erişim ve kimlik doğrulama log korelasyonu, olay müdahalesi, dijital adli bilişim (DFIR) ve aktif ağ savunması.'
        },
        {
            'title': 'Full-Stack & Güvenli Mimari',
            'icon': 'fa-solid fa-code',
            'accent': 'cyan',
            'desc': 'Python/Flask tabanlı ölçeklenebilir backend geliştirme, 2FA (TOTP) kimlik doğrulama, CSRF & rate-limit güvenliği ve modern arayüz tasarımı.'
        },
        {
            'title': 'CTF, OSINT & Uygulamalı Öğrenme',
            'icon': 'fa-solid fa-flag',
            'accent': 'indigo',
            'desc': 'Açık kaynak istihbaratı (OSINT), çok aşamalı görev senaryoları, hız bonusu ve canlı sıralama tablosu ile rekabetçi siber güvenlik pratiği.'
        },
    ]
}


RAW_TEAM_MEMBERS = [
    {
        'id': 'sefa-gumus',
        'name': 'Sefa Gümüş',
        'role': 'Kurucu, Ekip Koordinatörü & Full-Stack Geliştirici',
        'badge': 'Kurucu',
        'team_category': 'core',
        'accent': 'gold',
        'initials': 'SG',
        'avatar_icon': 'fa-solid fa-crown',
        'photo_filename': 'sefa.jpg',
        'study': 'NÖHÜ • Bilgisayar ve Bilişim Bilimleri Fakültesi / Bilgi Teknolojileri Güvenliği Bölümü',
        'bio': (
            'Projenin ekip koordinasyonunu ve yönetimini Aziz Mahmudlu ile birlikte üstlenen, platformu sıfırdan inşa eden '
            'tam kapsamlı (Full-Stack) geliştirici. Sistem mimarisi, yönetim paneli, kullanıcı güvenliği, '
            'arayüz tasarımı ve tüm modüllerin platforma entegrasyonunu yönetiyor.'
        ),
        'working_on': [
            'Ortak ekip koordinasyonu, görev dağılımı ve proje sürecinin uçtan uca yönetimi',
            'Web sitesinin Frontend & Backend geliştirme süreci (Python/Flask, Veritabanı, Modern Dark UI)',
            'Yönetim paneli, rol/yetki kontrolü, 2FA TOTP güvenliği ve canlı sıralama/etkinlik altyapısı'
        ],
        'skills': ['Ekip Koordinasyonu', 'Full-Stack', 'HTML5', 'Python / Flask', 'Sistem Mimarisi', 'UI/UX Tasarım'],
        'tier': 'core'
    },
    {
        'id': 'aziz',
        'name': 'Aziz Mahmudlu',
        'role': 'Ekip Koordinatörü, Red Team Lideri & Ofansif Güvenlik Sorumlusu',
        'badge': 'Koordinatör & Red Team',
        'team_category': 'red',
        'accent': 'red',
        'initials': 'AM',
        'avatar_icon': 'fa-solid fa-crosshairs',
        'photo_filename': 'aziz.jpg',
        'study': 'NÖHÜ • Bilgisayar ve Bilişim Bilimleri Fakültesi / Bilgi Teknolojileri Güvenliği Bölümü',
        'bio': (
            'Projenin ekip koordinasyonunu ve yönetimini Sefa Gümüş ile birlikte üstlenen, ofansif güvenlik (Red Team) '
            'tarafını şekillendiren ve saldırı senaryolarını hazırlayan ekip arkadaşımız. Öğrencilerin web zafiyetlerini '
            'etik sınırlar içinde keşfedebileceği uygulamalı görevler kurguluyor.'
        ),
        'working_on': [
            'Ortak ekip koordinasyonu, Red Team liderliği ve proje sürecinin yönetimi',
            'Bayrak Avı (Flag Hunting) görev mekanizması ve istemci tarafı kaynak kod analizi',
            'OWASP Top 10 zafiyet laboratuvarları (SQL Injection, Reflected XSS) ve CTF zorluk dengesi'
        ],
        'skills': ['Ekip Koordinasyonu', 'Yönetim', 'Red Team', 'OWASP Top 10', 'SQLi & XSS', 'Flag Hunting'],
        'tier': 'core'
    },
    {
        'id': 'halil-ibrahim-cevik',
        'name': 'Halil İbrahim Çevik',
        'role': 'Blue Team Sorumlusu • SOC & Log Analizi',
        'badge': 'Blue Team',
        'team_category': 'blue',
        'accent': 'sky',
        'initials': 'HÇ',
        'avatar_icon': 'fa-solid fa-shield-halved',
        'photo_filename': 'halil_ibrahim.jpg',
        'study': 'NÖHÜ • Bilgisayar ve Bilişim Bilimleri Fakültesi / Bilgi Teknolojileri Güvenliği Bölümü',
        'bio': (
            'Defansif güvenlik (Blue Team) tarafında sunucu erişim ve kimlik doğrulama kayıtlarının incelenmesi, '
            'SOC olay müdahale süreçleri ve saldırı izlerinin tespiti üzerine çalışan ekip arkadaşımız.'
        ),
        'working_on': [
            'SOC Vakası 1: Nginx access.log ve Linux auth.log saldırı korelasyonu',
            'Şüpheli IP tespiti, web shell analizi ve brute-force anomali takibi',
            'Blue Team olay inceleme rehberleri ve savunma senaryoları'
        ],
        'skills': ['Blue Team', 'SOC Analizi', 'Log Korelasyonu', 'Olay Müdahalesi'],
        'tier': 'core'
    },
    {
        'id': 'murat-sarac',
        'name': 'Murat Saraç',
        'role': 'Blue Team Sorumlusu • Adli Bilişim & Ağ Savunması',
        'badge': 'Blue Team',
        'team_category': 'blue',
        'accent': 'sky',
        'initials': 'MS',
        'avatar_icon': 'fa-solid fa-user-shield',
        'photo_filename': 'murat.jpg',
        'study': 'NÖHÜ • Bilgisayar ve Bilişim Bilimleri Fakültesi / Bilgi Teknolojileri Güvenliği Bölümü',
        'bio': (
            'Blue Team modülünde dijital adli bilişim (DFIR), dosya bütünlüğü incelemeleri ve '
            'aktif güvenlik duvarı savunma kuralları üzerine çalışan ekip arkadaşımız.'
        ),
        'working_on': [
            'Digital Forensics: Hex dökümü inceleme ve silinmiş delil kurtarma senaryoları',
            'Aktif Ağ Savunması: iptables güvenlik duvarı ve şüpheli trafik engelleme kuralları',
            'Sistem sertleştirme ve savunma laboratuvarları teknik altyapısı'
        ],
        'skills': ['Blue Team', 'Digital Forensics', 'Firewall', 'Ağ Savunması'],
        'tier': 'core'
    },
]


CURRENT_WORK_ROADMAP = [
    {
        'title': 'Red Team & OSINT Laboratuvarları',
        'status': 'Yayında',
        'status_color': 'emerald',
        'accent': 'red',
        'icon': 'fa-solid fa-crosshairs',
        'desc': 'Bayrak Avı 1 (Kaynak Kod Analizi) ve OhSINT Lab 2 (EXIF & Açık Kaynak İstihbaratı) aktif; eğitim PDF ve video rehberleriyle destekleniyor.',
        'endpoint': 'red_team',
        'link_text': 'Red Team Modülünü İncele'
    },
    {
        'title': 'Blue Team & İnteraktif SOC Konsolu',
        'status': 'Yayında',
        'status_color': 'emerald',
        'accent': 'sky',
        'icon': 'fa-solid fa-shield-halved',
        'desc': 'SOC Vakası 1 kapsamında gerçekçi access.log ve auth.log kayıtlarını filtreleyip Base64 çözücüyle analiz eden tarayıcı içi inceleme konsolu.',
        'endpoint': 'blue_team',
        'link_text': 'Blue Team Modülünü İncele'
    },
    {
        'title': 'Purple Team & Zararlı Yazılım Analizi',
        'status': 'Geliştiriliyor',
        'status_color': 'purple',
        'accent': 'purple',
        'icon': 'fa-solid fa-bolt',
        'desc': 'Atomic Red Team tehdit emülasyonu, MITRE ATT&CK taktik doğrulaması ve statik malware inceleme senaryoları hazırlanıyor.',
        'endpoint': 'purple_team',
        'link_text': 'Purple Team Yol Haritası'
    },
    {
        'title': 'Platform Güvenliği, 2FA & NÖHÜ Etkinlik Radarı',
        'status': 'Sürekli Güncel',
        'status_color': 'cyan',
        'accent': 'amber',
        'icon': 'fa-solid fa-layer-group',
        'desc': 'Dinamik hız bonusu, First Blood rozetleri, TOTP iki adımlı doğrulama ve NÖHÜ resmi etkinlik takvimi entegrasyonu ile platform sürekli geliştiriliyor.',
        'endpoint': 'events_page',
        'link_text': 'Etkinlik Takvimine Git'
    },
]


RAW_GALLERY_SLOTS = [
    {
        'id': 'gallery-1',
        'title': 'Geliştirme & Kodlama Süreci',
        'caption': 'Platform mimarisi, laboratuvar senaryoları ve arayüz geliştirme kareleri.',
        'filename': 'gallery_1.jpg',
        'icon': 'fa-solid fa-laptop-code',
        'accent': 'cyan'
    },
    {
        'id': 'gallery-2',
        'title': 'NÖHÜ Kampüs & Bölüm Çalışmaları',
        'caption': 'Bilgisayar ve Bilişim Bilimleri Fakültesi & Bilgi Teknolojileri Güvenliği Bölümü hatıraları.',
        'filename': 'gallery_2.jpg',
        'icon': 'fa-solid fa-building-columns',
        'accent': 'indigo'
    },
    {
        'id': 'gallery-3',
        'title': 'CTF & Ekip Buluşmaları',
        'caption': 'Takım arkadaşlarımızla yaptığımız siber güvenlik çalışmaları ve toplantılar.',
        'filename': 'gallery_3.jpg',
        'icon': 'fa-solid fa-people-group',
        'accent': 'emerald'
    },
]


def get_team_context():
    """Build resolved team members, academic info, roadmap, and gallery slots."""
    members = []
    for m in RAW_TEAM_MEMBERS:
        item = dict(m)
        item['photo_url'] = _photo_url_if_exists(m.get('photo_filename'))
        members.append(item)

    core_members = [m for m in members if m.get('tier') == 'core']
    extended_members = [m for m in members if m.get('tier') != 'core']

    gallery = []
    for g in RAW_GALLERY_SLOTS:
        slot = dict(g)
        slot['photo_url'] = _photo_url_if_exists(g.get('filename'))
        gallery.append(slot)

    return {
        'academic': ACADEMIC_INFO,
        'team_members': members,
        'core_members': core_members,
        'extended_members': extended_members,
        'current_work': CURRENT_WORK_ROADMAP,
        'gallery_slots': gallery,
    }
