"""Configuration and task definitions for multi-task interactive labs."""

MULTI_TASK_LABS = {
    'red-bayrak-avi-1': {
        'pass_threshold': 50,
        'target_endpoint': 'bayrak_avi_1_target',
        'target_label': 'hedef_site.html',
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
