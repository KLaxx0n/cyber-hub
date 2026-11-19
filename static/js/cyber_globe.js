/**
 * NÖHÜ Siber Güvenlik Platformu - İnteraktif 3D Siber Tehdit Küresi
 * Çerçevesiz, doğrudan hero alanına entegre, yoğun siber saldırı (Red Team) ve savunma (Blue Team) akışları.
 * Mouse ile 3D serbestçe döndürülebilir.
 */

document.addEventListener('DOMContentLoaded', function () {
    const container = document.getElementById('cyber-globe-viz');
    if (!container) return;

    if (typeof Globe === 'undefined') {
        console.warn('Globe.gl kütüphanesi henüz yüklenmedi.');
        return;
    }

    // Dünya Çapında Genişletilmiş Siber Düğümler (40+ Global Node)
    const CYBER_NODES = [
        // Türkiye & Bölge
        { id: 'nohu', name: 'NÖHÜ Siber Lab (Niğde HQ)', lat: 37.97, lng: 34.68, team: 'blue', isHQ: true },
        { id: 'ankara', name: 'Ankara USOM / SOC', lat: 39.93, lng: 32.85, team: 'blue' },
        { id: 'istanbul', name: 'İstanbul Finans SOC', lat: 41.00, lng: 28.97, team: 'blue' },
        { id: 'izmir', name: 'İzmir Ege Node', lat: 38.42, lng: 27.14, team: 'blue' },

        // Avrupa
        { id: 'frankfurt', name: 'Frankfurt DE-CIX', lat: 50.11, lng: 8.68, team: 'red' },
        { id: 'london', name: 'London Cyber Center', lat: 51.50, lng: -0.12, team: 'blue' },
        { id: 'amsterdam', name: 'Amsterdam AMS-IX', lat: 52.36, lng: 4.90, team: 'red' },
        { id: 'paris', name: 'Paris Data Hub', lat: 48.85, lng: 2.35, team: 'blue' },
        { id: 'berlin', name: 'Berlin SecOps', lat: 52.52, lng: 13.40, team: 'red' },
        { id: 'madrid', name: 'Madrid Node', lat: 40.41, lng: -3.70, team: 'blue' },
        { id: 'stockholm', name: 'Stockholm IX', lat: 59.33, lng: 18.06, team: 'red' },
        { id: 'zurich', name: 'Zürich FinSec', lat: 47.37, lng: 8.54, team: 'blue' },
        { id: 'warsaw', name: 'Warsaw Hub', lat: 52.23, lng: 21.01, team: 'red' },

        // Kuzey Amerika
        { id: 'newyork', name: 'New York WallSt Gateway', lat: 40.71, lng: -74.00, team: 'blue' },
        { id: 'silicon', name: 'Silicon Valley Cloud', lat: 37.77, lng: -122.41, team: 'red' },
        { id: 'washington', name: 'Washington DC Gov SOC', lat: 38.90, lng: -77.03, team: 'blue' },
        { id: 'chicago', name: 'Chicago Exchange Node', lat: 41.87, lng: -87.62, team: 'red' },
        { id: 'seattle', name: 'Seattle Cloud Hub', lat: 47.60, lng: -122.33, team: 'blue' },
        { id: 'toronto', name: 'Toronto IXP', lat: 43.65, lng: -79.38, team: 'blue' },
        { id: 'austin', name: 'Austin Tech Center', lat: 30.26, lng: -97.74, team: 'red' },

        // Asya & Pasifik
        { id: 'tokyo', name: 'Tokyo AP Gateway', lat: 35.67, lng: 139.65, team: 'red' },
        { id: 'singapore', name: 'Singapur Hub', lat: 1.35, lng: 103.81, team: 'blue' },
        { id: 'seoul', name: 'Seoul Telecom Node', lat: 37.56, lng: 126.97, team: 'red' },
        { id: 'beijing', name: 'Beijing APT Cluster', lat: 39.90, lng: 116.40, team: 'red' },
        { id: 'hongkong', name: 'Hong Kong Gateway', lat: 22.31, lng: 114.16, team: 'blue' },
        { id: 'mumbai', name: 'Mumbai Data Hub', lat: 19.07, lng: 72.87, team: 'red' },
        { id: 'taiwan', name: 'Taipei Semi Sec', lat: 25.03, lng: 121.56, team: 'blue' },
        { id: 'sydney', name: 'Sidney Pasifik SOC', lat: -33.86, lng: 151.20, team: 'blue' },
        { id: 'melbourne', name: 'Melbourne Node', lat: -37.81, lng: 144.96, team: 'red' },

        // Orta Doğu & Afrika & Rusya
        { id: 'dubai', name: 'Dubai Gulf Gateway', lat: 25.20, lng: 55.27, team: 'blue' },
        { id: 'riyadh', name: 'Riyadh Telecom', lat: 24.71, lng: 46.67, team: 'blue' },
        { id: 'telaviv', name: 'Tel Aviv Cyber Lab', lat: 32.08, lng: 34.78, team: 'red' },
        { id: 'moscow', name: 'Moscow Threat Group', lat: 55.75, lng: 37.61, team: 'red' },
        { id: 'cairo', name: 'Cairo Nile Hub', lat: 30.04, lng: 31.23, team: 'blue' },
        { id: 'johannesburg', name: 'Johannesburg Node', lat: -26.20, lng: 28.04, team: 'blue' },

        // Latin Amerika
        { id: 'saopaulo', name: 'São Paulo LatAm Node', lat: -23.55, lng: -46.63, team: 'red' },
        { id: 'buenosaires', name: 'Buenos Aires IX', lat: -34.60, lng: -58.38, team: 'blue' },
        { id: 'santiago', name: 'Santiago Andes Node', lat: -33.44, lng: -70.66, team: 'red' }
    ];

    // Aktif Yaylar ve Halkalar
    let activeArcs = [];
    let activeRings = [];

    // NÖHÜ HQ halkası sürekli aktif ve belirgin
    activeRings.push({
        lat: 37.97,
        lng: 34.68,
        maxR: 5.5,
        propagationSpeed: 3,
        repeatPeriod: 1000,
        color: () => 'rgba(34, 211, 238, 0.9)'
    });

    // Yoğun siber saldırı / savunma yayı oluşturucu
    function createCyberArc() {
        const isRedAttack = Math.random() < 0.55; // %55 Kırmızı Saldırı, %45 Mavi Savunma
        const sourceIndex = Math.floor(Math.random() * CYBER_NODES.length);
        let targetIndex = Math.floor(Math.random() * CYBER_NODES.length);
        while (targetIndex === sourceIndex) {
            targetIndex = Math.floor(Math.random() * CYBER_NODES.length);
        }

        // Bazen NÖHÜ veya Türkiye merkezli düğümlere yönlendir
        if (Math.random() < 0.25) {
            targetIndex = 0; // NÖHÜ HQ
        }

        const source = CYBER_NODES[sourceIndex];
        const target = CYBER_NODES[targetIndex];

        // Kırmızı ve Mavi için parlak neon gradyanlar
        const redGradients = [
            ['rgba(255, 23, 68, 0.95)', 'rgba(255, 82, 82, 0.9)'],
            ['rgba(244, 63, 94, 0.95)', 'rgba(225, 29, 72, 0.85)'],
            ['rgba(239, 68, 68, 0.95)', 'rgba(185, 28, 28, 0.85)']
        ];

        const blueGradients = [
            ['rgba(0, 240, 255, 0.95)', 'rgba(0, 114, 255, 0.9)'],
            ['rgba(56, 189, 248, 0.95)', 'rgba(2, 132, 199, 0.85)'],
            ['rgba(96, 165, 250, 0.95)', 'rgba(37, 99, 235, 0.85)']
        ];

        const chosenColors = isRedAttack 
            ? redGradients[Math.floor(Math.random() * redGradients.length)]
            : blueGradients[Math.floor(Math.random() * blueGradients.length)];

        // Hedefte anlık darbe halkası tetikle
        if (Math.random() < 0.4) {
            activeRings.push({
                lat: target.lat,
                lng: target.lng,
                maxR: isRedAttack ? 3.8 : 3.2,
                propagationSpeed: isRedAttack ? 3.5 : 2.8,
                repeatPeriod: 1200,
                color: () => isRedAttack ? 'rgba(255, 23, 68, 0.8)' : 'rgba(0, 240, 255, 0.8)'
            });

            if (activeRings.length > 14) {
                activeRings.splice(1, 1);
            }
        }

        return {
            id: 'arc-' + Date.now() + '-' + Math.random().toString(36).substr(2, 6),
            startLat: source.lat,
            startLng: source.lng,
            endLat: target.lat,
            endLng: target.lng,
            color: chosenColors,
            altitude: 0.12 + Math.random() * 0.35,
            stroke: isRedAttack ? (1.5 + Math.random() * 0.8) : (1.2 + Math.random() * 0.6),
            order: Math.random(),
            animateTime: 1200 + Math.random() * 1200 // Hızlı ve dinamik akış
        };
    }

    const isMobileViewport = window.innerWidth < 640;
    const maxActiveArcs = isMobileViewport ? 22 : 40;

    // Başlangıçta aktif saldırı hatlarını oluştur
    for (let i = 0; i < maxActiveArcs; i++) {
        activeArcs.push(createCyberArc());
    }

    // Globe.gl Boyutlandırma
    const initialWidth = container.clientWidth || 480;
    const initialHeight = container.clientHeight || 440;

    const globe = Globe()(container)
        .width(initialWidth)
        .height(initialHeight)
        .backgroundColor('rgba(0,0,0,0)') // Şeffaf arka plan, kartın cam efektiyle bütünleşik
        .globeImageUrl('/static/img/globe/earth-night.jpg')
        .bumpImageUrl('/static/img/globe/earth-topology.png')
        // Atmosfer Halesi
        .showAtmosphere(true)
        .atmosphereColor('#38bdf8')
        .atmosphereAltitude(0.24)
        // Yoğun Siber Saldırı Yayları
        .arcsData(activeArcs)
        .arcColor('color')
        .arcAltitude('altitude')
        .arcStroke('stroke')
        .arcDashLength(0.45)
        .arcDashGap(0.18)
        .arcDashInitialGap(d => d.order * 0.1)
        .arcDashAnimateTime('animateTime')
        // Darbe ve Savunma Dalgaları
        .ringsData(activeRings)
        .ringColor('color')
        .ringMaxRadius('maxR')
        .ringPropagationSpeed('propagationSpeed')
        .ringRepeatPeriod('repeatPeriod')
        // Düğümler
        .pointsData(CYBER_NODES)
        .pointColor(d => d.isHQ ? '#22d3ee' : (d.team === 'red' ? '#ff1744' : '#00f0ff'))
        .pointAltitude(d => d.isHQ ? 0.04 : 0.02)
        .pointRadius(d => d.isHQ ? 0.95 : 0.5)
        .pointResolution(24)
        // Etiket
        .labelsData([
            { lat: 37.97, lng: 34.68, text: '★ NÖHÜ Siber Lab', color: '#22d3ee', size: 1.2 }
        ])
        .labelText('text')
        .labelSize('size')
        .labelColor('color')
        .labelDotRadius(0.35)
        .labelAltitude(0.025);

    // Mouse / Kamera Kontrolleri
    const controls = globe.controls();
    if (controls) {
        controls.autoRotate = true;
        controls.autoRotateSpeed = 0.95; // Akıcı dönüş
        controls.enableZoom = false;     // Sayfa kaydırma ile çakışmasın
        controls.enableDamping = true;   // Akıcı ivmeli dönüş hissi
        controls.dampingFactor = 0.05;
        controls.minPolarAngle = Math.PI * 0.12;
        controls.maxPolarAngle = Math.PI * 0.88;
    }

    // Başlangıç Açısı: Türkiye ve Çevresini (NÖHÜ) Merkeze Al (mobilde tam sığması için biraz daha uzak kamera)
    globe.pointOfView({ lat: 38.0, lng: 35.0, altitude: isMobileViewport ? 2.45 : 2.15 }, 1200);

    // Yüksek Frekanslı Saldırı Döngüsü (Her 280ms'de yeni saldırılar ekle)
    setInterval(() => {
        while (activeArcs.length > maxActiveArcs) {
            activeArcs.shift();
        }
        // Aynı anda 1 veya 2 yeni saldırı yayını ekle
        activeArcs.push(createCyberArc());
        if (Math.random() < 0.6) {
            activeArcs.push(createCyberArc());
        }

        globe.arcsData([...activeArcs]);
        globe.ringsData([...activeRings]);
    }, 280);

    // Responsive Yeniden Boyutlandırma
    const resizeObserver = new ResizeObserver(entries => {
        for (let entry of entries) {
            const w = entry.contentRect.width;
            const h = entry.contentRect.height;
            if (w > 0 && h > 0) {
                globe.width(w).height(h);
            }
        }
    });
    resizeObserver.observe(container);

    window.addEventListener('resize', () => {
        if (container.clientWidth > 0 && container.clientHeight > 0) {
            globe.width(container.clientWidth).height(container.clientHeight);
        }
    });
});
