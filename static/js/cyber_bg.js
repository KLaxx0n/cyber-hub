/**
 * CyberHub Siber Harekât ve Savunma Merkezi (AEGIS CYBER-OPS v2)
 * Taktiksel Radar & Koordinat Izgara Arka Plan Motoru
 * Hafif, yüksek performanslı ve sinematik operasyon ekranı
 */

(function () {
    const canvas = document.getElementById('cyber-bg-canvas');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    let width = canvas.width = window.innerWidth;
    let height = canvas.height = window.innerHeight;

    let sweepAngle = 0;
    const GRID_SPACING = 60; // Izgara aralığı

    // Simüle edilmiş telemetri noktaları (radar pingleri)
    const pings = [];
    const PING_COUNT = 14;

    function initPings() {
        pings.length = 0;
        for (let i = 0; i < PING_COUNT; i++) {
            pings.push({
                x: Math.random() * width,
                y: Math.random() * height,
                type: Math.random() > 0.5 ? 'red' : 'blue',
                alpha: Math.random() * 0.7,
                size: 2 + Math.random() * 2,
                pulse: 0,
                pulseSpeed: 0.02 + Math.random() * 0.03,
                label: Math.random() > 0.7 ? (Math.random() > 0.5 ? '10.10.' + Math.floor(Math.random() * 254) : 'NODE-' + Math.floor(Math.random() * 99)) : null
            });
        }
    }

    function draw() {
        ctx.clearRect(0, 0, width, height);

        // 1. Koordinat Kesişim Artıları (+)
        ctx.fillStyle = 'rgba(255, 255, 255, 0.035)';
        for (let x = GRID_SPACING; x < width; x += GRID_SPACING) {
            for (let y = GRID_SPACING; y < height; y += GRID_SPACING) {
                // Küçük artı işareti
                ctx.fillRect(x - 3, y, 7, 1);
                ctx.fillRect(x, y - 3, 1, 7);
            }
        }

        // 2. Taktiksel Radar Taraması (Merkezden ya da üstten hafif tarama açısı)
        sweepAngle += 0.008;
        const centerX = width * 0.5;
        const centerY = height * 0.35;
        const radius = Math.max(width, height) * 0.7;

        const sweepGradient = ctx.createConicGradient(sweepAngle, centerX, centerY);
        sweepGradient.addColorStop(0, 'rgba(56, 189, 248, 0.04)');
        sweepGradient.addColorStop(0.08, 'rgba(56, 189, 248, 0.01)');
        sweepGradient.addColorStop(0.15, 'transparent');
        sweepGradient.addColorStop(1, 'transparent');

        ctx.fillStyle = sweepGradient;
        ctx.beginPath();
        ctx.arc(centerX, centerY, radius, 0, Math.PI * 2);
        ctx.fill();

        // 3. Taktiksel Radar Halkaları
        ctx.strokeStyle = 'rgba(255, 255, 255, 0.025)';
        ctx.lineWidth = 1;
        [180, 360, 540, 720].forEach(r => {
            ctx.beginPath();
            ctx.arc(centerX, centerY, r, 0, Math.PI * 2);
            ctx.stroke();
        });

        // 4. Telemetri Noktaları & Yanıp Sönen Düğümler
        pings.forEach(p => {
            p.pulse += p.pulseSpeed;
            const currentAlpha = 0.2 + (Math.sin(p.pulse) + 1) * 0.25;

            ctx.beginPath();
            ctx.arc(p.x, p.y, p.size, 0, Math.PI * 2);
            ctx.fillStyle = p.type === 'red' ? `rgba(244, 63, 94, ${currentAlpha})` : `rgba(56, 189, 248, ${currentAlpha})`;
            ctx.fill();

            // Etiket varsa yaz
            if (p.label) {
                ctx.font = '9px "JetBrains Mono", monospace';
                ctx.fillStyle = p.type === 'red' ? `rgba(244, 63, 94, ${currentAlpha * 0.8})` : `rgba(56, 189, 248, ${currentAlpha * 0.8})`;
                ctx.fillText(p.label, p.x + 6, p.y + 3);
            }
        });

        requestAnimationFrame(draw);
    }

    window.addEventListener('resize', () => {
        width = canvas.width = window.innerWidth;
        height = canvas.height = window.innerHeight;
        initPings();
    });

    initPings();
    draw();
})();
