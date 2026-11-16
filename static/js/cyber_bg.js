/**
 * NÖHÜ Siber Güvenlik Platformu - İnteraktif Ağ Animasyonu
 * Transparan camların arkasında net görünen parlak ağ düğümleri
 */

(function () {
    const canvas = document.getElementById('cyber-bg-canvas');
    if (!canvas) return;

    const ctx = canvas.getContext('2d');
    let width = canvas.width = window.innerWidth;
    let height = canvas.height = window.innerHeight;

    const NODE_COUNT = Math.floor((width * height) / 10000); // Daha dolgun ağ
    const MAX_DISTANCE = 140;
    const MOUSE_RADIUS = 180;

    const particles = [];
    const pulses = [];

    // Parlak ve belirgin renkler (Camın arkasında net görünmesi için)
    const colors = [
        { r: 56, g: 189, b: 248 },   // Açık Gökyüzü Mavisi (#38bdf8)
        { r: 96, g: 165, b: 250 },   // Açık Mavi (#60a5fa)
        { r: 248, g: 113, b: 113 },  // Açık Kırmızı (#f87171)
        { r: 52, g: 211, b: 153 }    // Açık Zümrüt Yeşili (#34d399)
    ];

    class Particle {
        constructor() {
            this.x = Math.random() * width;
            this.y = Math.random() * height;
            this.vx = (Math.random() - 0.5) * 0.7;
            this.vy = (Math.random() - 0.5) * 0.7;
            this.radius = Math.random() * 2 + 1.5;
            this.color = colors[Math.floor(Math.random() * colors.length)];
        }

        update() {
            this.x += this.vx;
            this.y += this.vy;

            if (this.x < 0) this.x = width;
            if (this.x > width) this.x = 0;
            if (this.y < 0) this.y = height;
            if (this.y > height) this.y = 0;
        }

        draw() {
            ctx.beginPath();
            ctx.arc(this.x, this.y, this.radius, 0, Math.PI * 2);
            ctx.fillStyle = `rgb(${this.color.r}, ${this.color.g}, ${this.color.b})`;
            ctx.shadowColor = `rgba(${this.color.r}, ${this.color.g}, ${this.color.b}, 0.8)`;
            ctx.shadowBlur = 8;
            ctx.fill();
            ctx.shadowBlur = 0;
        }
    }

    for (let i = 0; i < NODE_COUNT; i++) {
        particles.push(new Particle());
    }

    const mouse = { x: null, y: null };

    window.addEventListener('mousemove', (e) => {
        mouse.x = e.clientX;
        mouse.y = e.clientY;
    });

    window.addEventListener('mouseleave', () => {
        mouse.x = null;
        mouse.y = null;
    });

    window.addEventListener('click', (e) => {
        pulses.push({
            x: e.clientX,
            y: e.clientY,
            radius: 5,
            maxRadius: 220,
            opacity: 0.85
        });
    });

    window.addEventListener('resize', () => {
        width = canvas.width = window.innerWidth;
        height = canvas.height = window.innerHeight;
    });

    function animate() {
        ctx.clearRect(0, 0, width, height);

        // Radar Pulses
        for (let i = pulses.length - 1; i >= 0; i--) {
            const p = pulses[i];
            p.radius += 3.5;
            p.opacity *= 0.96;

            ctx.beginPath();
            ctx.arc(p.x, p.y, p.radius, 0, Math.PI * 2);
            ctx.strokeStyle = `rgba(56, 189, 248, ${p.opacity})`;
            ctx.lineWidth = 1.5;
            ctx.stroke();

            if (p.opacity <= 0.02 || p.radius >= p.maxRadius) {
                pulses.splice(i, 1);
            }
        }

        // Connections & Nodes
        for (let i = 0; i < particles.length; i++) {
            const p1 = particles[i];
            p1.update();

            for (let j = i + 1; j < particles.length; j++) {
                const p2 = particles[j];
                const dx = p1.x - p2.x;
                const dy = p1.y - p2.y;
                const dist = Math.sqrt(dx * dx + dy * dy);

                if (dist < MAX_DISTANCE) {
                    // Net ve görünür çizgi parlaklığı
                    const alpha = (1 - dist / MAX_DISTANCE) * 0.45;
                    ctx.beginPath();
                    ctx.moveTo(p1.x, p1.y);
                    ctx.lineTo(p2.x, p2.y);
                    ctx.strokeStyle = `rgba(${p1.color.r}, ${p1.color.g}, ${p1.color.b}, ${alpha})`;
                    ctx.lineWidth = 0.9;
                    ctx.stroke();
                }
            }

            // Mouse Connection
            if (mouse.x !== null && mouse.y !== null) {
                const dx = p1.x - mouse.x;
                const dy = p1.y - mouse.y;
                const dist = Math.sqrt(dx * dx + dy * dy);

                if (dist < MOUSE_RADIUS) {
                    const alpha = (1 - dist / MOUSE_RADIUS) * 0.75;
                    ctx.beginPath();
                    ctx.moveTo(p1.x, p1.y);
                    ctx.lineTo(mouse.x, mouse.y);
                    ctx.strokeStyle = `rgba(56, 189, 248, ${alpha})`;
                    ctx.lineWidth = 1.2;
                    ctx.stroke();
                }
            }

            p1.draw();
        }

        requestAnimationFrame(animate);
    }

    animate();
})();
