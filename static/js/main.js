// Cyber Security Hub - Frontend Logic & Tactical Interactivity

document.addEventListener('DOMContentLoaded', () => {
    initHudClock();
    initQuickTerminal();
    initPasswordStrengthChecker();
    initLabTimer();
    initFlagSubmission();
});

/* ----------------- 0. HUD CANLI TELEMETRİ SAATİ ----------------- */
function initHudClock() {
    const clockEl = document.getElementById('hud-live-time');
    if (!clockEl) return;

    function update() {
        const now = new Date();
        const hrs = String(now.getHours()).padStart(2, '0');
        const min = String(now.getMinutes()).padStart(2, '0');
        const sec = String(now.getSeconds()).padStart(2, '0');
        clockEl.textContent = `${hrs}:${min}:${sec} UTC+3`;
    }
    update();
    setInterval(update, 1000);
}

/* ----------------- 0.1 ANA SAYFA ETKİLEŞİMLİ MİNİ TERMİNAL ----------------- */
function initQuickTerminal() {
    const inputEl = document.getElementById('quick-terminal-input');
    const outputEl = document.getElementById('quick-terminal-output');
    if (!inputEl || !outputEl) return;

    const commandHistory = [];
    let historyIndex = -1;

    const responses = {
        help: `[Mevcut Komutlar]:
  scan [ip]       - Hedef sunucuda Nmap port taraması başlatır (Örnek: scan 10.10.14.5)
  status          - Savunma düğümleri ve DEFCON alarm seviyesini görüntüler
  target          - Öncelikli sızma testi hedefini listeler
  rules           - Aktif Blue Team iptables / IDS güvenlik filtrelerini listeler
  teams           - Red Team ve Blue Team operasyonel denge istatistiklerini getirir
  whoami          - Aktif oturum kimliğini görüntüler
  clear           - Terminal ekranını temizler`,
        
        status: `[SİSTEM DURUM RAPORU]:
  ● OPERASYON: AKTİF (NOMINAL)
  ● SAVUNMA SEVİYESİ: DEFCON 2 (YÜKSEK HAZIRLIK)
  ● HAREKÂT ÜSSÜ: CyberHub Siber Güvenlik Laboratuvarı (Niğde)
  ● VERİ TABANI: SQLite / SQLAlchemy Engine Online
  ● DOĞRULAMA MOTORU: Regex + SHA-256 Checksum Aktif`,

        target: `[ÖNCELİKLİ HEDEF DOSYASI]:
  [+] Hedef: VulnBank API Gateway (v1.4)
  [+] IP: 10.10.14.5
  [+] Zafiyet Türü: SQL Injection & Yetki Yükseltme
  [+] Ödül: 150 Puan (FLAG{sqli_auth_bypass_success})
  [+] Durum: Laboratuvarda konuşlandırıldı. Çözüm için Red Team paneline gidin.`,

        rules: `[BLUE TEAM AKTİF GÜVENLİK DUVARI KURALLARI]:
  [1] DROP tcp from 45.33.32.156 to any port 80 [SYN Flood Engellendi]
  [2] ALERT tcp any any -> any 22 (msg:"SSH Brute-Force Denemesi"; threshold:type both, count 5, seconds 60;)
  [3] ACCEPT tcp 10.10.0.0/16 to any port 443 [İç Güvenli Bölge]
  [4] LOG tcp any any -> any 80 (pcre:"/(union.*select|or\s+1=1)/Ui"; msg:"SQLi Saldırısı Algılandı";)`,

        teams: `[KUVVET DENGESİ & HAREKÂT SKORU]:
  [RED TEAM]  : %48 Hakimiyet (Ofansif CTF Görevleri & Zafiyet Sömürüleri)
  [BLUE TEAM] : %52 Hakimiyet (Defansif SIEM Analizi, Log İnceleme & Hardening)
  [DURUM]     : İki cephede de eğitim simülasyonları eşit ağırlıkla devam ediyor.`,

        whoami: `[OTURUM KİMLİĞİ]:
  Operatör: ${document.body.getAttribute('data-username') || 'Misafir Operatör'}
  Erişim Yetkisi: Standart Öğrenci / Analist
  Lokasyon: Niğde Ömer Halisdemir Üniversitesi`
    };

    inputEl.addEventListener('keydown', (e) => {
        if (e.key === 'Enter') {
            const raw = inputEl.value.trim();
            if (!raw) return;

            commandHistory.push(raw);
            historyIndex = commandHistory.length;

            const parts = raw.split(' ');
            const cmd = parts[0].toLowerCase();
            const arg = parts.slice(1).join(' ');

            // Yazılan komut satırı
            const cmdLine = document.createElement('div');
            cmdLine.className = 'text-slate-300 mt-1';
            cmdLine.innerHTML = `<span class="text-cyan-400 font-bold">operator@cyberhub:~$</span> <span class="text-white">${escapeHtml(raw)}</span>`;
            outputEl.appendChild(cmdLine);

            // Yanıt oluştur
            const respDiv = document.createElement('div');
            respDiv.className = 'text-xs text-slate-300 whitespace-pre-wrap font-mono my-1 pl-2 border-l-2 border-cyan-500/50';

            if (cmd === 'clear') {
                outputEl.innerHTML = '';
                inputEl.value = '';
                return;
            } else if (cmd === 'scan') {
                const targetIp = arg || '10.10.14.5';
                respDiv.innerHTML = `<span class="text-amber-400 font-bold">[NMAP TARAMASI BAŞLATILDI]</span> -> ${escapeHtml(targetIp)}
Nmap scan report for ${escapeHtml(targetIp)}
Host is up (0.0021s latency).
PORT     STATE SERVICE     VERSION
22/tcp   open  ssh         OpenSSH 8.9p1 Ubuntu
80/tcp   open  http        Apache httpd 2.4.52 (SQLi Zafiyeti Tespit Edildi!)
3306/tcp open  mysql       MySQL 8.0.32
4444/tcp open  metasploit? Reverse Shell Listener
<span class="text-emerald-400">Tarama tamamlandı: 4 açık port bulundu. Laboratuvar modülünden sızma testini başlatabilirsiniz.</span>`;
            } else if (responses[cmd]) {
                respDiv.textContent = responses[cmd];
            } else {
                respDiv.innerHTML = `<span class="text-red-400">Komut bulunamadı: '${escapeHtml(cmd)}'. Komut listesi için 'help' yazın.</span>`;
            }

            outputEl.appendChild(respDiv);
            inputEl.value = '';
            outputEl.scrollTop = outputEl.scrollHeight;
        } else if (e.key === 'ArrowUp') {
            if (historyIndex > 0) {
                historyIndex--;
                inputEl.value = commandHistory[historyIndex];
            }
        } else if (e.key === 'ArrowDown') {
            if (historyIndex < commandHistory.length - 1) {
                historyIndex++;
                inputEl.value = commandHistory[historyIndex];
            } else {
                historyIndex = commandHistory.length;
                inputEl.value = '';
            }
        }
    });

    function escapeHtml(str) {
        return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    }
}

/* ----------------- 1. ŞİFRE KARMAŞIKLIK KONTROLÜ (REGEX) ----------------- */
function initPasswordStrengthChecker() {
    const passwordInput = document.getElementById('reg_password');
    const ruleLength = document.getElementById('rule_length');
    const ruleLetter = document.getElementById('rule_letter');
    const ruleNumber = document.getElementById('rule_number');
    const submitBtn = document.getElementById('register_btn');

    if (!passwordInput) return;

    passwordInput.addEventListener('input', () => {
        const val = passwordInput.value;

        const hasLength = val.length >= 6;
        const hasLetter = /[A-Za-z]/.test(val);
        const hasNumber = /\d/.test(val);

        updateRuleUI(ruleLength, hasLength);
        updateRuleUI(ruleLetter, hasLetter);
        updateRuleUI(ruleNumber, hasNumber);

        if (submitBtn) {
            submitBtn.disabled = !(hasLength && hasLetter && hasNumber);
            if (submitBtn.disabled) {
                submitBtn.classList.add('opacity-50', 'cursor-not-allowed');
            } else {
                submitBtn.classList.remove('opacity-50', 'cursor-not-allowed');
            }
        }
    });

    function updateRuleUI(element, isValid) {
        if (!element) return;
        const icon = element.querySelector('i');
        if (isValid) {
            element.classList.remove('text-slate-400', 'text-red-400');
            element.classList.add('text-emerald-400');
            if (icon) {
                icon.className = 'fa-solid fa-circle-check mr-2';
            }
        } else {
            element.classList.remove('text-emerald-400');
            element.classList.add('text-slate-400');
            if (icon) {
                icon.className = 'fa-regular fa-circle mr-2';
            }
        }
    }
}

/* ----------------- 2. GERİ SAYIM SAYACI (TIMER - setInterval) ----------------- */
let labTimerInterval = null;

function initLabTimer() {
    const timerDisplay = document.getElementById('lab-timer-display');
    const timeLimitInput = document.getElementById('lab-time-limit');
    const flagInput = document.getElementById('flag-input');
    const flagSubmitBtn = document.getElementById('flag-submit-btn');
    const labContentArea = document.getElementById('lab-interactive-area');
    const timeoutBanner = document.getElementById('lab-timeout-banner');

    if (!timerDisplay || !timeLimitInput) return;

    let remainingSeconds = parseInt(timeLimitInput.value) || 600;

    function renderTime() {
        const minutes = Math.floor(remainingSeconds / 60);
        const seconds = remainingSeconds % 60;
        timerDisplay.textContent = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;

        if (remainingSeconds <= 60) {
            timerDisplay.classList.add('timer-critical');
        } else if (remainingSeconds <= 180) {
            timerDisplay.classList.remove('text-cyan-400');
            timerDisplay.classList.add('text-amber-400');
        }
    }

    renderTime();

    labTimerInterval = setInterval(() => {
        remainingSeconds--;
        renderTime();

        if (remainingSeconds <= 0) {
            clearInterval(labTimerInterval);
            timerDisplay.textContent = "00:00 (SÜRE DOLDU)";
            timerDisplay.classList.add('timer-critical');

            if (flagInput) flagInput.disabled = true;
            if (flagSubmitBtn) {
                flagSubmitBtn.disabled = true;
                flagSubmitBtn.classList.add('opacity-50', 'cursor-not-allowed');
            }
            if (labContentArea) {
                labContentArea.classList.add('opacity-40', 'pointer-events-none');
            }
            if (timeoutBanner) {
                timeoutBanner.classList.remove('hidden');
            }
        }
    }, 1000);
}

/* ----------------- 3. FLAG GÖNDERİMİ & PUANLAMA (AJAX) ----------------- */
function initFlagSubmission() {
    const flagForm = document.getElementById('flag-form');
    const feedbackBox = document.getElementById('flag-feedback');

    if (!flagForm) return;

    flagForm.addEventListener('submit', async (e) => {
        e.preventDefault();

        const labId = document.getElementById('lab-id').value;
        const flagVal = document.getElementById('flag-input').value.trim();
        const submitBtn = document.getElementById('flag-submit-btn');

        if (!flagVal) return;

        submitBtn.disabled = true;
        submitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin mr-2"></i>Doğrulanıyor...';

        try {
            const csrfToken = document.querySelector('meta[name="csrf-token"]')?.getAttribute('content') || '';
            const res = await fetch('/api/submit-flag', {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                body: JSON.stringify({ lab_id: labId, flag: flagVal })
            });

            const data = await res.json();

            if (feedbackBox) {
                feedbackBox.classList.remove('hidden', 'bg-emerald-950/70', 'border-emerald-500', 'bg-red-950/70', 'border-red-500');

                if (data.success) {
                    feedbackBox.classList.add('bg-emerald-950/70', 'border-emerald-500', 'text-emerald-200');
                    feedbackBox.innerHTML = `
                        <div class="flex items-center space-x-3">
                            <i class="fa-solid fa-circle-check text-2xl text-emerald-400"></i>
                            <div>
                                <h4 class="font-bold text-emerald-300">BAŞARILI!</h4>
                                <p class="text-sm">${data.message}</p>
                            </div>
                        </div>
                    `;

                    if (labTimerInterval) clearInterval(labTimerInterval);
                    const timerElem = document.getElementById('lab-timer-display');
                    if (timerElem) timerElem.textContent = 'TAMAMLANDI ✔';

                } else {
                    feedbackBox.classList.add('bg-red-950/70', 'border-red-500', 'text-red-200');
                    feedbackBox.innerHTML = `
                        <div class="flex items-center space-x-3">
                            <i class="fa-solid fa-circle-xmark text-2xl text-red-400"></i>
                            <div>
                                <h4 class="font-bold text-red-400">HATALI BAYRAK</h4>
                                <p class="text-sm">${data.message}</p>
                            </div>
                        </div>
                    `;
                }
            }
        } catch (err) {
            console.error(err);
            alert('Sunucu iletişim hatası meydana geldi.');
        } finally {
            submitBtn.disabled = false;
            submitBtn.innerHTML = '<i class="fa-solid fa-paper-plane mr-2"></i>Bayrağı Gönder';
        }
    });
}
