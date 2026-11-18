// Cyber Security Hub - Frontend Logic & Interactivity

document.addEventListener('DOMContentLoaded', () => {
    initPasswordStrengthChecker();
    initLabTimer();
    initFlagSubmission();
});

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

        // Min 6 chars
        const hasLength = val.length >= 6;
        // Has Letter (a-zA-Z)
        const hasLetter = /[A-Za-z]/.test(val);
        // Has Number (0-9)
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
            element.classList.remove('text-gray-400', 'text-red-400');
            element.classList.add('text-emerald-400');
            if (icon) {
                icon.className = 'fa-solid fa-circle-check mr-2';
            }
        } else {
            element.classList.remove('text-emerald-400');
            element.classList.add('text-gray-400');
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
    const flagForm = document.getElementById('flag-form');
    const flagInput = document.getElementById('flag-input');
    const flagSubmitBtn = document.getElementById('flag-submit-btn');
    const labContentArea = document.getElementById('lab-interactive-area');
    const timeoutBanner = document.getElementById('lab-timeout-banner');

    if (!timerDisplay || !timeLimitInput) return;

    let remainingSeconds = parseInt(timeLimitInput.value) || 600;
    window.labRemainingSeconds = remainingSeconds;

    function renderTime() {
        window.labRemainingSeconds = remainingSeconds;
        const minutes = Math.floor(remainingSeconds / 60);
        const seconds = remainingSeconds % 60;
        timerDisplay.textContent = `${minutes.toString().padStart(2, '0')}:${seconds.toString().padStart(2, '0')}`;

        // Color coding
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

            // Kilit mekanizması
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
            const remainingSec = (typeof window.labRemainingSeconds === 'number') ? window.labRemainingSeconds : null;
            const res = await fetch('/api/submit-flag', {
                method: 'POST',
                headers: { 
                    'Content-Type': 'application/json',
                    'X-CSRFToken': csrfToken
                },
                body: JSON.stringify({ 
                    lab_id: labId, 
                    flag: flagVal,
                    remaining_seconds: remainingSec
                })
            });

            const data = await res.json();

            if (feedbackBox) {
                feedbackBox.classList.remove('hidden', 'bg-emerald-950/70', 'border-emerald-500', 'bg-red-950/70', 'border-red-500');

                if (data.success) {
                    if (data.new_score) {
                        const ns = document.getElementById('navbar-user-score');
                        if (ns) ns.textContent = `${data.new_score} P`;
                    }

                    feedbackBox.classList.add('bg-emerald-950/70', 'border-emerald-500', 'text-emerald-200');
                    feedbackBox.innerHTML = `
                        <div class="flex items-start space-x-3">
                            <i class="fa-solid fa-circle-check text-2xl text-emerald-400 mt-0.5"></i>
                            <div class="space-y-1">
                                <h4 class="font-bold text-emerald-300">BAŞARILI!</h4>
                                <p class="text-sm leading-relaxed">${data.message}</p>
                                ${data.speed_bonus > 0 ? `
                                <div class="inline-flex items-center gap-1.5 px-2.5 py-1 rounded bg-amber-950 border border-amber-600 text-amber-300 text-xs font-mono font-bold">
                                    <i class="fa-solid fa-bolt text-amber-400"></i>
                                    <span>Hız Bonusu: +${data.speed_bonus} Ekstra Puan!</span>
                                </div>` : ''}
                            </div>
                        </div>
                    `;

                    // If completed, stop timer and celebrate
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
