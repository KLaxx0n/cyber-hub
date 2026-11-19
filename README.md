# Siber Güvenlik Eğitim Platformu (Red Team & Blue Team Hub)

[![Deploy to Render](https://render.com/images/deploy-to-render-button.svg)](https://render.com/deploy?repo=https://github.com/KLaxx0n/cyber-hub)

**Niğde Ömer Halisdemir Üniversitesi — Bilgi Teknolojileri Güvenliği Bölümü**  
**Dönem Projesi & Teknik Dokümantasyon Uygulaması**

---

## 👥 Proje Ekibi ve Rol Dağılımı

1. **Aziz:** Proje Koordinatörü, Red Team, OWASP Top 10 ve Flag Hunting (Bayrak Avı) Mekanizması
2. **Sefa (Full-Stack Uzmanı):** Web Sitesi Tasarımı (HTML, CSS Dark Mode), Backend (Python/Flask, Kayıt/Giriş, Regex Şifre Kontrolü, E-Posta Doğrulama Kodu) ve Sosyal Mühendislik Simülasyonu
3. **Blue Team Sorumlusu (Geçici):** Digital Forensics (Adli Bilişim & Hex Kurtarma), Savunma Kuralları ve Geri Sayım Sayacı (Timer)

---

## 🚀 Proje Mimarisi ve Özellikleri

* **Ön Yüz (Frontend):** 
  * Responsive, modern koyu tema (Cyberpunk/Dark Mode) siber güvenlik estetiği.
  * Tailwind CSS & FontAwesome ikonları ile donatılmış arayüz.
* **Arka Yüz (Backend - Python / Flask):**
  * `app.py`: Ana yönlendirmeler, API rotaları ve oturum yönetimi.
  * `models.py`: `User`, `Lab`, `UserLabProgress` veritabanı modelleri (SQLite & SQLAlchemy).
  * `seed_data.py`: Gerçekçi Red Team ve Blue Team laboratuvar verilerini yükleyen tohumlama scripti.
* **Güvenlik & Kimlik Doğrulama:**
  * **Regex Şifre Kontrolü:** Şifrenin hem harf (a-z / A-Z) hem de rakam (0-9) ve en az 6 karakter içermesi kuralı (Frontend canlı geri bildirim + Backend doğrulaması).
  * **E-Posta Doğrulama Kodu:** Kayıt sonrasında üretilen 6 haneli alfa-sayısal doğrulama kodu (`verify.html`) ile hesap aktivasyonu.
  * **Proje Lideri Yönetim Paneli (`/admin`):** Proje liderlerine özel yönetim kontrol merkezi; kayıtlı öğrencileri, aktivasyon kodlarını, çözülen labları ve skorları listeler, filtreler, tek tıkla e-posta onayı sağlar ve diğer kullanıcılara Proje Liderliği yetkisi atama/geri alma imkânı sunar.
* **İnteraktif Laboratuvarlar & Zamanlayıcı:**
  * JavaScript `setInterval` ile çalışan canlı geri sayım sayacı (`Timer`).
  * Süre bitiminde laboratuvarın kilitlenmesi ve uyarı mekanizması.
  * Canlı zafiyet simülatörleri:
    * **SQL Injection:** Zafiyetli arama motoru manipülasyonu ve gizli kayıt sızdırma.
    * **Reflected XSS:** DOM enjeksiyonu ve oturum çerezi çalma simülasyonu.
    * **Phishing:** Oltalama e-postası ve sahte domain header analizi (SPF/DKIM/Return-Path).
    * **Log Analizi:** Web sunucu `access.log` kayıtlarında saldırgan IP tespiti ve dosya indirme analizi.
    * **Digital Forensics:** Silinmiş dosya analizi ve Hex dökümünden gizli bayrağı kurtarma.
    * **Firewall Defans:** `iptables` güvenlik duvarı kuralı yazarak saldırgan subnetini bloklama.
* **CTF Tarzı Flag Hunting & Puanlama:**
  * `FLAG{...}` doğrulaması, puan kazanımı ve canlı liderlik sıralaması (`Leaderboard`).

---

## ⚡ Çalıştırma Talimatı

1. Proje dizinine girin:
   ```bash
   cd C:\Users\gsefa\.gemini\antigravity\scratch\cyber-hub
   ```
2. Sunucuyu başlatın:
   ```bash
   python app.py
   ```
   *(Veya doğrudan `run.bat` dosyasına çift tıklayın.)*
3. Tarayıcınızda açın:
   👉 **http://127.0.0.1:5000**

---

### 🔑 Hesap Oluşturma & Giriş:
* Platforma **/register** sayfasından kayıt olarak (veya e-posta doğrulama kodunu girerek) anında giriş yapabilir ve CTF laboratuvarlarını çözmeye başlayabilirsiniz.
* Kayıt olan tüm aktif öğrenciler dinamik olarak Liderlik Sıralaması Tablosuna (Leaderboard) dahil edilir.
