import os
import json
import urllib.request
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from flask import current_app

def send_via_resend_api(api_key, to_email, subject, html_body):
    """
    Render Free Tier gibi harici SMTP portlarının (587/465) engellendiği bulut
    ortamlarında HTTPS Port 443 üzerinden Resend REST API ile e-posta gönderir.
    """
    url = "https://api.resend.com/emails"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "User-Agent": "NOHU-CyberHub/1.0"
    }
    payload = {
        "from": "NÖHÜ Siber Lab <onboarding@resend.dev>",
        "to": [to_email],
        "subject": subject,
        "html": html_body
    }
    try:
        req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'), headers=headers, method='POST')
        with urllib.request.urlopen(req, timeout=8) as response:
            if response.getcode() in [200, 201]:
                print(f"[+] Resend REST API üzerinden e-posta başarıyla iletildi: {to_email}")
                return True, "Doğrulama kodu başarıyla e-posta adresinize gönderildi."
            return False, f"Resend API HTTP {response.getcode()}"
    except Exception as e:
        print(f"[!] Resend API Hatası: {e}")
        return False, str(e)

def send_verification_email(to_email, username, verification_code):
    """
    Kullanıcının e-posta adresine siber güvenlik temalı (Dark Mode / Terminal)
    HTML doğrulama kodu gönderir.
    Önce Resend REST API (varsa), ardından standart SMTP dener.
    """
    subject = f"🛡️ NÖHÜ Siber Lab - Hesap Doğrulama Kodunuz: {verification_code}"

    try:
        html_body = f"""
        <!DOCTYPE html>
        <html lang="tr">
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
        </head>
        <body style="margin: 0; padding: 30px 15px; background-color: #06090f; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #cbd5e1;">
            <table role="presentation" width="100%" cellpadding="0" cellspacing="0" border="0" style="background-color: #06090f; margin: 0; padding: 0;">
                <tr>
                    <td align="center">
                        <table role="presentation" width="100%" style="max-width: 520px; background-color: #0f172a; border: 1px solid #1e293b; border-radius: 12px; overflow: hidden; box-shadow: 0 10px 30px rgba(0,0,0,0.6);" cellpadding="0" cellspacing="0" border="0">
                            
                            <!-- Header -->
                            <tr>
                                <td style="background-color: #030712; padding: 26px 20px; text-align: center; border-bottom: 1px solid #1e293b; border-top: 3px solid #2563eb;">
                                    <div style="font-size: 11px; font-family: 'Courier New', monospace; color: #38bdf8; letter-spacing: 2px; margin-bottom: 6px; text-transform: uppercase;">
                                        [ NÖHÜ SİBER GÜVENLİK LABORATUVARI ]
                                    </div>
                                    <h1 style="margin: 0; font-size: 18px; font-weight: 700; color: #ffffff; letter-spacing: 0.5px;">
                                        Kimlik Doğrulama Servisi
                                    </h1>
                                    <p style="margin: 5px 0 0; font-size: 12px; color: #64748b;">
                                        Bilgi Teknolojileri Bölümü &bull; Güvenlik Altyapısı
                                    </p>
                                </td>
                            </tr>

                            <!-- Content -->
                            <tr>
                                <td style="padding: 32px 28px; background-color: #0f172a; text-align: center;">
                                    <p style="margin: 0 0 16px; font-size: 15px; color: #f1f5f9; text-align: left;">
                                        Merhaba <strong style="color: #38bdf8; font-family: 'Courier New', monospace;">{username}</strong>,
                                    </p>
                                    <p style="margin: 0 0 24px; font-size: 13px; color: #94a3b8; line-height: 1.6; text-align: left;">
                                        Siber Güvenlik Eğitim Platformuna (Red Team & Blue Team Hub) kaydınızı tamamlamak ve hesabınızı aktifleştirmek için 6 haneli güvenlik kodunuz oluşturuldu:
                                    </p>

                                    <!-- Cyber Terminal Code Box -->
                                    <div style="background-color: #030712; border: 2px dashed #0284c7; border-radius: 8px; padding: 20px 15px; margin: 24px 0; text-align: center;">
                                        <div style="font-size: 10px; color: #64748b; font-family: 'Courier New', monospace; letter-spacing: 2px; margin-bottom: 8px;">
                                            // SECURITY_VERIFICATION_TOKEN
                                        </div>
                                        <div style="font-size: 32px; font-weight: 800; letter-spacing: 8px; color: #38bdf8; font-family: 'Courier New', Consolas, monospace; display: inline-block;">
                                            {verification_code}
                                        </div>
                                        <div style="font-size: 11px; color: #10b981; font-family: 'Courier New', monospace; margin-top: 8px;">
                                            &bull; STATUS: ACTIVE_PENDING_CONFIRMATION
                                        </div>
                                    </div>

                                    <!-- Security Notice -->
                                    <div style="background-color: #1a1015; border-left: 3px solid #dc2626; border-radius: 4px; padding: 12px 14px; margin-top: 20px; text-align: left;">
                                        <div style="font-size: 11px; font-weight: 600; color: #f87171; margin-bottom: 2px;">
                                            ⚠️ Güvenlik Uyarısı
                                        </div>
                                        <div style="font-size: 11px; color: #cbd5e1; line-height: 1.4;">
                                            Bu kod tek kullanımlıktır ve 15 dakika geçerlidir. Güvenliğiniz için bu anahtarı kimseyle paylaşmayınız.
                                        </div>
                                    </div>
                                </td>
                            </tr>

                            <!-- Footer -->
                            <tr>
                                <td style="background-color: #030712; padding: 18px 20px; text-align: center; font-size: 11px; color: #475569; border-top: 1px solid #1e293b; font-family: 'Courier New', monospace;">
                                    &copy; 2026 Niğde Ömer Halisdemir Üniversitesi &bull; NÖHÜ Siber Lab
                                </td>
                            </tr>

                        </table>
                    </td>
                </tr>
            </table>
        </body>
        </html>
        """

        # 1. Öncelik: Resend REST API (HTTPS Port 443 - Bulut ve Render kısıtlamalarına takılmaz)
        resend_key = os.environ.get('RESEND_API_KEY') or current_app.config.get('RESEND_API_KEY')
        if resend_key:
            sent, api_msg = send_via_resend_api(resend_key, to_email, subject, html_body)
            if sent:
                return True, api_msg

        # 2. Öncelik: Standart SMTP (Localhost veya engellenmemiş sunucularda çalışır)
        mail_username = current_app.config.get('MAIL_USERNAME', '').strip()
        mail_password = current_app.config.get('MAIL_PASSWORD', '').strip()
        mail_server = current_app.config.get('MAIL_SERVER', 'smtp.gmail.com')
        mail_port = int(current_app.config.get('MAIL_PORT', 587))
        use_tls = current_app.config.get('MAIL_USE_TLS', True)

        if not mail_username or not mail_password:
            return False, "SMTP e-posta bilgileri (MAIL_USERNAME / MAIL_PASSWORD) yapılandırılmamış."

        msg = MIMEMultipart('alternative')
        msg['Subject'] = subject
        msg['From'] = f"NÖHÜ Siber Güvenlik Lab <{mail_username}>"
        msg['To'] = to_email
        msg.attach(MIMEText(html_body, 'html', 'utf-8'))

        # Timeout 4 sn tutuldu (bulut güvenlik duvarında isteklerin askıda kalmaması için)
        with smtplib.SMTP(mail_server, mail_port, timeout=4) as server:
            if use_tls:
                server.starttls()
            server.login(mail_username, mail_password)
            server.sendmail(mail_username, to_email, msg.as_string())

        print(f"[+] Siber temalı doğrulama kodu {to_email} adresine başarıyla iletildi.")
        return True, "Doğrulama kodu başarıyla e-posta adresinize gönderildi."

    except Exception as e:
        error_msg = str(e)
        print(f"[!] E-posta gönderme hatası: {error_msg}")
        return False, error_msg
