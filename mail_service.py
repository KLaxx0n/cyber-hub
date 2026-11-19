import os
import re
import json
import html
import urllib.request
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.utils import formataddr, formatdate, make_msgid
from flask import current_app


def _strip_html_to_text(html_body):
    """Spam filtrelerini (Gmail/Outlook) geçmek için HTML gövdeden temiz plain-text alternatifi üretir."""
    text = re.sub(r'<style[^>]*>.*?</style>', '', html_body, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<br\s*/?>', '\n', text, flags=re.IGNORECASE)
    text = re.sub(r'</(p|div|tr|h1|h2|h3|li)>', '\n', text, flags=re.IGNORECASE)
    text = re.sub(r'<[^>]+>', '', text)
    text = html.unescape(text)
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    return '\n'.join(lines)


def _to_ascii_email(email_addr):
    """
    IDN (Türkçe karakterli alan adı, örn: iletisim@nöhü-cyberhub.com.tr) içeren
    e-posta adreslerini SMTP protokolünün (RFC 5321/5322) kabul ettiği Punycode
    (iletisim@xn--nh-cyberhub-sfb8g.com.tr) formatına dönüştürür.
    """
    if not email_addr or '@' not in email_addr:
        return email_addr
    local_part, domain_part = email_addr.strip().rsplit('@', 1)
    try:
        ascii_domain = domain_part.encode('idna').decode('ascii')
    except Exception:
        ascii_domain = domain_part
    return f"{local_part}@{ascii_domain}"


def _to_ascii_host(hostname):
    """Türkçe karakterli sunucu adlarını (mail.nöhü-cyberhub.com.tr) Punycode (IDNA) formatına çevirir."""
    if not hostname:
        return hostname
    try:
        return hostname.strip().encode('idna').decode('ascii')
    except Exception:
        return hostname.strip()


def _send_smtp_message(to_email, subject, html_body, plain_body=None, reply_to=None):
    """
    Türkticaret.Net kurumsal SMTP (mail.nöhü-cyberhub.com.tr / 587 STARTTLS veya 465 SSL)
    ve standart SMTP sunucuları üzerinden RFC 5322 & IDNA Punycode uyumlu, düşük spam skorlu e-posta gönderir.
    """
    raw_username = current_app.config.get('MAIL_USERNAME', '').strip()
    mail_password = current_app.config.get('MAIL_PASSWORD', '').strip()
    raw_server = current_app.config.get('MAIL_SERVER', 'smtp.turkticaret.net').strip()
    mail_port = int(current_app.config.get('MAIL_PORT', 587))
    use_tls = current_app.config.get('MAIL_USE_TLS', True)
    use_ssl = current_app.config.get('MAIL_USE_SSL', False)
    sender_name = current_app.config.get('MAIL_SENDER_NAME', 'NÖHÜ Siber Güvenlik Lab').strip()
    raw_sender_email = (current_app.config.get('MAIL_DEFAULT_SENDER') or raw_username).strip()

    if not raw_username or not mail_password:
        return False, "SMTP e-posta bilgileri (MAIL_USERNAME / MAIL_PASSWORD) yapılandırılmamış."

    mail_server = _to_ascii_host(raw_server)
    ascii_username = _to_ascii_email(raw_username)
    sender_email = _to_ascii_email(raw_sender_email)
    ascii_to_email = _to_ascii_email(to_email)
    ascii_reply_to = _to_ascii_email(reply_to) if (reply_to and '@' in reply_to) else sender_email

    domain = sender_email.split('@')[-1] if '@' in sender_email else 'cyberhub.local'
    msg = MIMEMultipart('alternative')
    msg['Subject'] = subject
    msg['From'] = formataddr((sender_name, sender_email))
    msg['To'] = ascii_to_email
    msg['Date'] = formatdate(localtime=True)
    msg['Message-ID'] = make_msgid(domain=domain)
    msg['Reply-To'] = ascii_reply_to
    msg['X-Priority'] = '3'
    msg['X-Mailer'] = 'NOHU-CyberHub-Mailer/2.0'

    text_part = plain_body or _strip_html_to_text(html_body)
    msg.attach(MIMEText(text_part, 'plain', 'utf-8'))
    msg.attach(MIMEText(html_body, 'html', 'utf-8'))

    # Önce yapılandırılan portu dene (örn: Türkticaret.Net 587 STARTTLS veya 465 SSL), başarısız olursa alternatifi dene
    attempts = []
    if use_ssl or mail_port == 465:
        attempts.append(('ssl', mail_port))
        attempts.append(('tls', 587))
    else:
        attempts.append(('tls', mail_port))
        attempts.append(('ssl', 465))

    # Kullanıcı adı hem Punycode (iletisim@xn--nh-cyberhub-sfb8g.com.tr) hem de UTF-8 olarak denenebilir
    login_candidates = [ascii_username]
    if raw_username != ascii_username:
        login_candidates.append(raw_username)

    last_err = None
    for mode, port in attempts:
        for login_user in login_candidates:
            try:
                if mode == 'ssl':
                    with smtplib.SMTP_SSL(mail_server, port, timeout=8) as server:
                        server.ehlo()
                        server.login(login_user, mail_password)
                        server.sendmail(sender_email, [ascii_to_email], msg.as_string())
                        return True, "E-posta başarıyla gönderildi."
                else:
                    with smtplib.SMTP(mail_server, port, timeout=8) as server:
                        server.ehlo()
                        if use_tls:
                            server.starttls()
                            server.ehlo()
                        server.login(login_user, mail_password)
                        server.sendmail(sender_email, [ascii_to_email], msg.as_string())
                        return True, "E-posta başarıyla gönderildi."
            except Exception as err:
                last_err = err

    return False, str(last_err)


def send_via_brevo_api(api_key, to_email, username, subject, html_body):
    """
    Render Free Tier gibi harici SMTP portlarının (587/465) engellendiği bulut
    ortamlarında HTTPS Port 443 üzerinden Brevo (Sendinblue) REST API v3 ile e-posta gönderir.
    """
    url = "https://api.brevo.com/v3/smtp/email"
    raw_sender = (current_app.config.get('MAIL_DEFAULT_SENDER') or current_app.config.get('MAIL_USERNAME') or "iletisim@nöhü-cyberhub.com.tr").strip()
    sender_email = _to_ascii_email(raw_sender)
    sender_name = current_app.config.get('MAIL_SENDER_NAME', 'NÖHÜ Siber Güvenlik Lab').strip()
    headers = {
        "api-key": api_key,
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "NOHU-CyberHub/1.0"
    }
    payload = {
        "sender": {"name": sender_name, "email": sender_email},
        "to": [{"email": to_email, "name": username or to_email}],
        "subject": subject,
        "textContent": _strip_html_to_text(html_body),
        "htmlContent": html_body
    }
    try:
        req = urllib.request.Request(url, data=json.dumps(payload).encode('utf-8'), headers=headers, method='POST')
        with urllib.request.urlopen(req, timeout=10) as response:
            if response.getcode() in [200, 201]:
                print(f"[+] Brevo REST API üzerinden e-posta başarıyla iletildi: {to_email}")
                return True, "Doğrulama kodu başarıyla e-posta adresinize gönderildi."
            return False, f"Brevo API HTTP {response.getcode()}"
    except Exception as e:
        print(f"[!] Brevo API Hatası: {e}")
        return False, str(e)

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
                                        Bilgi Teknolojileri Güvenliği Bölümü &bull; Güvenlik Altyapısı
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

        # 1. Öncelik: Türkticaret.Net Kurumsal SMTP (iletisim@nöhü-cyberhub.com.tr - Port 587 STARTTLS / 465 SSL)
        sent, smtp_msg = _send_smtp_message(to_email, subject, html_body)
        if sent:
            print(f"[+] Siber temalı doğrulama kodu {to_email} adresine kurumsal SMTP ile iletildi.")
            return True, "Doğrulama kodu başarıyla e-posta adresinize gönderildi."

        # 2. Yedek: Brevo REST API (SMTP engelli bulut ortamları için)
        brevo_key = os.environ.get('BREVO_API_KEY') or current_app.config.get('BREVO_API_KEY')
        if brevo_key:
            sent, api_msg = send_via_brevo_api(brevo_key, to_email, username, subject, html_body)
            if sent:
                return True, api_msg

        # 3. Yedek: Resend REST API
        resend_key = os.environ.get('RESEND_API_KEY') or current_app.config.get('RESEND_API_KEY')
        if resend_key:
            sent, api_msg = send_via_resend_api(resend_key, to_email, subject, html_body)
            if sent:
                return True, api_msg

        print(f"[!] E-posta gönderme hatası: {smtp_msg}")
        return False, smtp_msg

    except Exception as e:
        error_msg = str(e)
        print(f"[!] E-posta gönderme hatası: {error_msg}")
        return False, error_msg

def send_password_reset_email(to_email, username, reset_code):
    """
    Kullanıcının şifresini unuttuğu veya yenilemek istediği durumlarda
    siber temalı HTML şifre sıfırlama kodu gönderir.
    """
    subject = f"🔐 NÖHÜ Siber Lab - Şifre Sıfırlama Kodunuz: {reset_code}"

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
                                <td style="background-color: #030712; padding: 26px 20px; text-align: center; border-bottom: 1px solid #1e293b; border-top: 3px solid #f59e0b;">
                                    <div style="font-size: 11px; font-family: 'Courier New', monospace; color: #fbbf24; letter-spacing: 2px; margin-bottom: 6px; text-transform: uppercase;">
                                        [ NÖHÜ SİBER GÜVENLİK LABORATUVARI ]
                                    </div>
                                    <h1 style="margin: 0; font-size: 18px; font-weight: 700; color: #ffffff; letter-spacing: 0.5px;">
                                        Hesap Şifresi Sıfırlama Talebi
                                    </h1>
                                    <p style="margin: 5px 0 0; font-size: 12px; color: #64748b;">
                                        Güvenlik Operasyonları &bull; Kimlik Doğrulama
                                    </p>
                                </td>
                            </tr>

                            <!-- Content -->
                            <tr>
                                <td style="padding: 32px 28px; background-color: #0f172a; text-align: center;">
                                    <p style="margin: 0 0 16px; font-size: 15px; color: #f1f5f9; text-align: left;">
                                        Merhaba <strong style="color: #fbbf24; font-family: 'Courier New', monospace;">{username}</strong>,
                                    </p>
                                    <p style="margin: 0 0 24px; font-size: 13px; color: #94a3b8; line-height: 1.6; text-align: left;">
                                        Hesabınız için şifre sıfırlama veya şifre güncelleme talebinde bulunuldu. Yeni şifrenizi tanımlamak için aşağıdaki 6 haneli tek kullanımlık güvenlik kodunu kullanabilirsiniz:
                                    </p>

                                    <!-- Cyber Terminal Code Box -->
                                    <div style="background-color: #030712; border: 2px dashed #d97706; border-radius: 8px; padding: 20px 15px; margin: 24px 0; text-align: center;">
                                        <div style="font-size: 10px; color: #64748b; font-family: 'Courier New', monospace; letter-spacing: 2px; margin-bottom: 8px;">
                                            // PASSWORD_RESET_TOKEN
                                        </div>
                                        <div style="font-size: 32px; font-weight: 800; letter-spacing: 8px; color: #fbbf24; font-family: 'Courier New', Consolas, monospace; display: inline-block;">
                                            {reset_code}
                                        </div>
                                        <div style="font-size: 11px; color: #38bdf8; font-family: 'Courier New', monospace; margin-top: 8px;">
                                            &bull; GEÇERLİLİK: 15 DAKİKA
                                        </div>
                                    </div>

                                    <!-- Security Notice -->
                                    <div style="background-color: #1a1015; border-left: 3px solid #f59e0b; border-radius: 4px; padding: 12px 14px; margin-top: 20px; text-align: left;">
                                        <div style="font-size: 11px; font-weight: 600; color: #fbbf24; margin-bottom: 2px;">
                                            ⚠️ Güvenlik Bilgilendirmesi
                                        </div>
                                        <div style="font-size: 11px; color: #cbd5e1; line-height: 1.4;">
                                            Bu talebi siz yapmadıysanız lütfen endişelenmeyiniz. Mevcut şifreniz siz yeni bir şifre tanımlayana kadar değişmeyecektir. Kodunuzu kimseyle paylaşmayınız.
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

        # 1. Öncelik: Türkticaret.Net Kurumsal SMTP (iletisim@nöhü-cyberhub.com.tr - Port 587 STARTTLS / 465 SSL)
        sent, smtp_msg = _send_smtp_message(to_email, subject, html_body)
        if sent:
            print(f"[+] Şifre sıfırlama kodu {to_email} adresine kurumsal SMTP ile iletildi.")
            return True, "Şifre sıfırlama kodu başarıyla e-posta adresinize gönderildi."

        # 2. Yedek: Brevo REST API
        brevo_key = os.environ.get('BREVO_API_KEY') or current_app.config.get('BREVO_API_KEY')
        if brevo_key:
            sent, api_msg = send_via_brevo_api(brevo_key, to_email, username, subject, html_body)
            if sent:
                return True, api_msg

        # 3. Yedek: Resend REST API
        resend_key = os.environ.get('RESEND_API_KEY') or current_app.config.get('RESEND_API_KEY')
        if resend_key:
            sent, api_msg = send_via_resend_api(resend_key, to_email, subject, html_body)
            if sent:
                return True, api_msg

        print(f"[!] Şifre sıfırlama e-posta hatası: {smtp_msg}")
        return False, smtp_msg

    except Exception as e:
        error_msg = str(e)
        print(f"[!] Şifre sıfırlama e-posta hatası: {error_msg}")
        return False, error_msg


def send_feedback_notification_email(
    sender_name,
    sender_email,
    category,
    rating,
    message,
    target_email='cyberhubsecurity.tr@gmail.com',
):
    """Send user feedback notification email to the site's contact mailbox."""
    safe_name = html.escape(sender_name or 'Ziyaretçi')
    safe_email = html.escape(sender_email or 'Belirtilmedi')
    safe_cat = html.escape(category or 'Genel')
    safe_msg = html.escape(message or '').replace('\n', '<br>')
    safe_rating = max(1, min(5, int(rating or 5)))
    stars_text = '★' * safe_rating + '☆' * (5 - safe_rating)
    subject = f"💬 NÖHÜ CyberHub Yeni Geri Bildirim [{category}] - {sender_name}"

    html_body = f"""
    <!DOCTYPE html>
    <html lang="tr">
    <head><meta charset="utf-8"></head>
    <body style="margin:0;padding:24px;background:#06090f;font-family:Arial,sans-serif;color:#e2e8f0;">
        <div style="max-width:560px;margin:0 auto;background:#0f172a;border:1px solid #1e293b;border-radius:12px;overflow:hidden;">
            <div style="background:#030712;padding:20px;border-bottom:1px solid #1e293b;border-top:3px solid #06b6d4;">
                <div style="font-size:11px;color:#22d3ee;font-family:monospace;letter-spacing:1.5px;">[ NÖHÜ CYBERHUB GERİ BİLDİRİM ]</div>
                <h2 style="margin:6px 0 0;color:#ffffff;font-size:18px;">Yeni Kullanıcı Geri Dönüşü</h2>
            </div>
            <div style="padding:22px;font-size:13px;line-height:1.6;">
                <p style="margin:0 0 8px;"><strong>Gönderen:</strong> {safe_name}</p>
                <p style="margin:0 0 8px;"><strong>Yanıt E-Postası:</strong> {safe_email}</p>
                <p style="margin:0 0 8px;"><strong>Kategori:</strong> {safe_cat}</p>
                <p style="margin:0 0 14px;"><strong>Değerlendirme:</strong> {stars_text} ({safe_rating}/5)</p>
                <div style="padding:14px;background:#030712;border:1px solid #334155;border-radius:8px;color:#cbd5e1;">
                    {safe_msg}
                </div>
            </div>
        </div>
    </body>
    </html>
    """

    try:
        # 1. Öncelik: Türkticaret.Net Kurumsal SMTP
        sent, smtp_msg = _send_smtp_message(
            target_email,
            subject,
            html_body,
            reply_to=sender_email if (sender_email and '@' in sender_email) else None
        )
        if sent:
            return True, "Geri bildirim e-postası gönderildi."

        # 2. Yedek: Brevo REST API
        brevo_key = os.environ.get('BREVO_API_KEY') or current_app.config.get('BREVO_API_KEY')
        if brevo_key:
            sent, api_msg = send_via_brevo_api(brevo_key, target_email, 'CyberHub Admin', subject, html_body)
            if sent:
                return True, api_msg

        # 3. Yedek: Resend REST API
        resend_key = os.environ.get('RESEND_API_KEY') or current_app.config.get('RESEND_API_KEY')
        if resend_key:
            sent, api_msg = send_via_resend_api(resend_key, target_email, subject, html_body)
            if sent:
                return True, api_msg

        return False, smtp_msg
    except Exception as e:
        return False, str(e)
