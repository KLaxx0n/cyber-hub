@echo off
title Cyber Hub - Global Yayini
echo ========================================================
echo   CYBER HUB - KURESEL (GLOBAL) CANLI YAYIN BASLATICI
echo ========================================================
echo.

:: 1. Flask uygulamasini arka planda baslat
echo [*] Flask web sunucusu calistiriliyor...
start "Cyber Hub Backend" /min python app.py

:: 2. Sunucunun ayaga kalkmasi icin 3 saniye bekle
timeout /t 3 /nobreak >nul

:: 3. Cloudflare Tunnel ile internete ac
echo [*] Cloudflare Global Tunel kuruluyor...
echo [*] Asagidaki ciktida 'trycloudflare.com' adresinizi goreceksiniz:
echo.
"%TEMP%\cloudflared.exe" tunnel --url http://127.0.0.1:5000
pause
