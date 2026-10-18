@echo off
title CyberGuard AI — Unified Cyber Defense Platform (Port 5050)
echo ==============================================================
echo        CYBERGUARD AI — Unified Cyber Defense Platform
echo          "One AI Brain. Multiple Specialized Defenses."
echo ==============================================================
echo.
echo Initializing defense engines:
echo  [+] PhishShield (URL & Social Engineering Analyzer)
echo  [+] UPI Shield (Digital Payment & Reverse PIN Trap)
echo  [+] NetSentinel (C2 Beaconing & DNS Tunneling Profiler)
echo  [+] Risk Engine (Cross-Threat Correlation & Policy Enforcer)
echo.
echo Launching server on http://127.0.0.1:5050 ...
echo.

cd /d "%~dp0"
..\venv\Scripts\python app.py

pause
