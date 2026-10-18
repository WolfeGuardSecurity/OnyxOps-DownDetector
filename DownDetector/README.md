# 🛡️ OnyxOps Sentinel
### Automated Down Detector, Exploit Diagnostic & 24/7 Threat Intelligence Bot
**Created for:** OnyxOps by WolfeGuard  
**Lead Developer:** `sinfulldesirez` (Discord)  
**Version:** 1.0.0

---

## 📌 Overview

**OnyxOps Sentinel** is a full-featured incident detection, continuous uptime monitoring, and deep vulnerability diagnostic system. When your sites experience outages, performance drops, or attacks, Sentinel does not merely detect that the service is down: it runs an immediate **Deep Diagnostic Scan** to identify the root cause, determine if the failure is at the Cloudflare edge or origin server, probe for exposed secrets/files, audit OWASP security headers, check for CORS misconfigurations, detect in-browser malware/crypto-miners, and dispatch alerts via Phone (SMS), Email, and Discord.

---

## 🕹️ Interactive Feature Menu

You don't need to remember different CLI commands! Running `run.bat` or `python main.py` opens the interactive console menu:

```
  ___  _  _ __   ____  _____  ___  ___   ____ ___ _  _ _____ ___ _  _ ____ _    
 / _ \| \| |\ \ / /\ \/ / _ \| _ \/ __| / ___| __| \| |_   _|_ _| \| | __| |   
| (_) | .` | \ V /  >  < (_) |  _/\__ \ \___ \ _|| .` | | |  | || .` | _|| |__ 
 \___/|_|\_|  |_|  /_/\_\___/|_|  |___/ |____/___|_|\_| |_| |___|_|\_|___|____|

  Automated Down Detection, Exploit Diagnostics & Threat Intelligence
  Organization: WolfeGuard / OnyxOps | Lead Developer: sinfulldesirez | v1.0.0

Choose an operation mode:

 [1] 🟢 24/7 Live Website Monitor (Continuous uptime & automated alert engine)
 [2] 🔍 Deep Exploit & Vulnerability Audit (CORS, Headers, Methods, Secrets)
 [3] ☁️ Cloudflare & Edge Diagnostics (52x errors, Ray ID, WAF rules)
 [4] 🔌 Port & Infrastructure Scanner (Database, SSH, Admin services)
 [5] 🦠 Web Integrity & Malware Scan (Crypto-miners, Defacement, Injected scripts)
 [6] 🎯 Target Manager (Add, list, or remove monitored websites)
 [7] 🔔 Test Alert Dispatchers (SMS, Email, Discord)
 [8] 📑 View Archived Incident Reports
 [0] 🚪 Exit
```

---

## ⚡ Deepened Scanners & Diagnostic Capabilities

### 1. 🟢 24/7 Live Continuous Website Monitor
- **Real-Time Terminal Dashboard:** Live updating status table with HTTP codes, latency (ms), SSL certificate days remaining, uptime %, and root-cause diagnosis.
- **Immediate Incident Trigger:** Automatically triggers the full Deep Exploit Scan the instant a site drops or degrades.
- **Multi-Channel Dispatch:** Dispatches SMS, Email, and Discord alerts upon failure and recovery.

### 2. 🔍 Deep Vulnerability & Exploit Reconnaissance
- **CORS Misconfiguration:** Tests for arbitrary origin reflection and wildcard credentials.
- **Dangerous HTTP Methods:** Probes for `TRACE` (Cross-Site Tracing / XST vulnerability) and exposed `PUT`/`DELETE` methods.
- **Insecure Cookies:** Audits every cookie for missing `HttpOnly` and `Secure` attributes.
- **SPA-Aware Asset Probing:** Uses intelligent baseline 404 hashing to distinguish real exposed files from Single Page Application (SPA) catch-all routes. Probes for:
  - `/.env`, `/.env.local`, `/.env.production`
  - `/.git/HEAD`, `/.git/config`
  - Database dumps (`.sql`, `.sqlite`, `.sqlite3`)
  - Backups (`.zip`, `.tar.gz`, `wp-config.php.bak`)
  - Admin/Debug endpoints (`/actuator/env`, `/elmah.axd`, `/phpinfo.php`, `/swagger.json`)
- **OWASP Security Headers:** Audits `Strict-Transport-Security` (HSTS), `Content-Security-Policy` (CSP), `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, and `Permissions-Policy`.

### 3. ☁️ Cloudflare Edge vs Origin Root-Cause Analyzer
- **52x Error Translation:** Decodes Cloudflare status codes (520, 521, 522, 523, 524, 525, 526, 530).
- **Origin IP Leak Detection:** Cross-references resolved IP addresses against Cloudflare's official IPv4 networks to warn if an origin IP is exposed, allowing attackers to bypass Cloudflare DDoS/WAF protection.
- **Edge Metadata:** Captures Cloudflare Ray ID, cache status (HIT/MISS/DYNAMIC), and WAF challenge blocks.

### 4. 🦠 Web Integrity, Intrusion & Malware Detector
- Scans rendered HTML for embedded cryptocurrency miners (CoinHive, CryptoLoot, WebMinePool).
- Detects obfuscated JavaScript droppers (`eval(atob(...))`, `eval(unescape(...))`).
- Detects hidden zero-pixel `<iframe>` injections used in clickjacking and drive-by downloads.
- Flags website defacement signatures.

### 5. 📢 Multi-Channel Alerting
- **SMS / Phone Alerts:** Twilio REST API integration & custom webhooks.
- **Email:** SMTP with TLS, sending structured HTML incident briefings.
- **Discord:** Rich colored embeds (Red for Down/Threat, Green for Recovery, Orange for Warning).

---

## 🚀 Quick Launch

### Run the Interactive Menu:
Simply double-click or run:
```cmd
run.bat
```
Or with Python:
```cmd
python main.py
```

### Direct CLI Shortcuts:
- **Scan a specific URL:**
  ```cmd
  python main.py scan https://admin.onyxops.org/products
  ```
- **Start the 24/7 Monitor directly:**
  ```cmd
  python main.py run
  ```
- **Test Alert Channels:**
  ```cmd
  python main.py test-alerts
  ```

---
*OnyxOps by WolfeGuard • Lead Dev: sinfulldesirez*
