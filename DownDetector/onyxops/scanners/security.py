import asyncio
import hashlib
import re
import socket
from typing import List, Dict, Optional, Tuple
from urllib.parse import urlparse, urljoin
import aiohttp

from onyxops.core.models import SecurityFinding, PortScanFinding

COMMON_PORTS = {
    21: "FTP (File Transfer)",
    22: "SSH (Secure Shell)",
    23: "Telnet (Insecure)",
    25: "SMTP (Mail Server)",
    80: "HTTP Web Traffic",
    443: "HTTPS Web Traffic",
    1433: "MSSQL Database",
    3306: "MySQL Database",
    3389: "RDP (Remote Desktop)",
    5432: "PostgreSQL Database",
    6379: "Redis In-Memory Cache",
    8080: "HTTP Alternate / Proxy",
    8443: "HTTPS Alternate",
    9200: "Elasticsearch",
    27017: "MongoDB Database"
}

SECURITY_HEADERS = {
    "strict-transport-security": {
        "title": "Missing HTTP Strict Transport Security (HSTS)",
        "severity": "MEDIUM",
        "detail": "The server does not enforce HTTPS connections via HSTS header, leaving users open to SSL-stripping and MitM attacks.",
        "remediation": "Add 'Strict-Transport-Security: max-age=31536000; includeSubDomains; preload' to web server headers."
    },
    "content-security-policy": {
        "title": "Missing Content-Security-Policy (CSP)",
        "severity": "HIGH",
        "detail": "No CSP header detected. Browsers will execute any inline or injected external scripts, drastically increasing XSS impact.",
        "remediation": "Deploy a strict Content-Security-Policy header restricting trusted script-src, object-src, and default-src."
    },
    "x-frame-options": {
        "title": "Missing X-Frame-Options Header (Clickjacking Risk)",
        "severity": "MEDIUM",
        "detail": "Page lacks X-Frame-Options and frame-ancestors directive, allowing malicious sites to iframe the application and hijack clicks.",
        "remediation": "Add 'X-Frame-Options: DENY' or 'X-Frame-Options: SAMEORIGIN'."
    },
    "x-content-type-options": {
        "title": "Missing X-Content-Type-Options Header",
        "severity": "LOW",
        "detail": "MIME-type sniffing is enabled. Browsers might execute non-executable files (e.g. user-uploaded images) as executable scripts.",
        "remediation": "Add 'X-Content-Type-Options: nosniff' to web server headers."
    },
    "referrer-policy": {
        "title": "Missing Referrer-Policy Header",
        "severity": "LOW",
        "detail": "Default referrer policy may leak internal sensitive query strings, tokens, and URL paths to external third parties.",
        "remediation": "Set 'Referrer-Policy: strict-origin-when-cross-origin' or 'no-referrer'."
    },
    "permissions-policy": {
        "title": "Missing Permissions-Policy Header",
        "severity": "INFO",
        "detail": "Browser permissions (camera, microphone, geolocation) are not restricted by server policy.",
        "remediation": "Add 'Permissions-Policy: geolocation=(), microphone=(), camera=()'."
    }
}

PROBE_PATHS = [
    # Sensitive Environment & Source Code
    {"path": "/.env", "name": "Environment Variables (.env)", "severity": "CRITICAL"},
    {"path": "/.env.local", "name": "Local Environment File (.env.local)", "severity": "CRITICAL"},
    {"path": "/.env.production", "name": "Production Environment File", "severity": "CRITICAL"},
    {"path": "/.git/HEAD", "name": "Exposed Git Repository Root (/.git/HEAD)", "severity": "CRITICAL"},
    {"path": "/.git/config", "name": "Exposed Git Config (/.git/config)", "severity": "CRITICAL"},
    {"path": "/docker-compose.yml", "name": "Docker Compose Manifest", "severity": "HIGH"},
    {"path": "/Dockerfile", "name": "Dockerfile Source", "severity": "HIGH"},
    # Database Dumps & Backups
    {"path": "/backup.sql", "name": "Exposed Database Dump (.sql)", "severity": "CRITICAL"},
    {"path": "/dump.sql", "name": "Database Dump", "severity": "CRITICAL"},
    {"path": "/backup.zip", "name": "Website / Code Backup Archive (.zip)", "severity": "HIGH"},
    {"path": "/backup.tar.gz", "name": "Tarball Backup Archive", "severity": "HIGH"},
    {"path": "/db.sqlite", "name": "SQLite Database File", "severity": "CRITICAL"},
    {"path": "/db.sqlite3", "name": "SQLite3 Database File", "severity": "CRITICAL"},
    # CMS & Config
    {"path": "/wp-config.php.bak", "name": "WordPress Config Backup", "severity": "CRITICAL"},
    {"path": "/config.json", "name": "Application Config JSON", "severity": "HIGH"},
    {"path": "/config.php.bak", "name": "PHP Configuration Backup", "severity": "CRITICAL"},
    {"path": "/phpinfo.php", "name": "PHP Info Diagnostic Page", "severity": "HIGH"},
    # API Documentation & Debug
    {"path": "/swagger.json", "name": "Swagger / OpenAPI Specification", "severity": "MEDIUM"},
    {"path": "/openapi.json", "name": "OpenAPI Definition", "severity": "MEDIUM"},
    {"path": "/api/docs", "name": "API Documentation Portal", "severity": "LOW"},
    {"path": "/graphql", "name": "GraphQL Endpoint", "severity": "LOW"},
    {"path": "/actuator/health", "name": "Spring Boot Actuator Health", "severity": "MEDIUM"},
    {"path": "/actuator/env", "name": "Spring Boot Actuator Environment", "severity": "CRITICAL"},
    {"path": "/elmah.axd", "name": "ASP.NET ELMAH Error Log", "severity": "HIGH"},
    {"path": "/server-status", "name": "Apache Server Status", "severity": "MEDIUM"}
]

class SecurityScanner:
    """Advanced security, vulnerability, configuration, and exploit analyzer."""

    def __init__(self, timeout_seconds: int = 6):
        self.timeout = aiohttp.ClientTimeout(total=timeout_seconds)

    async def audit_headers(self, headers: Dict[str, str]) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        norm = {k.lower(): v for k, v in headers.items()}

        # 1. Missing Security Headers
        for h_key, meta in SECURITY_HEADERS.items():
            if h_key not in norm:
                findings.append(SecurityFinding(
                    severity=meta["severity"],
                    category="Missing Security Header",
                    title=meta["title"],
                    detail=meta["detail"],
                    remediation=meta["remediation"]
                ))

        # 2. Server Software & Technology Disclosure
        server_val = norm.get("server")
        if server_val and any(char.isdigit() for char in server_val):
            findings.append(SecurityFinding(
                severity="LOW",
                category="Information Disclosure",
                title=f"Server Version Disclosed: '{server_val}'",
                detail=f"The 'Server' header exposes detailed software versions: '{server_val}'. Attackers use this to identify known CVEs.",
                remediation="Configure web server to suppress granular version information (e.g. 'ServerTokens Prod' or 'server_tokens off;')."
            ))

        x_powered = norm.get("x-powered-by")
        if x_powered:
            findings.append(SecurityFinding(
                severity="LOW",
                category="Information Disclosure",
                title=f"X-Powered-By Header Disclosed: '{x_powered}'",
                detail=f"Server exposes technology stack: '{x_powered}'.",
                remediation="Disable 'X-Powered-By' in your backend framework configuration."
            ))

        # 3. Weak / Insecure Cookies Audit
        set_cookie = norm.get("set-cookie")
        if set_cookie:
            cookies = [c.strip() for c in set_cookie.split(",")]
            for cookie in cookies:
                cookie_lower = cookie.lower()
                c_name = cookie.split("=")[0].strip() if "=" in cookie else "Cookie"
                if "httponly" not in cookie_lower:
                    findings.append(SecurityFinding(
                        severity="MEDIUM",
                        category="Insecure Cookie Configuration",
                        title=f"Cookie '{c_name}' Missing HttpOnly Flag",
                        detail=f"Cookie '{c_name}' lacks the HttpOnly attribute, allowing JavaScript to read session cookies during XSS.",
                        remediation=f"Set 'HttpOnly; Secure; SameSite=Lax' on cookie '{c_name}'."
                    ))
                if "secure" not in cookie_lower:
                    findings.append(SecurityFinding(
                        severity="MEDIUM",
                        category="Insecure Cookie Configuration",
                        title=f"Cookie '{c_name}' Missing Secure Flag",
                        detail=f"Cookie '{c_name}' lacks the Secure flag, allowing transmission over unencrypted HTTP.",
                        remediation=f"Enable the 'Secure' flag on cookie '{c_name}'."
                    ))

        return findings

    async def test_cors_misconfiguration(self, base_url: str) -> List[SecurityFinding]:
        """Tests whether the API/Web server reflects arbitrary origins or allows credential theft."""
        findings = []
        test_origin = "https://evil-attacker-site.com"
        headers = {
            "Origin": test_origin,
            "User-Agent": "OnyxOps-Sentinel/1.0"
        }
        connector = aiohttp.TCPConnector(ssl=False)
        try:
            async with aiohttp.ClientSession(timeout=self.timeout, connector=connector) as session:
                async with session.get(base_url, headers=headers, allow_redirects=False) as resp:
                    resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                    allow_origin = resp_headers.get("access-control-allow-origin", "")
                    allow_creds = resp_headers.get("access-control-allow-credentials", "").lower()

                    if allow_origin == test_origin:
                        severity = "CRITICAL" if allow_creds == "true" else "HIGH"
                        findings.append(SecurityFinding(
                            severity=severity,
                            category="CORS Misconfiguration",
                            title="Arbitrary Origin Reflection in CORS",
                            detail=f"Server reflected untrusted origin '{test_origin}' in Access-Control-Allow-Origin (Credentials allowed: {allow_creds}). This enables cross-origin data theft.",
                            remediation="Implement an explicit whitelist of trusted domains for Access-Control-Allow-Origin. Do not reflect the request Origin header blindly."
                        ))
                    elif allow_origin == "*" and allow_creds == "true":
                        findings.append(SecurityFinding(
                            severity="HIGH",
                            category="CORS Misconfiguration",
                            title="Wildcard CORS with Credentials Enabled",
                            detail="Access-Control-Allow-Origin is set to '*' alongside Access-Control-Allow-Credentials: true.",
                            remediation="Do not use wildcard '*' when credentials are required."
                        ))
        except Exception:
            pass
        return findings

    async def test_http_methods(self, base_url: str) -> List[SecurityFinding]:
        """Tests for dangerous or unnecessary HTTP methods (PUT, DELETE, TRACE, OPTIONS)."""
        findings = []
        connector = aiohttp.TCPConnector(ssl=False)
        try:
            async with aiohttp.ClientSession(timeout=self.timeout, connector=connector) as session:
                # Test TRACE (Cross-Site Tracing / XST vulnerability)
                try:
                    async with session.request("TRACE", base_url, headers={"User-Agent": "OnyxOps-Sentinel/1.0"}) as resp:
                        if resp.status == 200:
                            body = await resp.text()
                            if "TRACE" in body:
                                findings.append(SecurityFinding(
                                    severity="HIGH",
                                    category="Dangerous HTTP Method",
                                    title="HTTP TRACE Method Enabled (XST Vulnerability)",
                                    detail="The web server permits the HTTP TRACE method, reflecting requests back to clients. This allows Cross-Site Tracing (XST) attacks to bypass HttpOnly cookies.",
                                    remediation="Disable HTTP TRACE/TRACK methods in web server configuration (e.g. 'TraceEnable Off' in Apache)."
                                ))
                except Exception:
                    pass

                # Check OPTIONS Allow header
                try:
                    async with session.options(base_url, headers={"User-Agent": "OnyxOps-Sentinel/1.0"}) as resp:
                        allow = resp.headers.get("Allow", "")
                        for dangerous_method in ["PUT", "DELETE", "DEBUG"]:
                            if dangerous_method in allow.upper():
                                findings.append(SecurityFinding(
                                    severity="MEDIUM",
                                    category="Dangerous HTTP Method",
                                    title=f"HTTP {dangerous_method} Method Exposed in Allow Header",
                                    detail=f"The server advertises support for '{dangerous_method}' on the public web root: '{allow}'.",
                                    remediation=f"Restrict '{dangerous_method}' methods to authenticated API endpoints only."
                                ))
                except Exception:
                    pass
        except Exception:
            pass
        return findings

    async def probe_sensitive_paths(self, base_url: str) -> List[SecurityFinding]:
        """
        Intelligently probes for sensitive files and directories.
        Includes Single Page Application (SPA) false-positive filtering by comparing responses
        against a baseline non-existent route fingerprint.
        """
        findings: List[SecurityFinding] = []
        connector = aiohttp.TCPConnector(ssl=False)
        headers = {"User-Agent": "OnyxOps-Sentinel/1.0 (+https://wolfeguard.internal/security)"}

        async with aiohttp.ClientSession(timeout=self.timeout, connector=connector) as session:
            # 1. Establish baseline 404 behavior for SPA fingerprinting
            baseline_url = urljoin(base_url, "/non_existent_check_onyxops_987654321")
            baseline_status = 404
            baseline_len = 0
            baseline_hash = ""
            try:
                async with session.get(baseline_url, headers=headers, allow_redirects=True) as b_resp:
                    baseline_status = b_resp.status
                    b_content = await b_resp.read()
                    baseline_len = len(b_content)
                    baseline_hash = hashlib.md5(b_content).hexdigest()
            except Exception:
                pass

            # 2. Probe all sensitive paths concurrently
            tasks = [self._probe_single(session, base_url, p, headers, baseline_status, baseline_len, baseline_hash) for p in PROBE_PATHS]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for res in results:
                if isinstance(res, SecurityFinding):
                    findings.append(res)

        return findings

    async def _probe_single(self, session: aiohttp.ClientSession, base_url: str, probe: Dict[str, str],
                            headers: Dict[str, str], b_status: int, b_len: int, b_hash: str) -> Optional[SecurityFinding]:
        path = probe["path"]
        target_url = urljoin(base_url, path)
        try:
            async with session.get(target_url, headers=headers, allow_redirects=False) as resp:
                if resp.status == 200:
                    content_bytes = await resp.read()
                    content_len = len(content_bytes)
                    content_hash = hashlib.md5(content_bytes).hexdigest()

                    # False positive elimination (SPA catch-all returning same HTML for everything)
                    if b_status == 200:
                        if content_hash == b_hash or abs(content_len - b_len) < 50:
                            return None # SPA false-positive: catch-all 200 route

                    content_peek = content_bytes[:300].decode("utf-8", errors="ignore")

                    # Verify actual file characteristics
                    if path.endswith((".env", ".env.local", ".env.production")):
                        if not ("=" in content_peek and not "<!doctype" in content_peek.lower()):
                            return None # Not a true .env file
                    elif path.endswith("/.git/HEAD"):
                        if not ("ref: refs/" in content_peek or len(content_peek.strip()) == 40):
                            return None # Not a true git repo
                    elif path.endswith(".sql"):
                        if not ("create" in content_peek.lower() or "insert" in content_peek.lower()):
                            return None
                    elif path.endswith(".zip") or path.endswith(".tar.gz") or path.endswith(".sqlite"):
                        # Binary files should not have HTML tags
                        if "<html" in content_peek.lower() or "<!doctype" in content_peek.lower():
                            return None

                    return SecurityFinding(
                        severity=probe["severity"],
                        category="Exposed Sensitive Asset",
                        title=f"Exposed Asset Discovered: {probe['name']}",
                        detail=f"Resource '{target_url}' is publicly accessible (HTTP 200 OK, {content_len} bytes). Sample: {content_peek[:60]}...",
                        remediation=f"Block public access to '{path}' immediately in web server configuration or remove from document root."
                    )
        except Exception:
            return None
        return None

    async def scan_open_ports(self, hostname: str, ports: List[int] = None) -> List[PortScanFinding]:
        if not ports:
            ports = list(COMMON_PORTS.keys())
        tasks = [self._check_port(hostname, port) for port in ports]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        findings = [r for r in results if isinstance(r, PortScanFinding) and r.state == "open"]
        return findings

    async def _check_port(self, hostname: str, port: int) -> PortScanFinding:
        service_name = COMMON_PORTS.get(port, "Custom Service")
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(hostname, port),
                timeout=1.5
            )
            writer.close()
            await writer.wait_closed()
            return PortScanFinding(port=port, service=service_name, state="open")
        except Exception:
            return PortScanFinding(port=port, service=service_name, state="closed")
