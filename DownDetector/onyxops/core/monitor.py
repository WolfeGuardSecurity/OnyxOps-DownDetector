import asyncio
import logging
from datetime import datetime, timezone
from urllib.parse import urlparse
from typing import Dict, List, Any, Callable, Optional

from onyxops.core.models import (
    TargetSite, UptimeResult, DeepScanReport, SecurityFinding
)
from onyxops.scanners.uptime import UptimeScanner
from onyxops.scanners.cloudflare import CloudflareScanner
from onyxops.scanners.security import SecurityScanner
from onyxops.scanners.integrity import IntegrityScanner
from onyxops.notifiers.sms import SMSNotifier
from onyxops.notifiers.email import EmailNotifier
from onyxops.notifiers.discord import DiscordNotifier
from onyxops.reporting.incident_report import IncidentReporter

logger = logging.getLogger("OnyxOps.Monitor")

class SentinelMonitor:
    """Core asynchronous monitoring engine for OnyxOps."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.system_cfg = config.get("system", {})
        self.interval = self.system_cfg.get("check_interval_seconds", 60)
        self.timeout = self.system_cfg.get("timeout_seconds", 15)

        # Scanners
        self.uptime_scanner = UptimeScanner(timeout_seconds=self.timeout)
        self.cf_scanner = CloudflareScanner()
        self.security_scanner = SecurityScanner(timeout_seconds=6)
        self.integrity_scanner = IntegrityScanner()
        self.reporter = IncidentReporter()

        # Notifiers
        notif_cfg = config.get("notifications", {})
        self.notifiers = []
        if notif_cfg.get("enabled", True):
            if notif_cfg.get("sms", {}).get("enabled", False):
                self.notifiers.append(SMSNotifier(notif_cfg.get("sms", {})))
            if notif_cfg.get("email", {}).get("enabled", False):
                self.notifiers.append(EmailNotifier(notif_cfg.get("email", {})))
            if notif_cfg.get("discord", {}).get("enabled", False):
                self.notifiers.append(DiscordNotifier(notif_cfg.get("discord", {})))

        # Target states: target_id -> dict telemetry
        self.state: Dict[str, Dict[str, Any]] = {}
        self.targets: List[TargetSite] = []
        for t in config.get("targets", []):
            target_obj = TargetSite(
                id=t.get("id"),
                name=t.get("name"),
                url=t.get("url"),
                check_ssl=t.get("check_ssl", True),
                ssl_expiry_warning_days=t.get("ssl_expiry_warning_days", 14),
                deep_scan_on_failure=t.get("deep_scan_on_failure", True),
                periodic_security_scan_hours=t.get("periodic_security_scan_hours", 12),
                expected_status_codes=t.get("expected_status_codes", [200, 301, 302]),
                expected_content_keywords=t.get("expected_content_keywords", []),
                headers=t.get("headers", {})
            )
            self.targets.append(target_obj)
            self._init_target_state(target_obj)

        self.is_running = False
        self.on_check_complete: Optional[Callable[[TargetSite, UptimeResult], None]] = None

    def _init_target_state(self, target: TargetSite):
        self.state[target.id] = {
            "name": target.name,
            "url": target.url,
            "is_up": True,
            "consecutive_failures": 0,
            "last_status": 200,
            "last_latency": 0.0,
            "ssl_days": None,
            "total_checks": 0,
            "total_success": 0,
            "uptime_pct": 100.0,
            "last_check": None,
            "last_error": None
        }

    def add_target(self, target: TargetSite):
        # Remove if existing
        self.targets = [t for t in self.targets if t.id != target.id]
        self.targets.append(target)
        self._init_target_state(target)

    def remove_target(self, target_id: str):
        self.targets = [t for t in self.targets if t.id != target_id]
        self.state.pop(target_id, None)

    async def run_deep_scan(self, target: TargetSite, uptime_res: UptimeResult, body_sample: str, headers: Dict[str, str]) -> DeepScanReport:
        logger.warning(f"Initiating Deep Diagnostic & Exploit Scan for {target.name} ({target.url})...")
        parsed = urlparse(target.url)
        hostname = parsed.hostname or target.url

        security_findings: List[SecurityFinding] = []

        # 1. Cloudflare Analysis & Origin Leak Check
        cf_report, cf_findings = self.cf_scanner.analyze(uptime_res.status_code, headers, body_sample, uptime_res.dns_resolved_ips)
        security_findings.extend(cf_findings)

        # 2. Port Scanning
        deep_cfg = self.config.get("deep_scan", {})
        port_cfg = deep_cfg.get("port_scan", {})
        open_ports = []
        if port_cfg.get("enabled", True):
            ports_to_check = port_cfg.get("ports", [80, 443, 21, 22, 3306, 5432, 6379, 8080, 8443])
            open_ports = await self.security_scanner.scan_open_ports(hostname, ports_to_check)

        # 3. Security Headers Audit
        sec_cfg = deep_cfg.get("security_audit", {})
        if sec_cfg.get("check_missing_security_headers", True) and headers:
            sec_headers = await self.security_scanner.audit_headers(headers)
            security_findings.extend(sec_headers)

        # 4. CORS Misconfiguration Audit
        cors_findings = await self.security_scanner.test_cors_misconfiguration(target.url)
        security_findings.extend(cors_findings)

        # 5. Dangerous HTTP Methods Audit (TRACE, PUT, DELETE)
        method_findings = await self.security_scanner.test_http_methods(target.url)
        security_findings.extend(method_findings)

        # 6. Exposed Sensitive Files & Secrets (with SPA false-positive filter)
        if sec_cfg.get("check_exposed_files", True):
            exposed = await self.security_scanner.probe_sensitive_paths(target.url)
            security_findings.extend(exposed)

        # 7. Integrity, Injected Scripts, Malware
        if sec_cfg.get("detect_malicious_scripts", True) and body_sample:
            integrity_hits = self.integrity_scanner.inspect(body_sample)
            security_findings.extend(integrity_hits)

        # 8. Synthesize Root Cause
        root_cause = self._diagnose_root_cause(uptime_res, cf_report)

        report = DeepScanReport(
            target_id=target.id,
            target_name=target.name,
            url=target.url,
            timestamp=datetime.now(timezone.utc),
            uptime=uptime_res,
            cloudflare=cf_report,
            open_ports=open_ports,
            security_findings=security_findings,
            root_cause_summary=root_cause
        )

        # Save forensic report
        self.reporter.save_report(report)
        return report

    def _diagnose_root_cause(self, uptime: UptimeResult, cf: Any) -> str:
        if not uptime.dns_resolved_ips:
            return "DNS Resolution Failed (Domain name does not resolve to an IP address)."
        
        if uptime.ssl_info and not uptime.ssl_info.valid:
            return f"SSL/TLS Certificate Error: {uptime.ssl_info.error_message}"

        if cf.is_cloudflare and cf.cf_error_code:
            return f"Cloudflare Edge Error ({cf.cf_error_meaning}). Origin server is unreachable or misconfigured."

        if uptime.status_code == 500:
            return "Internal Server Error (500) - Unhandled backend exception or database query crash."
        elif uptime.status_code == 502:
            return "Bad Gateway (502) - Reverse proxy (NGINX/Caddy/Apache) cannot reach internal application service."
        elif uptime.status_code == 503:
            return "Service Unavailable (503) - Server overloaded or undergoing maintenance."
        elif uptime.status_code == 504:
            return "Gateway Timeout (504) - Upstream application server timed out processing request."
        elif uptime.status_code == 404:
            return "Resource Not Found (404) - Target path or routing configuration is missing."
        elif uptime.status_code == 403:
            return "Access Forbidden (403) - Permissions or firewall blocked the request."
        elif uptime.status_code is None:
            return f"Network/Connection Timeout or Refusal: {uptime.error_message}"
        
        return uptime.error_message or "General service degradation detected."

    async def check_single_target(self, target: TargetSite) -> UptimeResult:
        state = self.state[target.id]
        uptime_res, body_sample, headers = await self.uptime_scanner.check_target(target)
        state["last_check"] = datetime.now(timezone.utc)
        state["last_status"] = uptime_res.status_code
        state["last_latency"] = uptime_res.response_time_ms
        state["total_checks"] += 1
        if uptime_res.ssl_info:
            state["ssl_days"] = uptime_res.ssl_info.days_until_expiry

        if not uptime_res.is_up:
            state["consecutive_failures"] += 1
            state["last_error"] = uptime_res.error_message
            logger.error(f"[DOWN] {target.name} ({target.url}) failed: {uptime_res.error_message}")

            if target.deep_scan_on_failure:
                deep_report = await self.run_deep_scan(target, uptime_res, body_sample, headers)
                if state["is_up"]:
                    state["is_up"] = False
                    for notifier in self.notifiers:
                        asyncio.create_task(notifier.send_down_alert(deep_report))
        else:
            state["total_success"] += 1
            if not state["is_up"]:
                logger.info(f"[RECOVERED] {target.name} is back online!")
                state["is_up"] = True
                state["consecutive_failures"] = 0
                state["last_error"] = None
                for notifier in self.notifiers:
                    asyncio.create_task(notifier.send_recovery_alert(uptime_res, target.name))
            else:
                state["consecutive_failures"] = 0
                state["last_error"] = None

        state["uptime_pct"] = round((state["total_success"] / state["total_checks"]) * 100, 2)

        if self.on_check_complete:
            self.on_check_complete(target, uptime_res)

        return uptime_res

    async def start(self):
        self.is_running = True
        logger.info(f"OnyxOps Sentinel starting with {len(self.targets)} targets. Polling interval: {self.interval}s.")
        while self.is_running:
            tasks = [self.check_single_target(target) for target in self.targets]
            await asyncio.gather(*tasks, return_exceptions=True)
            await asyncio.sleep(self.interval)

    def stop(self):
        self.is_running = False
