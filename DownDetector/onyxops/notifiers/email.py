import asyncio
import logging
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Dict, Any, List

from onyxops.notifiers.base import BaseNotifier
from onyxops.core.models import DeepScanReport, UptimeResult

logger = logging.getLogger("OnyxOps.Email")

class EmailNotifier(BaseNotifier):
    """Dispatches comprehensive HTML & plaintext incident reports via SMTP."""

    def __init__(self, config: Dict[str, Any]):
        self.enabled = config.get("enabled", False)
        self.smtp_host = config.get("smtp_host", "smtp.gmail.com")
        self.smtp_port = config.get("smtp_port", 587)
        self.use_tls = config.get("use_tls", True)
        self.username = config.get("username", "")
        self.password = config.get("password", "")
        self.from_address = config.get("from_address", "OnyxOps Sentinel <alerts@onyxops.internal>")
        self.to_addresses: List[str] = config.get("to_addresses", [])

    def _send_sync_email(self, subject: str, text_body: str, html_body: str) -> bool:
        if not (self.username and self.password and self.to_addresses):
            logger.error("Email credentials or recipients not configured.")
            return False

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = self.from_address
        msg["To"] = ", ".join(self.to_addresses)

        msg.attach(MIMEText(text_body, "plain"))
        msg.attach(MIMEText(html_body, "html"))

        try:
            with smtplib.SMTP(self.smtp_host, self.smtp_port, timeout=10) as server:
                if self.use_tls:
                    server.starttls()
                server.login(self.username, self.password)
                server.sendmail(self.from_address, self.to_addresses, msg.as_string())
            logger.info("Incident notification email successfully dispatched.")
            return True
        except Exception as e:
            logger.error(f"Failed to dispatch email: {e}")
            return False

    async def _dispatch_async(self, subject: str, text_body: str, html_body: str) -> bool:
        if not self.enabled:
            return False
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, self._send_sync_email, subject, text_body, html_body)

    async def send_down_alert(self, report: DeepScanReport) -> bool:
        subject = f"[DOWN DETECTED] {report.target_name} is UNREACHABLE"
        
        # Build HTML table of security findings if any
        findings_html = ""
        for f in report.security_findings:
            color = "#ff4444" if f.severity in ("CRITICAL", "HIGH") else "#ffbb33"
            findings_html += f"""
            <tr>
                <td style="padding: 8px; border: 1px solid #333;"><span style="color: {color}; font-weight: bold;">{f.severity}</span></td>
                <td style="padding: 8px; border: 1px solid #333;">{f.title}</td>
                <td style="padding: 8px; border: 1px solid #333;">{f.detail}</td>
            </tr>
            """

        ports_str = ", ".join([f"{p.port} ({p.service})" for p in report.open_ports]) or "No atypical open ports detected"

        html_body = f"""
        <!DOCTYPE html>
        <html>
        <body style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; background-color: #0f141c; color: #e1e7ec; padding: 20px;">
            <div style="max-width: 650px; margin: 0 auto; background: #18202c; border: 1px solid #283548; border-radius: 8px; padding: 25px;">
                <div style="border-bottom: 2px solid #e53935; padding-bottom: 15px; margin-bottom: 20px;">
                    <h2 style="color: #e53935; margin: 0;">OnyxOps Sentinel Incident Alert</h2>
                    <p style="color: #8da2b5; margin: 5px 0 0 0;">Automated Root-Cause Diagnostic & Uptime Monitor</p>
                </div>

                <div style="background: #232c3d; border-left: 4px solid #e53935; padding: 12px; margin-bottom: 20px;">
                    <strong>Target:</strong> {report.target_name} (<a href="{report.url}" style="color: #4da3ff;">{report.url}</a>)<br>
                    <strong>Timestamp:</strong> {report.timestamp.isoformat()}<br>
                    <strong>Status Code:</strong> {report.uptime.status_code or 'NO RESPONSE'}<br>
                    <strong>Diagnosis:</strong> {report.root_cause_summary}
                </div>

                <h3 style="color: #4da3ff; margin-top: 20px;">Cloudflare Deep Scan</h3>
                <ul style="color: #c9d6df;">
                    <li><strong>Cloudflare Detected:</strong> {'Yes' if report.cloudflare.is_cloudflare else 'No'}</li>
                    <li><strong>Edge Ray ID:</strong> {report.cloudflare.cf_ray or 'N/A'}</li>
                    <li><strong>Edge vs Origin Status:</strong> {report.cloudflare.origin_vs_edge}</li>
                    <li><strong>Diagnosis Note:</strong> {report.cloudflare.cf_error_meaning or 'No specific CF error'}</li>
                </ul>

                <h3 style="color: #4da3ff; margin-top: 20px;">Network & Ports</h3>
                <p style="color: #c9d6df;"><strong>Open Detected Ports:</strong> {ports_str}</p>
                <p style="color: #c9d6df;"><strong>Resolved IPs:</strong> {', '.join(report.uptime.dns_resolved_ips) or 'DNS Resolution Failed'}</p>

                {f'''
                <h3 style="color: #ffaa00; margin-top: 20px;">Security & Vulnerability Findings</h3>
                <table style="width: 100%; border-collapse: collapse; font-size: 13px;">
                    <tr style="background: #243042; text-align: left;">
                        <th style="padding: 8px; border: 1px solid #333;">Severity</th>
                        <th style="padding: 8px; border: 1px solid #333;">Vulnerability</th>
                        <th style="padding: 8px; border: 1px solid #333;">Details</th>
                    </tr>
                    {findings_html}
                </table>
                ''' if findings_html else ''}

                <div style="margin-top: 30px; font-size: 11px; color: #5a7184; border-top: 1px solid #283548; padding-top: 15px;">
                    OnyxOps Sentinel Security Bot • Developed by sinfulldesirez for WolfeGuard
                </div>
            </div>
        </body>
        </html>
        """

        text_body = (
            f"OnyxOps Incident Report\n"
            f"Target: {report.target_name} ({report.url})\n"
            f"Status: {report.uptime.status_code}\n"
            f"Root Cause: {report.root_cause_summary}\n"
            f"Cloudflare Edge: {report.cloudflare.origin_vs_edge}\n"
            f"Resolved IPs: {', '.join(report.uptime.dns_resolved_ips)}\n"
        )

        return await self._dispatch_async(subject, text_body, html_body)

    async def send_recovery_alert(self, result: UptimeResult, site_name: str) -> bool:
        subject = f"[RECOVERED] {site_name} is BACK ONLINE"
        text_body = f"The service {site_name} ({result.url}) has recovered. Response time: {result.response_time_ms}ms"
        html_body = f"""
        <html>
        <body style="font-family: sans-serif; background-color: #0f141c; color: #e1e7ec; padding: 20px;">
            <div style="max-width: 500px; margin: 0 auto; background: #18202c; border: 1px solid #283548; border-radius: 8px; padding: 20px;">
                <h2 style="color: #4caf50; margin-top: 0;">Service Recovered</h2>
                <p><strong>Site:</strong> {site_name}</p>
                <p><strong>URL:</strong> <a href="{result.url}" style="color: #4da3ff;">{result.url}</a></p>
                <p><strong>HTTP Status:</strong> {result.status_code}</p>
                <p><strong>Latency:</strong> {result.response_time_ms} ms</p>
            </div>
        </body>
        </html>
        """
        return await self._dispatch_async(subject, text_body, html_body)

    async def send_security_alert(self, report: DeepScanReport) -> bool:
        subject = f"[SECURITY THREAT] Vulnerability / Intrusion Alert on {report.target_name}"
        return await self.send_down_alert(report)
