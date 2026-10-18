import logging
from typing import Dict, Any, List
import aiohttp

from onyxops.notifiers.base import BaseNotifier
from onyxops.core.models import DeepScanReport, UptimeResult

logger = logging.getLogger("OnyxOps.Discord")

COLOR_RED = 15022389     # #e53935 (Down / Critical)
COLOR_GREEN = 4432071    # #43a047 (Recovered / Healthy)
COLOR_ORANGE = 16485376  # #fb8c00 (Warning / Degradation)

class DiscordNotifier(BaseNotifier):
    """Dispatches real-time rich embeds to a Discord channel via Webhook."""

    def __init__(self, config: Dict[str, Any]):
        self.enabled = config.get("enabled", False)
        self.webhook_url = config.get("webhook_url", "")
        self.username = config.get("username", "OnyxOps Sentinel")
        self.avatar_url = config.get("avatar_url", "")

    async def _post_embed(self, embed: Dict[str, Any]) -> bool:
        if not self.enabled or not self.webhook_url:
            return False

        payload = {
            "username": self.username,
            "embeds": [embed]
        }
        if self.avatar_url:
            payload["avatar_url"] = self.avatar_url

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(self.webhook_url, json=payload) as resp:
                    if resp.status in (200, 204):
                        logger.info("Discord webhook alert sent successfully.")
                        return True
                    else:
                        text = await resp.text()
                        logger.error(f"Failed to send Discord webhook: HTTP {resp.status} - {text}")
                        return False
        except Exception as e:
            logger.error(f"Exception dispatching Discord webhook: {e}")
            return False

    async def send_down_alert(self, report: DeepScanReport) -> bool:
        fields = [
            {"name": "🌐 Target URL", "value": f"[{report.url}]({report.url})", "inline": True},
            {"name": "⚠️ Status Code", "value": str(report.uptime.status_code or "NO RESPONSE"), "inline": True},
            {"name": "⏱️ Latency", "value": f"{report.uptime.response_time_ms} ms", "inline": True},
            {"name": "🔍 Root Cause Diagnosis", "value": report.root_cause_summary or "Unknown failure", "inline": False}
        ]

        # Cloudflare details
        if report.cloudflare.is_cloudflare:
            cf_val = f"**Status:** {report.cloudflare.origin_vs_edge}\n**Ray ID:** `{report.cloudflare.cf_ray or 'N/A'}`"
            if report.cloudflare.cf_error_meaning:
                cf_val += f"\n**Error:** {report.cloudflare.cf_error_meaning}"
            fields.append({"name": "☁️ Cloudflare Diagnostics", "value": cf_val, "inline": False})

        # Open ports
        if report.open_ports:
            ports_summary = ", ".join([f"`{p.port}` ({p.service})" for p in report.open_ports[:5]])
            fields.append({"name": "🔌 Open Ports Detected", "value": ports_summary, "inline": False})

        # Vulnerabilities / Security threats
        if report.security_findings:
            crit_findings = [f"• **[{f.severity}]** {f.title}" for f in report.security_findings[:6]]
            fields.append({
                "name": f"🛡️ Security Scan Findings ({len(report.security_findings)} total)",
                "value": "\n".join(crit_findings),
                "inline": False
            })

        embed = {
            "title": f"🚨 INCIDENT: {report.target_name} is DOWN",
            "description": "An automated deep diagnostic scan was executed immediately upon outage detection.",
            "color": COLOR_RED,
            "fields": fields,
            "footer": {
                "text": "OnyxOps by WolfeGuard • Dev: sinfulldesirez"
            },
            "timestamp": report.timestamp.isoformat()
        }

        return await self._post_embed(embed)

    async def send_recovery_alert(self, result: UptimeResult, site_name: str) -> bool:
        embed = {
            "title": f"✅ RECOVERY: {site_name} is BACK ONLINE",
            "description": f"Target `{result.url}` has recovered and is successfully responding.",
            "color": COLOR_GREEN,
            "fields": [
                {"name": "HTTP Status", "value": f"{result.status_code} OK", "inline": True},
                {"name": "Response Time", "value": f"{result.response_time_ms} ms", "inline": True},
                {"name": "Resolved IP", "value": ", ".join(result.dns_resolved_ips) or "Default", "inline": True}
            ],
            "footer": {
                "text": "OnyxOps Sentinel • WolfeGuard"
            },
            "timestamp": result.timestamp.isoformat()
        }
        return await self._post_embed(embed)

    async def send_security_alert(self, report: DeepScanReport) -> bool:
        crit_count = sum(1 for f in report.security_findings if f.severity in ("CRITICAL", "HIGH"))
        findings_text = "\n".join([f"• **[{f.severity}]** {f.title}: {f.detail[:70]}" for f in report.security_findings[:8]])

        embed = {
            "title": f"🛡️ SECURITY THREAT: {report.target_name}",
            "description": f"Periodic security audit identified **{crit_count}** Critical/High severity issues.",
            "color": COLOR_ORANGE,
            "fields": [
                {"name": "Vulnerabilities Detected", "value": findings_text or "Check incident logs for details.", "inline": False}
            ],
            "footer": {
                "text": "OnyxOps Sentinel • Dev: sinfulldesirez"
            },
            "timestamp": report.timestamp.isoformat()
        }
        return await self._post_embed(embed)
