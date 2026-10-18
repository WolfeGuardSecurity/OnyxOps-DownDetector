import base64
import logging
from typing import Dict, Any, List
import aiohttp

from onyxops.notifiers.base import BaseNotifier
from onyxops.core.models import DeepScanReport, UptimeResult

logger = logging.getLogger("OnyxOps.SMS")

class SMSNotifier(BaseNotifier):
    """Dispatches SMS alerts via Twilio REST API or generic SMS Webhook."""

    def __init__(self, config: Dict[str, Any]):
        self.enabled = config.get("enabled", False)
        self.provider = config.get("provider", "twilio")
        self.twilio_cfg = config.get("twilio", {})
        self.generic_webhook_url = config.get("generic_webhook_url", "")

    async def _send_twilio_sms(self, to_number: str, message: str) -> bool:
        sid = self.twilio_cfg.get("account_sid")
        token = self.twilio_cfg.get("auth_token")
        from_num = self.twilio_cfg.get("from_number")

        if not (sid and token and from_num):
            logger.error("Twilio credentials incomplete.")
            return False

        url = f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json"
        auth_header = "Basic " + base64.b64encode(f"{sid}:{token}".encode("utf-8")).decode("utf-8")

        data = {
            "From": from_num,
            "To": to_number,
            "Body": message
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, data=data, headers={"Authorization": auth_header}) as resp:
                    if resp.status in (200, 201):
                        logger.info(f"SMS sent successfully to {to_number}")
                        return True
                    else:
                        body = await resp.text()
                        logger.error(f"Failed to send SMS to {to_number}: HTTP {resp.status} - {body}")
                        return False
        except Exception as e:
            logger.error(f"Error dispatching Twilio SMS to {to_number}: {e}")
            return False

    async def _dispatch_to_all(self, message: str) -> bool:
        if not self.enabled:
            return False

        raw_numbers = self.twilio_cfg.get("to_numbers", [])
        if isinstance(raw_numbers, str):
            raw_numbers = [raw_numbers]
        to_numbers: List[str] = [str(n).strip() for n in raw_numbers if str(n).strip()]
        if not to_numbers:
            logger.warning("No recipient phone numbers configured for SMS alerts.")
            return False

        success = True
        for num in to_numbers:
            ok = await self._send_twilio_sms(num, message)
            if not ok:
                success = False
        return success

    async def send_down_alert(self, report: DeepScanReport) -> bool:
        cf_note = f" | Cloudflare: {report.cloudflare.origin_vs_edge}" if report.cloudflare.is_cloudflare else ""
        msg = (
            f"[CRITICAL ALERT - OnyxOps]\n"
            f"Site DOWN: {report.target_name}\n"
            f"URL: {report.url}\n"
            f"Status: {report.uptime.status_code or 'NO_RESPONSE'}\n"
            f"Root Cause: {report.root_cause_summary}{cf_note}"
        )
        return await self._dispatch_to_all(msg)

    async def send_recovery_alert(self, result: UptimeResult, site_name: str) -> bool:
        msg = (
            f"[RECOVERY - OnyxOps]\n"
            f"Site RESTORED: {site_name}\n"
            f"URL: {result.url}\n"
            f"Status: {result.status_code} OK (Latency: {result.response_time_ms}ms)"
        )
        return await self._dispatch_to_all(msg)

    async def send_security_alert(self, report: DeepScanReport) -> bool:
        crit_count = sum(1 for f in report.security_findings if f.severity in ("CRITICAL", "HIGH"))
        msg = (
            f"[SECURITY ALERT - OnyxOps]\n"
            f"Site: {report.target_name}\n"
            f"Detected {crit_count} Critical/High Security or Intrusion issues!\n"
            f"Check email or incident dashboard immediately."
        )
        return await self._dispatch_to_all(msg)
