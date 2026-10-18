import asyncio
import socket
import ssl
import time
from datetime import datetime, timezone
from typing import List, Optional, Tuple, Dict
from urllib.parse import urlparse
import aiohttp

from onyxops.core.models import TargetSite, UptimeResult, SSLInfo

class UptimeScanner:
    """Performs HTTP/HTTPS status checks, DNS resolution, and SSL inspection."""

    def __init__(self, timeout_seconds: int = 15):
        self.timeout = aiohttp.ClientTimeout(total=timeout_seconds)

    async def check_target(self, target: TargetSite) -> Tuple[UptimeResult, Optional[str], Dict[str, str]]:
        parsed = urlparse(target.url)
        hostname = parsed.hostname or target.url
        port = parsed.port or (443 if parsed.scheme == "https" else 80)

        # 1. DNS Resolution Check
        dns_ips = await self._resolve_dns(hostname)

        # 2. SSL Inspection (if HTTPS)
        ssl_info = None
        if parsed.scheme == "https" and target.check_ssl:
            ssl_info = await self._inspect_ssl(hostname, port)

        # 3. HTTP / Response check
        start_time = time.perf_counter()
        status_code = None
        response_text = ""
        response_headers = {}
        error_msg = None
        is_up = False

        headers = {
            "User-Agent": "OnyxOps-Sentinel/1.0 (+https://wolfeguard.internal/bot)",
            "Accept": "*/*"
        }
        headers.update(target.headers)

        try:
            connector = aiohttp.TCPConnector(ssl=False) # allow fetching headers even on invalid cert to diagnose
            async with aiohttp.ClientSession(timeout=self.timeout, connector=connector) as session:
                async with session.get(target.url, headers=headers, allow_redirects=True) as resp:
                    status_code = resp.status
                    response_headers = dict(resp.headers)
                    # Read sample content for keyword or integrity checks (limit 1MB)
                    body_bytes = await resp.content.read(1024 * 1024)
                    response_text = body_bytes.decode("utf-8", errors="replace")

                    if status_code in target.expected_status_codes:
                        is_up = True
                    else:
                        is_up = False
                        error_msg = f"Unexpected HTTP status code: {status_code}"

                    # Keyword verification if configured
                    if is_up and target.expected_content_keywords:
                        for kw in target.expected_content_keywords:
                            if kw not in response_text:
                                is_up = False
                                error_msg = f"Expected keyword '{kw}' not found in page content"
                                break

        except asyncio.TimeoutError:
            is_up = False
            error_msg = f"Connection timed out after {self.timeout.total}s"
        except aiohttp.ClientConnectorError as e:
            is_up = False
            error_msg = f"Connection failed: {str(e)}"
        except Exception as e:
            is_up = False
            error_msg = f"Request error: {str(e)}"

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        result = UptimeResult(
            target_id=target.id,
            url=target.url,
            timestamp=datetime.now(timezone.utc),
            is_up=is_up,
            status_code=status_code,
            response_time_ms=round(elapsed_ms, 2),
            dns_resolved_ips=dns_ips,
            ssl_info=ssl_info,
            error_message=error_msg
        )

        return result, response_text, response_headers

    async def _resolve_dns(self, hostname: str) -> List[str]:
        loop = asyncio.get_running_loop()
        try:
            addr_info = await loop.getaddrinfo(hostname, None, family=socket.AF_INET)
            ips = list({item[4][0] for item in addr_info})
            return ips
        except Exception:
            return []

    async def _inspect_ssl(self, hostname: str, port: int) -> SSLInfo:
        loop = asyncio.get_running_loop()
        def _get_cert_sync():
            ctx = ssl.create_default_context()
            try:
                with socket.create_connection((hostname, port), timeout=5) as sock:
                    with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                        cert = ssock.getpeercert()
                        return cert, None
            except Exception as e:
                return None, str(e)

        cert, err = await loop.run_in_executor(None, _get_cert_sync)
        if err or not cert:
            return SSLInfo(valid=False, error_message=err or "Unable to retrieve SSL certificate")

        try:
            # Parse cert details
            not_after_str = cert.get("notAfter")
            # Format: 'May 20 12:00:00 2025 GMT'
            exp_date = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            now = datetime.now(timezone.utc)
            days_left = (exp_date - now).days

            issuer_dict = dict(x[0] for x in cert.get("issuer", ()))
            subject_dict = dict(x[0] for x in cert.get("subject", ()))

            issuer = issuer_dict.get("organizationName", issuer_dict.get("commonName", "Unknown"))
            subject = subject_dict.get("commonName", "Unknown")

            return SSLInfo(
                valid=days_left > 0,
                issuer=issuer,
                subject=subject,
                expiration_date=exp_date,
                days_until_expiry=days_left,
                error_message=None if days_left > 0 else "SSL Certificate has expired!"
            )
        except Exception as e:
            return SSLInfo(valid=False, error_message=f"Failed to parse SSL certificate: {str(e)}")
