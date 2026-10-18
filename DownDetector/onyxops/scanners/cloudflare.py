import ipaddress
from typing import Dict, Optional, List, Tuple
from onyxops.core.models import CloudflareReport, SecurityFinding

CF_IPV4_RANGES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
    "141.101.64.0/18", "108.162.192.0/18", "190.93.240.0/20", "188.114.96.0/20",
    "197.234.240.0/22", "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22"
]
CF_NETWORKS = [ipaddress.ip_network(r) for r in CF_IPV4_RANGES]

CF_ERROR_CATALOG = {
    520: {
        "title": "520 Web Server is Returning an Unknown Error",
        "detail": "Origin server returned an empty or invalid HTTP response to Cloudflare.",
        "origin_vs_edge": "Edge Active, Origin Malformed/Crashed"
    },
    521: {
        "title": "521 Web Server is Down",
        "detail": "Origin web server actively refused TCP connection from Cloudflare (port 80/443 closed or web service down).",
        "origin_vs_edge": "Edge Active, Origin Down"
    },
    522: {
        "title": "522 Connection Timed Out",
        "detail": "Cloudflare could not complete TCP handshake with origin (origin firewall dropping Cloudflare IP ranges).",
        "origin_vs_edge": "Edge Active, Origin Dropping Handshake"
    },
    523: {
        "title": "523 Origin is Unreachable",
        "detail": "Cloudflare cannot reach origin server due to invalid origin DNS A-record or routing failure.",
        "origin_vs_edge": "Edge Active, Routing/Origin IP Fault"
    },
    524: {
        "title": "524 A Timeout Occurred",
        "detail": "Cloudflare completed TCP handshake, but origin server took longer than 100 seconds to respond.",
        "origin_vs_edge": "Edge Active, Origin Processing Hang"
    },
    525: {
        "title": "525 SSL Handshake Failed",
        "detail": "Cloudflare and origin server could not agree on an SSL/TLS cipher suite or origin port 443 is misconfigured.",
        "origin_vs_edge": "Edge Active, Origin SSL Misconfigured"
    },
    526: {
        "title": "526 Invalid SSL Certificate",
        "detail": "Cloudflare is in Full (Strict) SSL mode, but the origin certificate is expired, self-signed, or untrusted.",
        "origin_vs_edge": "Edge Active, Origin Certificate Untrusted"
    },
    530: {
        "title": "530 Origin DNS Error",
        "detail": "Cloudflare could not resolve the origin hostname in internal DNS settings.",
        "origin_vs_edge": "Edge Active, Cloudflare DNS Misconfigured"
    }
}

class CloudflareScanner:
    """Diagnoses Cloudflare edge vs origin status, WAF challenges, and origin IP leaks."""

    @staticmethod
    def is_cloudflare_ip(ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            return any(ip in net for net in CF_NETWORKS)
        except ValueError:
            return False

    @staticmethod
    def analyze(status_code: Optional[int], headers: Dict[str, str], body_sample: str, resolved_ips: List[str] = None) -> Tuple[CloudflareReport, List[SecurityFinding]]:
        norm_headers = {k.lower(): v for k, v in headers.items()}
        findings: List[SecurityFinding] = []

        cf_ray = norm_headers.get("cf-ray")
        server_header = norm_headers.get("server", "").lower()
        cf_cache_status = norm_headers.get("cf-cache-status")

        is_cf = bool(cf_ray or "cloudflare" in server_header or "cf-cache-status" in norm_headers)
        if not is_cf and ("cloudflare" in body_sample.lower() and "ray id" in body_sample.lower()):
            is_cf = True

        # Origin IP Leak Check: If domain is supposed to be Cloudflare protected, but resolves to non-CF IPs
        if resolved_ips:
            all_cf = all(CloudflareScanner.is_cloudflare_ip(ip) for ip in resolved_ips)
            any_cf = any(CloudflareScanner.is_cloudflare_ip(ip) for ip in resolved_ips)
            if any_cf and not all_cf:
                findings.append(SecurityFinding(
                    severity="HIGH",
                    category="Origin IP Leak / Bypass",
                    title="Direct Origin IP Leak Detected Alongside Cloudflare",
                    detail=f"DNS returns mixed IPs: {resolved_ips}. Attackers can bypass Cloudflare WAF/DDoS protection by connecting directly to the non-Cloudflare IP.",
                    remediation="Ensure all public DNS records are proxied (orange-clouded) through Cloudflare and origin firewalls accept traffic exclusively from Cloudflare IP ranges."
                ))

        cf_error_code = None
        cf_error_meaning = None
        origin_vs_edge = "Direct / Non-Cloudflare" if not is_cf else "Edge & Origin Normal"

        if is_cf:
            if status_code in CF_ERROR_CATALOG:
                cf_error_code = status_code
                info = CF_ERROR_CATALOG[status_code]
                cf_error_meaning = f"{info['title']}: {info['detail']}"
                origin_vs_edge = info['origin_vs_edge']
            elif status_code == 403 and ("error 1020" in body_sample.lower() or "access denied" in body_sample.lower()):
                cf_error_code = 1020
                cf_error_meaning = "Cloudflare WAF / Security Rule Blocked Request"
                origin_vs_edge = "Edge Blocked (WAF Rule Active)"
            elif status_code == 429 or "error 1015" in body_sample.lower():
                cf_error_code = 1015
                cf_error_meaning = "Cloudflare Rate Limit Exceeded"
                origin_vs_edge = "Edge Rate Limited"
            elif "cf-mitigated" in norm_headers or "challenge" in body_sample.lower():
                cf_error_meaning = "Cloudflare Interactive Challenge / Turnstile Triggered"

        report = CloudflareReport(
            is_cloudflare=is_cf,
            cf_ray=cf_ray,
            cf_cache_status=cf_cache_status,
            cf_error_code=cf_error_code,
            cf_error_meaning=cf_error_meaning,
            origin_vs_edge=origin_vs_edge
        )

        return report, findings
