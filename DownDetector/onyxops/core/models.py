from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Dict, Optional, Any

@dataclass
class TargetSite:
    id: str
    name: str
    url: str
    check_ssl: bool = True
    ssl_expiry_warning_days: int = 14
    deep_scan_on_failure: bool = True
    periodic_security_scan_hours: int = 12
    expected_status_codes: List[int] = field(default_factory=lambda: [200, 301, 302])
    expected_content_keywords: List[str] = field(default_factory=list)
    headers: Dict[str, str] = field(default_factory=dict)

@dataclass
class SSLInfo:
    valid: bool
    issuer: str = ""
    subject: str = ""
    expiration_date: Optional[datetime] = None
    days_until_expiry: Optional[int] = None
    error_message: Optional[str] = None

@dataclass
class CloudflareReport:
    is_cloudflare: bool = False
    cf_ray: Optional[str] = None
    cf_cache_status: Optional[str] = None
    cf_error_code: Optional[int] = None
    cf_error_meaning: Optional[str] = None
    origin_vs_edge: Optional[str] = None # e.g. "Edge OK, Origin Down (521/522/523)" or "Normal"

@dataclass
class PortScanFinding:
    port: int
    service: str
    state: str # "open", "closed", "filtered"

@dataclass
class SecurityFinding:
    severity: str # "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"
    category: str # "Exposed File", "Missing Header", "Malicious Pattern", "SSL Weakness"
    title: str
    detail: str
    remediation: str

@dataclass
class UptimeResult:
    target_id: str
    url: str
    timestamp: datetime
    is_up: bool
    status_code: Optional[int] = None
    response_time_ms: float = 0.0
    dns_resolved_ips: List[str] = field(default_factory=list)
    ssl_info: Optional[SSLInfo] = None
    error_message: Optional[str] = None

@dataclass
class DeepScanReport:
    target_id: str
    target_name: str
    url: str
    timestamp: datetime
    uptime: UptimeResult
    cloudflare: CloudflareReport
    open_ports: List[PortScanFinding] = field(default_factory=list)
    security_findings: List[SecurityFinding] = field(default_factory=list)
    root_cause_summary: str = ""
