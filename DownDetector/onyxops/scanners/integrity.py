import re
from typing import List
from onyxops.core.models import SecurityFinding

DEFACEMENT_PATTERNS = [
    r"hacked by\b",
    r"defaced by\b",
    r"pwned by\b",
    r"security breach\b",
    r"owned by\b",
    r"greetz to\b"
]

MALWARE_SIGNATURES = [
    {
        "pattern": r"(coinhive\.min\.js|cryptoloot|webminepool|deepminer)",
        "title": "Crypto-Mining Script Detected",
        "severity": "CRITICAL",
        "detail": "Unauthorized browser-based cryptocurrency miner script reference found embedded in page DOM.",
        "remediation": "Audit server filesystem and database for injected scripts; isolate infected web files immediately."
    },
    {
        "pattern": r"eval\s*\(\s*(atob|unescape|decodeURIComponent)\s*\(",
        "title": "Obfuscated Dynamic Script Execution (eval/atob/unescape)",
        "severity": "HIGH",
        "detail": "Heavy JavaScript obfuscation wrapper detected, often used by malware/droppers to conceal malicious payloads.",
        "remediation": "Inspect client-side scripts to verify origin and deobfuscate content for forensic review."
    },
    {
        "pattern": r"<iframe[^>]+(display:\s*none|visibility:\s*hidden|width=[\"']?0[\"']?|height=[\"']?0[\"']?)",
        "title": "Hidden Zero-Pixel / Invisible iFrame Injection",
        "severity": "HIGH",
        "detail": "Hidden iframe pattern found in page content. Often used in drive-by downloads, click-jacking, or credential exfiltration.",
        "remediation": "Audit page template and CMS plugins for compromised theme files or injected hooks."
    },
    {
        "pattern": r"document\.write\s*\(\s*unescape\s*\(",
        "title": "Legacy Malicious Script Write Injection",
        "severity": "HIGH",
        "detail": "Use of document.write(unescape(...)) signature typical of legacy web exploit kits.",
        "remediation": "Remove the script block and audit web access logs for unauthorized file modifications."
    }
]

class IntegrityScanner:
    """Analyzes rendered HTML for malware injection, crypto-miners, and website defacements."""

    @staticmethod
    def inspect(body_content: str) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        if not body_content:
            return findings

        # 1. Defacement Detection
        for pat in DEFACEMENT_PATTERNS:
            match = re.search(pat, body_content, re.IGNORECASE)
            if match:
                findings.append(SecurityFinding(
                    severity="CRITICAL",
                    category="Website Defacement / Intrusion",
                    title="Website Defacement / Hack Signature Detected",
                    detail=f"Found suspicious defacement text pattern: '{match.group(0)}'",
                    remediation="Immediately take website offline or switch to maintenance page. Initiate incident response to restore clean backups."
                ))
                break

        # 2. Malware & Injected Scripts
        for sig in MALWARE_SIGNATURES:
            match = re.search(sig["pattern"], body_content, re.IGNORECASE)
            if match:
                findings.append(SecurityFinding(
                    severity=sig["severity"],
                    category="Malware / Intrusion Signature",
                    title=sig["title"],
                    detail=f"{sig['detail']} (Matched: '{match.group(0)[:60]}')",
                    remediation=sig["remediation"]
                ))

        return findings
