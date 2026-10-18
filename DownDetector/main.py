import argparse
import asyncio
import os
import shutil
import sys
import time
from datetime import datetime, timezone
from typing import Optional, List
import yaml

# Ensure robust UTF-8 output on Windows consoles to prevent charmap encoding crashes
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.live import Live
from rich.layout import Layout
from rich.prompt import Prompt, Confirm
from rich import print as rprint

from onyxops import __version__, __author__, __organization__
from onyxops.core.models import TargetSite, UptimeResult, DeepScanReport
from onyxops.core.monitor import SentinelMonitor
from onyxops.scanners.uptime import UptimeScanner
from onyxops.scanners.cloudflare import CloudflareScanner
from onyxops.scanners.security import SecurityScanner
from onyxops.scanners.integrity import IntegrityScanner

console = Console()

BANNER_TEXT = f"""
  ___  _  _ __   ____  _____  ___  ___   ____ ___ _  _ _____ ___ _  _ ____ _    
 / _ \| \| |\ \ / /\ \/ / _ \| _ \/ __| / ___| __| \| |_   _|_ _| \| | __| |   
| (_) | .` | \ V /  >  < (_) |  _/\__ \ \___ \ _|| .` | | |  | || .` | _|| |__ 
 \___/|_|\_|  |_|  /_/\_\___/|_|  |___/ |____/___|_|\_| |_| |___|_|\_|___|____|

  [bold red]Automated Down Detection, Exploit Diagnostics & Threat Intelligence[/bold red]
  [dim]Organization: {__organization__} | Lead Developer: {__author__} | v{__version__}[/dim]
"""

def load_config(config_path: str = "config/config.yaml") -> dict:
    if not os.path.exists(config_path):
        example_path = "config/config.example.yaml"
        if os.path.exists(example_path):
            os.makedirs(os.path.dirname(config_path), exist_ok=True)
            shutil.copyfile(example_path, config_path)
        else:
            console.print(f"[red]Configuration template {example_path} not found.[/red]")
            sys.exit(1)

    with open(config_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def save_config(config: dict, config_path: str = "config/config.yaml"):
    with open(config_path, "w", encoding="utf-8") as f:
        yaml.safe_dump(config, f, default_flow_style=False, sort_keys=False)

def print_banner():
    console.print(Panel(BANNER_TEXT.strip(), border_style="bold red", subtitle=f"[cyan]OnyxOps Sentinel v{__version__}[/cyan]"))

# =====================================================================
# FEATURE 1: 24/7 CONTINUOUS WEBSITE MONITOR (LIVE DASHBOARD)
# =====================================================================
async def live_monitor_mode(config_path: str, custom_url: Optional[str] = None):
    config = load_config(config_path)
    monitor = SentinelMonitor(config)

    if custom_url:
        t_id = "custom-monitor"
        target = TargetSite(
            id=t_id,
            name=f"Live Target ({custom_url})",
            url=custom_url,
            check_ssl=True,
            deep_scan_on_failure=True
        )
        monitor.targets = [target]
        monitor._init_target_state(target)

    interval = config.get("system", {}).get("check_interval_seconds", 30)

    console.print(f"\n[bold green]>>> Starting 24/7 Sentinel Continuous Monitor <<<[/bold green]")
    console.print(f"[dim]Polling interval: {interval}s | Alert routes: {len(monitor.notifiers)} active | Press Ctrl+C to stop.[/dim]\n")

    def build_dashboard_table() -> Table:
        table = Table(title="OnyxOps Sentinel - Live Infrastructure Status", border_style="cyan", show_header=True, header_style="bold magenta")
        table.add_column("Target Name", style="bold white", width=24)
        table.add_column("URL", style="dim", width=34)
        table.add_column("Status", justify="center", width=12)
        table.add_column("HTTP", justify="center", width=8)
        table.add_column("Latency", justify="right", width=12)
        table.add_column("SSL Cert", justify="center", width=14)
        table.add_column("Uptime %", justify="right", width=10)
        table.add_column("Last Error / Diagnosis", style="yellow", width=30)

        for t in monitor.targets:
            st = monitor.state.get(t.id, {})
            is_up = st.get("is_up", True)
            status_text = "[bold green]ONLINE[/bold green]" if is_up else "[bold red]DOWN[/bold red]"
            code = str(st.get("last_status") or "-")
            lat = f"{st.get('last_latency', 0.0):.1f} ms"
            ssl_days = st.get("ssl_days")
            ssl_txt = f"{ssl_days} days" if ssl_days is not None else "N/A"
            if ssl_days is not None and ssl_days <= 14:
                ssl_txt = f"[bold red]{ssl_txt}[/bold red]"
            elif ssl_days is not None:
                ssl_txt = f"[green]{ssl_txt}[/green]"
            uptime_pct = f"{st.get('uptime_pct', 100.0):.1f}%"
            err = st.get("last_error") or "Normal"

            table.add_row(t.name[:24], t.url[:34], status_text, code, lat, ssl_txt, uptime_pct, str(err)[:30])
        return table

    with Live(build_dashboard_table(), refresh_per_second=2, console=console) as live:
        try:
            while True:
                tasks = [monitor.check_single_target(target) for target in monitor.targets]
                await asyncio.gather(*tasks, return_exceptions=True)
                live.update(build_dashboard_table())
                for _ in range(interval * 2):
                    await asyncio.sleep(0.5)
                    live.update(build_dashboard_table())
        except (KeyboardInterrupt, asyncio.CancelledError):
            console.print("\n[yellow]Continuous monitoring paused. Returning to menu...[/yellow]")

# =====================================================================
# FEATURE 2: DEEP EXPLOIT & VULNERABILITY AUDIT
# =====================================================================
async def run_deep_exploit_audit(url: str, config_path: str):
    config = load_config(config_path)
    monitor = SentinelMonitor(config)

    target = TargetSite(
        id="exploit-audit",
        name=f"Audit Target ({url})",
        url=url,
        check_ssl=True,
        deep_scan_on_failure=True
    )

    console.print(f"\n[bold cyan]>>> Executing Deep Exploit, Vulnerability & Breach Audit on:[/bold cyan] [bold white]{url}[/bold white]\n")

    with console.status("[bold green]Executing comprehensive multi-vector scan...[/bold green]"):
        uptime_scanner = UptimeScanner(timeout_seconds=15)
        uptime_res, body, headers = await uptime_scanner.check_target(target)
        report: DeepScanReport = await monitor.run_deep_scan(target, uptime_res, body, headers)

    # Uptime Table
    summary_table = Table(title="1. Infrastructure & Connectivity", show_header=True, header_style="bold magenta")
    summary_table.add_column("Check", style="bold")
    summary_table.add_column("Result")
    status_color = "green" if uptime_res.is_up else "red"
    summary_table.add_row("Service Status", f"[{status_color}]{'UP / REACHABLE' if uptime_res.is_up else 'DOWN / UNHEALTHY'}[/{status_color}]")
    summary_table.add_row("HTTP Status Code", str(uptime_res.status_code or "No Response"))
    summary_table.add_row("Roundtrip Latency", f"{uptime_res.response_time_ms} ms")
    summary_table.add_row("Resolved IP Addresses", ", ".join(uptime_res.dns_resolved_ips) or "Failed")
    if uptime_res.ssl_info:
        ssl_status = f"[green]Valid ({uptime_res.ssl_info.days_until_expiry} days remaining, Issuer: {uptime_res.ssl_info.issuer})[/green]" if uptime_res.ssl_info.valid else f"[red]Invalid: {uptime_res.ssl_info.error_message}[/red]"
        summary_table.add_row("SSL/TLS Security", ssl_status)
    summary_table.add_row("Root Cause Analysis", f"[bold yellow]{report.root_cause_summary}[/bold yellow]")
    console.print(summary_table)

    # Cloudflare Table
    cf_table = Table(title="2. Cloudflare & Edge Architecture", show_header=True, header_style="bold blue")
    cf_table.add_column("Attribute", style="bold")
    cf_table.add_column("Detail")
    cf_table.add_row("Cloudflare Edge Active", "[green]Yes[/green]" if report.cloudflare.is_cloudflare else "[yellow]No (Direct Origin)[/yellow]")
    cf_table.add_row("Cloudflare Ray ID", str(report.cloudflare.cf_ray or "N/A"))
    cf_table.add_row("Edge Cache Status", str(report.cloudflare.cf_cache_status or "N/A"))
    cf_table.add_row("Origin vs Edge Health", report.cloudflare.origin_vs_edge or "Direct")
    if report.cloudflare.cf_error_meaning:
        cf_table.add_row("Cloudflare Error Code", f"[red]{report.cloudflare.cf_error_meaning}[/red]")
    console.print(cf_table)

    # Open Ports
    if report.open_ports:
        port_table = Table(title=f"3. Open Port Reconnaissance ({len(report.open_ports)} exposed)", show_header=True, header_style="bold yellow")
        port_table.add_column("Port", style="bold")
        port_table.add_column("Identified Service")
        port_table.add_column("State")
        for p in report.open_ports:
            port_table.add_row(str(p.port), p.service, f"[bold green]{p.state.upper()}[/bold green]")
        console.print(port_table)

    # Vulnerability Table
    sec_table = Table(title=f"4. Deep Security & Exploit Findings ({len(report.security_findings)} identified)", show_header=True, header_style="bold red")
    sec_table.add_column("Severity", style="bold", width=12)
    sec_table.add_column("Vulnerability Category", width=25)
    sec_table.add_column("Finding Title", width=36)
    sec_table.add_column("Remediation / Fix", width=42)

    if report.security_findings:
        for f in report.security_findings:
            sev_color = {
                "CRITICAL": "bold red",
                "HIGH": "red",
                "MEDIUM": "yellow",
                "LOW": "cyan",
                "INFO": "dim white"
            }.get(f.severity, "white")

            sec_table.add_row(
                f"[{sev_color}]{f.severity}[/{sev_color}]",
                f.category,
                f.title,
                f.remediation
            )
        console.print(sec_table)
    else:
        console.print("[bold green]✓ Clean Scan: No critical OWASP vulnerabilities, exposed files, or malware detected.[/bold green]")

    console.print(f"\n[green]✓ Comprehensive forensic post-mortem saved to directory: [bold]incidents/[/bold][/green]\n")

# =====================================================================
# FEATURE 3: CLOUDFLARE EDGE DIAGNOSTIC
# =====================================================================
async def run_cloudflare_diagnostic(url: str):
    console.print(f"\n[bold blue]>>> Querying Cloudflare Edge Telemetry for:[/bold blue] {url}...\n")
    scanner = UptimeScanner(timeout_seconds=10)
    target = TargetSite(id="cf-diag", name="CF Diag", url=url)
    uptime_res, body, headers = await scanner.check_target(target)

    cf_scanner = CloudflareScanner()
    report, findings = cf_scanner.analyze(uptime_res.status_code, headers, body, uptime_res.dns_resolved_ips)

    table = Table(title=f"Cloudflare Edge Diagnostics: {url}", show_header=True, header_style="bold cyan")
    table.add_column("Metric", style="bold")
    table.add_column("Value")
    table.add_row("Cloudflare Proxied", "YES" if report.is_cloudflare else "NO")
    table.add_row("Cloudflare Ray ID", str(report.cf_ray or "N/A"))
    table.add_row("Cache Status", str(report.cf_cache_status or "N/A"))
    table.add_row("Origin Connectivity", str(report.origin_vs_edge))
    table.add_row("Resolved Edge IPs", ", ".join(uptime_res.dns_resolved_ips) or "None")

    if findings:
        for f in findings:
            table.add_row(f"[red]{f.category}[/red]", f.detail)

    console.print(table)

# =====================================================================
# FEATURE 4: PORT SCANNER
# =====================================================================
async def run_port_scanner(hostname: str):
    from urllib.parse import urlparse
    if "://" in hostname:
        hostname = urlparse(hostname).hostname or hostname

    console.print(f"\n[bold yellow]>>> Scanning Network Infrastructure & Ports on:[/bold yellow] {hostname}...\n")
    sec = SecurityScanner(timeout_seconds=2)
    with console.status("[bold green]Scanning TCP service ports...[/bold green]"):
        open_ports = await sec.scan_open_ports(hostname)

    table = Table(title=f"Port Reconnaissance Results: {hostname}", show_header=True, header_style="bold magenta")
    table.add_column("Port", style="bold")
    table.add_column("Service")
    table.add_column("State")

    if open_ports:
        for p in open_ports:
            table.add_row(str(p.port), p.service, "[green]OPEN[/green]")
    else:
        table.add_row("All Common Ports", "Standard Ports", "[cyan]Filtered / Closed[/cyan]")
    console.print(table)

# =====================================================================
# FEATURE 5: WEB INTEGRITY & MALWARE SCANNER
# =====================================================================
async def run_integrity_scan(url: str):
    console.print(f"\n[bold red]>>> Analyzing Web Integrity & Malware Signatures for:[/bold red] {url}...\n")
    scanner = UptimeScanner(timeout_seconds=10)
    target = TargetSite(id="integrity-scan", name="Integrity", url=url)
    uptime_res, body, _ = await scanner.check_target(target)

    integ = IntegrityScanner()
    hits = integ.inspect(body)

    if hits:
        table = Table(title="Malware & Integrity Findings", show_header=True, header_style="bold red")
        table.add_column("Severity")
        table.add_column("Title")
        table.add_column("Details")
        for h in hits:
            table.add_row(h.severity, h.title, h.detail)
        console.print(table)
    else:
        console.print("[bold green]✓ Page DOM Verified Clean. No known crypto-miners, hidden zero-pixel iframes, or defacement strings detected.[/bold green]")

# =====================================================================
# FEATURE 6: TARGET MANAGER
# =====================================================================
def target_manager(config_path: str):
    while True:
        config = load_config(config_path)
        targets = config.get("targets", [])

        console.print("\n[bold cyan]=== Monitored Targets Manager ===[/bold cyan]")
        table = Table(show_header=True, header_style="bold cyan")
        table.add_column("#", style="dim", width=4)
        table.add_column("Target ID", style="bold")
        table.add_column("Name")
        table.add_column("URL")

        for idx, t in enumerate(targets, 1):
            table.add_row(str(idx), t.get("id"), t.get("name"), t.get("url"))
        console.print(table)

        console.print("\n[1] Add New Target Website")
        console.print("[2] Remove Monitored Target")
        console.print("[0] Return to Main Menu")

        choice = Prompt.ask("Select option", choices=["1", "2", "0"], default="0")

        if choice == "1":
            new_url = Prompt.ask("Enter Website URL (e.g. https://example.com)")
            new_name = Prompt.ask("Enter Friendly Name", default=new_url.replace("https://", "").replace("http://", "").split("/")[0])
            new_id = new_name.lower().replace(" ", "-").replace(".", "-")[:20]

            new_target = {
                "id": new_id,
                "name": new_name,
                "url": new_url,
                "check_ssl": True,
                "ssl_expiry_warning_days": 14,
                "deep_scan_on_failure": True,
                "expected_status_codes": [200, 301, 302]
            }
            targets.append(new_target)
            config["targets"] = targets
            save_config(config, config_path)
            console.print(f"[green]Successfully added target '{new_name}' to configuration![/green]")
        elif choice == "2":
            if not targets:
                console.print("[yellow]No targets configured to remove.[/yellow]")
                continue
            idx_remove = Prompt.ask("Enter # of target to remove", default="1")
            try:
                idx_int = int(idx_remove) - 1
                if 0 <= idx_int < len(targets):
                    removed = targets.pop(idx_int)
                    config["targets"] = targets
                    save_config(config, config_path)
                    console.print(f"[green]Removed target '{removed.get('name')}'![/green]")
            except ValueError:
                console.print("[red]Invalid index.[/red]")
        elif choice == "0":
            break

# =====================================================================
# FEATURE 7: TEST ALERT DISPATCHERS
# =====================================================================
async def test_notifications(config_path: str):
    config = load_config(config_path)
    monitor = SentinelMonitor(config)

    dummy_uptime = UptimeResult(
        target_id="test-probe",
        url="https://admin.onyxops.org",
        timestamp=datetime.now(timezone.utc),
        is_up=False,
        status_code=521,
        response_time_ms=125.4,
        dns_resolved_ips=["104.21.4.222"],
        error_message="Test incident alert dispatch"
    )

    console.print(f"\n[bold cyan]Testing {len(monitor.notifiers)} active alert channels...[/bold cyan]")
    if not monitor.notifiers:
        console.print("[yellow]No notification channels are enabled in config/config.yaml.[/yellow]")
        console.print("[dim]Open config/config.yaml and set enabled: true for SMS, Email, or Discord.[/dim]")
        return

    for n in monitor.notifiers:
        channel_name = n.__class__.__name__
        console.print(f"Testing {channel_name}...")
        ok = await n.send_recovery_alert(dummy_uptime, "OnyxOps Sentinel Test Probe")
        status_txt = "[green]SUCCESS[/green]" if ok else "[red]FAILED[/red]"
        console.print(f" • {channel_name}: {status_txt}")

# =====================================================================
# FEATURE 8: VIEW ARCHIVED INCIDENT REPORTS
# =====================================================================
def view_incident_reports():
    inc_dir = "incidents"
    if not os.path.exists(inc_dir) or not os.listdir(inc_dir):
        console.print("[yellow]No incident reports archived yet. Run a deep scan or live monitor to generate reports.[/yellow]")
        return

    files = [f for f in os.listdir(inc_dir) if f.endswith(".md")]
    files.sort(reverse=True)

    console.print("\n[bold cyan]=== Archived Incident Forensic Reports ===[/bold cyan]")
    for i, f in enumerate(files[:15], 1):
        console.print(f"[{i}] {f}")

    choice = Prompt.ask("\nEnter report # to view (or 0 to cancel)", default="0")
    try:
        c_int = int(choice)
        if 1 <= c_int <= len(files):
            file_to_view = os.path.join(inc_dir, files[c_int - 1])
            with open(file_to_view, "r", encoding="utf-8") as rf:
                content = rf.read()
            console.print(Panel(content, title=files[c_int - 1], border_style="cyan"))
    except Exception:
        pass

# =====================================================================
# INTERACTIVE CONSOLE MENU
# =====================================================================
async def interactive_menu(config_path: str):
    while True:
        print_banner()
        console.print("[bold white]Choose an operation mode:[/bold white]\n")
        console.print(" [bold green][1][/bold green] 🟢 [bold]24/7 Live Website Monitor[/bold] (Continuous uptime & automated alert engine)")
        console.print(" [bold cyan][2][/bold cyan] 🔍 [bold]Deep Exploit & Vulnerability Audit[/bold] (CORS, Headers, Methods, Secrets)")
        console.print(" [bold blue][3][/bold blue] ☁️ [bold]Cloudflare & Edge Diagnostics[/bold] (52x errors, Ray ID, WAF rules)")
        console.print(" [bold yellow][4][/bold yellow] 🔌 [bold]Port & Infrastructure Scanner[/bold] (Database, SSH, Admin services)")
        console.print(" [bold red][5][/bold red] 🦠 [bold]Web Integrity & Malware Scan[/bold] (Crypto-miners, Defacement, Injected scripts)")
        console.print(" [bold magenta][6][/bold magenta] 🎯 [bold]Target Manager[/bold] (Add, list, or remove monitored websites)")
        console.print(" [bold cyan][7][/bold cyan] 🔔 [bold]Test Alert Dispatchers[/bold] (SMS, Email, Discord)")
        console.print(" [bold white][8][/bold white] 📑 [bold]View Archived Incident Reports[/bold]")
        console.print(" [bold dim][0][/bold dim] 🚪 [dim]Exit[/dim]\n")

        choice = Prompt.ask("[bold]Select an option[/bold]", choices=["1", "2", "3", "4", "5", "6", "7", "8", "0"], default="1")

        if choice == "1":
            config = load_config(config_path)
            default_url = config.get("targets", [{}])[0].get("url", "https://admin.onyxops.org/products")
            monitor_choice = Prompt.ask("Monitor all configured targets in config.yaml [bold](A)[/bold] or a specific custom URL [bold](C)[/bold]?", choices=["A", "C", "a", "c"], default="A").upper()
            if monitor_choice == "C":
                target_url = Prompt.ask("Enter Website URL to monitor 24/7", default=default_url)
                await live_monitor_mode(config_path, custom_url=target_url)
            else:
                await live_monitor_mode(config_path, custom_url=None)
        elif choice == "2":
            config = load_config(config_path)
            default_url = config.get("targets", [{}])[0].get("url", "https://admin.onyxops.org/products")
            target_url = Prompt.ask("Enter Website URL to Deep Audit", default=default_url)
            await run_deep_exploit_audit(target_url, config_path)
            Prompt.ask("\nPress Enter to return to menu...")
        elif choice == "3":
            config = load_config(config_path)
            default_url = config.get("targets", [{}])[0].get("url", "https://admin.onyxops.org/products")
            target_url = Prompt.ask("Enter Website URL for Cloudflare analysis", default=default_url)
            await run_cloudflare_diagnostic(target_url)
            Prompt.ask("\nPress Enter to return to menu...")
        elif choice == "4":
            config = load_config(config_path)
            default_url = config.get("targets", [{}])[0].get("url", "https://admin.onyxops.org/products")
            target_host = Prompt.ask("Enter Domain / IP for port scan", default=default_url)
            await run_port_scanner(target_host)
            Prompt.ask("\nPress Enter to return to menu...")
        elif choice == "5":
            config = load_config(config_path)
            default_url = config.get("targets", [{}])[0].get("url", "https://admin.onyxops.org/products")
            target_url = Prompt.ask("Enter Website URL for malware/integrity scan", default=default_url)
            await run_integrity_scan(target_url)
            Prompt.ask("\nPress Enter to return to menu...")
        elif choice == "6":
            target_manager(config_path)
        elif choice == "7":
            await test_notifications(config_path)
            Prompt.ask("\nPress Enter to return to menu...")
        elif choice == "8":
            view_incident_reports()
            Prompt.ask("\nPress Enter to return to menu...")
        elif choice == "0":
            console.print("\n[bold red]Shutting down OnyxOps Sentinel. Stay safe.[/bold red]\n")
            break

def main():
    parser = argparse.ArgumentParser(description="OnyxOps Sentinel - Down Detector & Threat Diagnostic Bot")
    parser.add_argument("--config", default="config/config.yaml", help="Path to config.yaml")

    subparsers = parser.add_subparsers(dest="command", help="Command to execute (optional - omitting launches interactive menu)")
    subparsers.add_parser("menu", help="Launch interactive feature menu")
    subparsers.add_parser("run", help="Start continuous monitoring daemon directly")
    
    scan_parser = subparsers.add_parser("scan", help="Run an immediate deep diagnostic scan on a URL")
    scan_parser.add_argument("url", help="Target URL (e.g. https://example.com)")

    subparsers.add_parser("test-alerts", help="Dispatch test notification pings to configured channels")

    args = parser.parse_args()

    # If user ran without subcommands or ran menu, launch interactive menu
    if args.command is None or args.command == "menu":
        asyncio.run(interactive_menu(args.config))
    elif args.command == "run":
        asyncio.run(live_monitor_mode(args.config))
    elif args.command == "scan":
        asyncio.run(run_deep_exploit_audit(args.url, args.config))
    elif args.command == "test-alerts":
        asyncio.run(test_notifications(args.config))

if __name__ == "__main__":
    main()
