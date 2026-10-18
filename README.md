# OnyxOps Sentinel

Website uptime monitoring and security diagnostics for OnyxOps by WolfeGuard.
Version 1.0.0.

## Team

- CortezDemartino — OnyxOps Founder
- sinfulldesirez — Lead Developer (Discord)
- NovaDev — Developer

## What it does

- Checks HTTP status, response time, DNS resolution, and TLS certificate expiry.
- Displays target status and uptime in a terminal dashboard.
- Runs additional diagnostics when a monitored target fails.
- Identifies common Cloudflare errors and records Ray IDs and cache status.
- Checks security headers, cookie flags, CORS behavior, advertised HTTP methods,
  exposed files, and common TCP ports.
- Looks for known malware and defacement patterns in fetched HTML.
- Saves incident reports as Markdown and JSON.
- Supports outage and recovery alerts through Twilio SMS, SMTP email, and Discord.

Scan results are indicators for investigation. Pattern matching cannot establish
that a site is secure or compromised, and HTML checks do not execute JavaScript.

## Setup

Use Python 3.12 or newer. Run these commands from the repository root in PowerShell:

```powershell
python -m venv .venv
python -m pip --python .venv install -r DownDetector/requirements.txt
```

The active configuration is `DownDetector/config/config.yaml`. If it is missing,
the application copies `DownDetector/config/config.example.yaml` on first load.

The active configuration monitors these sites with a 30-second polling interval:

- https://palisade.onyxops.org
- https://onyxops.org
- https://dubyu.xyz

Each monitoring round completes its checks before waiting for the polling interval.
TLS checks and diagnostics on failure are enabled for all three targets.

Notification channels start disabled. Add your credentials and recipients to the
configuration before enabling a channel. Keep credentials out of version control.

## Run

Open the interactive menu:

```powershell
.\.venv\Scripts\python.exe DownDetector/main.py
```

On Windows, you can also launch `DownDetector\run.bat`. The menu includes monitoring,
security scans, Cloudflare diagnostics, port scans, HTML integrity checks, target
management, alert tests, and archived reports.

Start monitoring directly:

```powershell
.\.venv\Scripts\python.exe DownDetector/main.py run
```

Run a diagnostic scan against a site you administer:

```powershell
.\.venv\Scripts\python.exe DownDetector/main.py scan https://palisade.onyxops.org
```

Send test alerts to enabled channels:

```powershell
.\.venv\Scripts\python.exe DownDetector/main.py test-alerts
```

To use another configuration, place `--config PATH` before the command:

```powershell
.\.venv\Scripts\python.exe DownDetector/main.py --config custom.yaml run
```

Reports are written to `incidents/` under the current working directory. The
Windows launchers use the `DownDetector` directory as their working directory.
Press Ctrl+C to stop monitoring.

## Tests

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe -m pip check
```

Tests use local HTTP fixtures and mocks. They cover configuration loading, HTTP
checks, scanner findings, outage and recovery state, and report generation.
They do not scan the configured public sites or send real notifications.
