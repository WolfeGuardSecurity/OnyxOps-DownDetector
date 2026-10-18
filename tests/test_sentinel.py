import asyncio
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'DownDetector'))
from main import load_config, save_config
from onyxops.core.models import TargetSite, UptimeResult, DeepScanReport, CloudflareReport
from onyxops.core.monitor import SentinelMonitor
from onyxops.scanners.cloudflare import CloudflareScanner, CF_ERROR_CATALOG
from onyxops.scanners.integrity import IntegrityScanner
from onyxops.scanners.security import SecurityScanner, SECURITY_HEADERS
from onyxops.scanners.uptime import UptimeScanner
from onyxops.reporting.incident_report import IncidentReporter
from onyxops.notifiers.discord import DiscordNotifier
from onyxops.notifiers.email import EmailNotifier
from onyxops.notifiers.sms import SMSNotifier
from aiohttp import web


class ConfigTests(unittest.TestCase):
    def test_default_from_other_directory(self):
        previous = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            try:
                os.chdir(tmp)
                config = load_config()
                self.assertTrue(config['targets'])
                self.assertFalse(config['notifications']['discord']['enabled'])
            finally:
                os.chdir(previous)

    def test_create_and_save_custom_config(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = str(Path(tmp) / 'nested' / 'config.yaml')
            config = load_config(path)
            config['targets'] = []
            save_config(config, path)
            self.assertEqual(load_config(path)['targets'], [])

    def test_bare_filename(self):
        previous = os.getcwd()
        with tempfile.TemporaryDirectory() as tmp:
            try:
                os.chdir(tmp)
                self.assertIsInstance(load_config('custom.yaml'), dict)
            finally:
                os.chdir(previous)


class AnalysisTests(unittest.TestCase):
    def test_cloudflare_errors(self):
        for code in CF_ERROR_CATALOG:
            with self.subTest(code=code):
                report, _ = CloudflareScanner.analyze(code, {'Server': 'cloudflare'}, '', [])
                self.assertEqual(report.cf_error_code, code)
                self.assertTrue(report.cf_error_meaning)

    def test_mixed_ips(self):
        _, findings = CloudflareScanner.analyze(200, {}, '', ['104.21.4.222', '192.0.2.1'])
        self.assertEqual(findings[0].severity, 'HIGH')

    def test_clean_integrity(self):
        self.assertEqual(IntegrityScanner.inspect('<h1>Welcome</h1>'), [])
        self.assertEqual(IntegrityScanner.inspect(''), [])

    def test_malware_signatures(self):
        for body in ['hacked by intruder', 'coinhive.min.js', 'eval(atob("x"))', '<iframe width="0">']:
            with self.subTest(body=body):
                self.assertTrue(IntegrityScanner.inspect(body))

    def test_report_files(self):
        result = UptimeResult('local', 'http://localhost', datetime.now(timezone.utc), False, status_code=503)
        report = DeepScanReport('local', 'Local', result.url, result.timestamp, result, CloudflareReport(), root_cause_summary='Unavailable')
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(IncidentReporter(tmp).save_report(report))
            self.assertIn('Unavailable', path.read_text(encoding='utf-8'))
            self.assertEqual(json.loads(path.with_suffix('.json').read_text())['uptime']['status_code'], 503)


class AsyncTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        async def handle(request):
            if request.path == '/down':
                return web.Response(status=503)
            if request.path == '/cors':
                return web.Response(headers={'Access-Control-Allow-Origin': request.headers.get('Origin', ''), 'Access-Control-Allow-Credentials': 'true'})
            return web.Response(text='healthy local fixture')
        app = web.Application()
        app.router.add_route('*', '/{path:.*}', handle)
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, '127.0.0.1', 0)
        await site.start()
        self.base = 'http://127.0.0.1:' + str(site._server.sockets[0].getsockname()[1])

    async def asyncTearDown(self):
        await self.runner.cleanup()

    async def test_http_up(self):
        result, body, _ = await UptimeScanner().check_target(TargetSite('local', 'Local', self.base))
        self.assertTrue(result.is_up)
        self.assertIn('healthy', body)

    async def test_http_down(self):
        result, _, _ = await UptimeScanner().check_target(TargetSite('local', 'Local', self.base + '/down'))
        self.assertFalse(result.is_up)
        self.assertEqual(result.status_code, 503)

    async def test_missing_keyword(self):
        result, _, _ = await UptimeScanner().check_target(TargetSite('local', 'Local', self.base, expected_content_keywords=['absent']))
        self.assertFalse(result.is_up)
        self.assertIn('absent', result.error_message)

    async def test_cors(self):
        findings = await SecurityScanner().test_cors_misconfiguration(self.base + '/cors')
        self.assertEqual(findings[0].severity, 'CRITICAL')

    async def test_spa_filter(self):
        self.assertEqual(await SecurityScanner().probe_sensitive_paths(self.base), [])

    async def test_headers(self):
        scanner = SecurityScanner()
        self.assertEqual(len(await scanner.audit_headers({})), len(SECURITY_HEADERS))
        self.assertEqual(await scanner.audit_headers({name: 'value' for name in SECURITY_HEADERS}), [])

    async def test_disabled_discord(self):
        self.assertFalse(await DiscordNotifier({'enabled': False})._post_embed({}))

    async def test_monitor_down_and_recovery(self):
        with patch('onyxops.core.monitor.IncidentReporter'):
            monitor = SentinelMonitor({'targets': [{'id': 'local', 'name': 'Local', 'url': self.base}], 'notifications': {'enabled': False}})
        target = monitor.targets[0]
        failed = UptimeResult('local', self.base, datetime.now(timezone.utc), False, status_code=503)
        recovered = UptimeResult('local', self.base, datetime.now(timezone.utc), True, status_code=200)
        monitor.uptime_scanner.check_target = AsyncMock(side_effect=[(failed, '', {}), (recovered, '', {})])
        monitor.run_deep_scan = AsyncMock()
        await monitor.check_single_target(target)
        self.assertFalse(monitor.state['local']['is_up'])
        await monitor.check_single_target(target)
        self.assertTrue(monitor.state['local']['is_up'])
        self.assertEqual(monitor.state['local']['uptime_pct'], 50)

    async def test_multiple_email_recipients(self):
        notifier = EmailNotifier({
            'enabled': True,
            'smtp_host': 'smtp.gmail.com',
            'username': 'user@gmail.com',
            'password': 'password',
            'to_addresses': [' dev1@example.com ', 'dev2@example.com', '  ']
        })
        self.assertEqual(notifier.to_addresses, ['dev1@example.com', 'dev2@example.com'])

        single_str_notifier = EmailNotifier({'to_addresses': ' devsolo@example.com '})
        self.assertEqual(single_str_notifier.to_addresses, ['devsolo@example.com'])

    async def test_multiple_sms_recipients(self):
        notifier = SMSNotifier({
            'enabled': True,
            'provider': 'twilio',
            'twilio': {
                'account_sid': 'AC123',
                'auth_token': 'secret',
                'from_number': '+1234567890',
                'to_numbers': [' +19876543210 ', '+15555555555', '']
            }
        })
        dispatched_numbers = []
        async def mock_send(to_num, msg):
            dispatched_numbers.append(to_num)
            return True

        notifier._send_twilio_sms = mock_send
        ok = await notifier._dispatch_to_all('Test message')
        self.assertTrue(ok)
        self.assertEqual(dispatched_numbers, ['+19876543210', '+15555555555'])


if __name__ == '__main__':
    unittest.main()
