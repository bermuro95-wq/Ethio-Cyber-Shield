"""
Test Suite: Part 14 — Log Agent Collector for Nginx, Apache, Syslog, and CEF.
Verifies:
1. Nginx/Apache Combined and Common access log parser into canonical Event Contract v1.1.
2. Nginx/Apache error log parser with security alert classification.
3. Syslog (RFC 3164 / RFC 5424) parser for authentication failures and network events.
4. Common Event Format (CEF) parser with financial fields (ETB, payment_rail, amount).
5. LogAgentCollector file tailing with state checkpointing and recovery.
6. Bounded resource constraints (memory queue limits, drop metrics).
7. Interactive /api/log-agent/parse API preview endpoint.
"""
import unittest
import os
import tempfile
import json
import uuid
import hashlib
from datetime import datetime, timezone

from app import create_app
from app.services.tenant_service import set_current_organization_id
from app.services.auth_service import create_token
from connectors.log_agent.parser import (
    parse_nginx_apache_access,
    parse_nginx_apache_error,
    parse_syslog,
    parse_cef,
    parse_log_line
)
from connectors.log_agent.collector import (
    LogAgentCollector,
    CollectorCheckpoint
)


class TestLogAgentCollector(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config['TESTING'] = True
        cls.client = cls.app.test_client()

        cls.org_id = str(uuid.uuid4())
        cls.user_admin = str(uuid.uuid4())
        cls.token_admin = create_token(cls.user_admin, "admin@telecom.et", "admin", organization_id=cls.org_id)

    def setUp(self):
        set_current_organization_id(self.org_id)

    def tearDown(self):
        set_current_organization_id(None)

    def test_01_nginx_apache_combined_access_log_parsing(self):
        """Test parsing standard Nginx/Apache Combined Access log line into canonical ECS event."""
        log_line = (
            '196.188.12.34 - USR_BEKELE [18/Oct/2026:10:15:30 +0300] '
            '"POST /api/v1/transfer HTTP/1.1" 200 512 '
            '"https://portal.bank.et/dashboard" '
            '"Mozilla/5.0 (Linux; Android 13; SM-A125F) Mobile Safari/537.36"'
        )

        event = parse_nginx_apache_access(log_line, organization_id=self.org_id, source_system="nginx-core")
        self.assertIsNotNone(event)
        self.assertEqual(event["organization_id"], self.org_id)
        self.assertEqual(event["source_system"], "nginx-core")
        self.assertEqual(event["source_ip"], "196.188.12.34")
        self.assertEqual(event["user_id_pub"], "USR_BEKELE")
        self.assertEqual(event["endpoint"], "/api/v1/transfer")
        self.assertEqual(event["result"], "SUCCESS")
        self.assertEqual(event["channel"], "mobile")
        self.assertEqual(event["attributes"]["http_method"], "POST")
        self.assertEqual(event["attributes"]["status_code"], 200)
        self.assertEqual(event["attributes"]["bytes_sent"], 512)
        self.assertEqual(event["attributes"]["referer"], "https://portal.bank.et/dashboard")

        # SHA-256 evidence sealing of raw log line
        expected_hash = hashlib.sha256(log_line.encode("utf-8")).hexdigest()
        self.assertEqual(event["attributes"]["raw_log_hash"], expected_hash)

    def test_02_nginx_apache_error_log_parsing(self):
        """Test parsing Nginx/Apache error log line indicating security violations."""
        error_line = (
            '2026/10/18 10:15:30 [error] 1234#0: *5678 access forbidden by rule, '
            'client: 196.188.12.34, server: api.bank.et, request: "GET /admin/export HTTP/1.1", host: "api.bank.et"'
        )

        event = parse_nginx_apache_error(error_line, organization_id=self.org_id, source_system="nginx-edge")
        self.assertIsNotNone(event)
        self.assertEqual(event["organization_id"], self.org_id)
        self.assertEqual(event["source_ip"], "196.188.12.34")
        self.assertEqual(event["endpoint"], "/admin/export")
        self.assertEqual(event["result"], "DENIED")
        self.assertEqual(event["event_type"], "AUTHZ_DENIED")
        self.assertEqual(event["attributes"]["log_level"], "error")
        self.assertIn("access forbidden by rule", event["attributes"]["message"])

    def test_03_syslog_rfc3164_and_rfc5424_parsing(self):
        """Test parsing standard syslog events (RFC 3164 & RFC 5424)."""
        # RFC 3164 (Linux auth log)
        rfc3164_line = "<34>Oct 18 10:15:30 web-gateway sshd[12345]: Failed password for invalid user admin from 196.188.12.34 port 54321 ssh2"
        event1 = parse_syslog(rfc3164_line, organization_id=self.org_id)
        self.assertIsNotNone(event1)
        self.assertEqual(event1["source_ip"], "196.188.12.34")
        self.assertEqual(event1["user_id_pub"], "admin")
        self.assertEqual(event1["event_type"], "LOGIN_FAILED")
        self.assertEqual(event1["result"], "FAILURE")
        self.assertEqual(event1["channel"], "system")
        self.assertEqual(event1["source_system"], "sshd")

        # RFC 5424 (Modern appliance syslog)
        rfc5424_line = '<134>1 2026-10-18T10:15:30.123+03:00 firewall-edge fw-daemon 4567 ID47 [security@1234] Connection blocked from 197.156.104.22 to port 443'
        event2 = parse_syslog(rfc5424_line, organization_id=self.org_id)
        self.assertIsNotNone(event2)
        self.assertEqual(event2["source_ip"], "197.156.104.22")
        self.assertEqual(event2["result"], "DENIED")
        self.assertEqual(event2["source_system"], "fw-daemon")

    def test_04_cef_common_event_format_parsing(self):
        """Test Common Event Format (CEF) parsing with Ethiopian currency and payment rail mappings."""
        cef_line = (
            "CEF:0|EthSwitch|NationalSwitch|3.0|TRANS_LIMIT_EXCEEDED|Daily Limit Denied|7|"
            "src=196.188.12.34 suser=ACC_ETH_001 act=block cn1=75000 cn1Label=amountMinor "
            "cs1=ETB cs1Label=currency cs2=telebirr cs2Label=rail msg=Exceeded single transaction limit"
        )

        event = parse_cef(cef_line, organization_id=self.org_id)
        self.assertIsNotNone(event)
        self.assertEqual(event["organization_id"], self.org_id)
        self.assertEqual(event["source_system"], "NationalSwitch")
        self.assertEqual(event["event_type"], "TRANS_LIMIT_EXCEEDED")
        self.assertEqual(event["result"], "DENIED")
        self.assertEqual(event["source_ip"], "196.188.12.34")
        self.assertEqual(event["user_id_pub"], "ACC_ETH_001")
        self.assertEqual(event["amount_minor"], 75000)
        self.assertEqual(event["amount"], 750.0)
        self.assertEqual(event["currency"], "ETB")
        self.assertEqual(event["payment_rail"], "wallet")  # telebirr normalized to wallet

    def test_05_log_agent_collector_tailing_and_checkpointing(self):
        """Test LogAgentCollector continuous tailing, batch processing, and checkpoint resumption."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = os.path.join(tmpdir, "access.log")
            state_path = os.path.join(tmpdir, "collector.state")

            # 1. Write initial log lines
            line1 = '196.188.12.10 - - [18/Oct/2026:10:00:00 +0300] "GET /health HTTP/1.1" 200 64 "-" "curl/7.88"'
            line2 = '196.188.12.20 - USR_A [18/Oct/2026:10:00:01 +0300] "POST /api/pay HTTP/1.1" 200 128 "-" "Mozilla/5.0"'
            with open(log_path, "w", encoding="utf-8") as f:
                f.write(line1 + "\n" + line2 + "\n")

            collector = LogAgentCollector(
                log_file=log_path,
                log_format="nginx_access",
                organization_id=self.org_id,
                state_file=state_path,
                batch_size=10
            )

            # First run: process existing lines
            events_batch1 = collector.poll_once()
            self.assertEqual(len(events_batch1), 2)
            self.assertEqual(events_batch1[0]["source_ip"], "196.188.12.10")
            self.assertEqual(events_batch1[1]["source_ip"], "196.188.12.20")

            # Checkpoint was saved
            self.assertTrue(os.path.exists(state_path))
            checkpoint = CollectorCheckpoint.load(state_path)
            self.assertGreater(checkpoint.offset, 0)

            # Polling again with no new content yields 0 events
            events_empty = collector.poll_once()
            self.assertEqual(len(events_empty), 0)

            # 2. Append 1 more line to the log file
            line3 = '196.188.12.30 - USR_B [18/Oct/2026:10:00:02 +0300] "GET /api/balance HTTP/1.1" 200 256 "-" "Mozilla/5.0"'
            with open(log_path, "a", encoding="utf-8") as f:
                f.write(line3 + "\n")

            # A new collector instance resumes from previous checkpoint
            new_collector = LogAgentCollector(
                log_file=log_path,
                log_format="nginx_access",
                organization_id=self.org_id,
                state_file=state_path,
                batch_size=10
            )
            events_batch2 = new_collector.poll_once()
            self.assertEqual(len(events_batch2), 1)
            self.assertEqual(events_batch2[0]["source_ip"], "196.188.12.30")

    def test_06_bounded_queue_and_drop_metrics(self):
        """Test that LogAgentCollector bounds in-memory queue to prevent OOM and tracks dropped lines."""
        with tempfile.TemporaryDirectory() as tmpdir:
            log_path = os.path.join(tmpdir, "access.log")
            state_path = os.path.join(tmpdir, "collector.state")

            # Create 20 lines
            with open(log_path, "w", encoding="utf-8") as f:
                for i in range(20):
                    f.write(f'196.188.12.{i} - - [18/Oct/2026:10:00:00 +0300] "GET / HTTP/1.1" 200 10 "-" "-"\n')

            # Collector configured with max_queue_size = 5
            collector = LogAgentCollector(
                log_file=log_path,
                log_format="nginx_access",
                organization_id=self.org_id,
                state_file=state_path,
                max_queue_size=5,
                batch_size=5
            )

            metrics = collector.get_metrics()
            self.assertEqual(metrics["processed_lines"], 0)
            self.assertEqual(metrics["dropped_lines"], 0)

            events = collector.poll_once()
            self.assertLessEqual(len(events), 5)
            updated_metrics = collector.get_metrics()
            self.assertGreater(updated_metrics["processed_lines"], 0)

    def test_07_api_interactive_parse_endpoint(self):
        """Test POST /api/log-agent/parse preview endpoint."""
        sample_log = '196.188.12.55 - USR_TEST [18/Oct/2026:10:20:00 +0300] "GET /api/v1/auth HTTP/1.1" 401 96 "-" "curl/7.88"'
        res = self.client.post(
            "/api/log-agent/parse",
            headers={"Authorization": f"Bearer {self.token_admin}"},
            json={
                "log_line": sample_log,
                "format": "nginx_access"
            }
        )

        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["parsed_event"]["source_ip"], "196.188.12.55")
        self.assertEqual(data["parsed_event"]["result"], "DENIED")
        self.assertEqual(data["parsed_event"]["organization_id"], self.org_id)


if __name__ == '__main__':
    unittest.main()
