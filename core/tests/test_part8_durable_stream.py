"""
Test Suite Part 8: Durable Ingest Queue & Sliding-Window Stream Engine.
Verifies Phase 1.4 requirements:
- Redis Streams / durable queue abstraction
- Consumer groups and worker processing
- Sliding-window state tracking (account, IP, device)
- Dead-letter handling on repeated failures
- Tenant isolation across streams and windows
- Graceful degradation when Redis is offline
"""
import unittest
import time
import uuid
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock

from app.services.stream_service import (
    StreamService,
    DurableQueueBackend,
    get_stream_service
)
from app.services.tenant_service import DEFAULT_ORGANIZATION_ID


class TestPart8DurableStream(unittest.TestCase):
    def setUp(self):
        self.org_a = "00000000-0000-0000-0000-000000000001"
        self.org_b = "99999999-9999-9999-9999-999999999999"
        self.service = StreamService()

    def test_1_stream_enqueue_and_consume_fallback(self):
        """Verifies enqueue and consumer group consumption works with durable fallback."""
        event_payload = {
            'event_id': f'evt-stream-{uuid.uuid4().hex[:8]}',
            'organization_id': self.org_a,
            'event_type': 'LOGIN_FAILED',
            'occurred_at': datetime.now(timezone.utc).isoformat(),
            'source_ip': '196.188.10.1',
            'account_id': 'ACC_TEST_001',
            'device_id': 'DEV_001'
        }

        # Enqueue event
        msg_id = self.service.enqueue_event(event_payload, org_id=self.org_a)
        self.assertIsNotNone(msg_id)

        # Consume via consumer
        messages = self.service.consume_batch(org_id=self.org_a, consumer_name="test_worker_1", count=10)
        self.assertGreaterEqual(len(messages), 1)

        found = any(m['payload'].get('event_id') == event_payload['event_id'] for m in messages)
        self.assertTrue(found, "Enqueued event was not found in consumer batch")

        # Ack messages
        for m in messages:
            self.service.ack_message(m['msg_id'], org_id=self.org_a)

    def test_2_sliding_window_indexing_and_lookup(self):
        """Verifies sliding window indexing by account, IP, and device within time windows."""
        acc_id = f"ACC_SW_{uuid.uuid4().hex[:6]}"
        ip_addr = "197.156.77.10"
        dev_id = f"DEV_SW_{uuid.uuid4().hex[:6]}"

        now = datetime.now(timezone.utc)
        # Event 1: 30 seconds ago
        ev1 = {
            'event_id': f'evt-1-{uuid.uuid4().hex[:6]}',
            'organization_id': self.org_a,
            'event_type': 'LOGIN_FAILED',
            'occurred_at': (now - timedelta(seconds=30)).isoformat(),
            'account_id': acc_id,
            'source_ip': ip_addr,
            'device_id': dev_id
        }
        # Event 2: 10 seconds ago
        ev2 = {
            'event_id': f'evt-2-{uuid.uuid4().hex[:6]}',
            'organization_id': self.org_a,
            'event_type': 'LOGIN_FAILED',
            'occurred_at': (now - timedelta(seconds=10)).isoformat(),
            'account_id': acc_id,
            'source_ip': ip_addr,
            'device_id': dev_id
        }
        # Event 3: 120 seconds ago (outside 60s window)
        ev3 = {
            'event_id': f'evt-3-{uuid.uuid4().hex[:6]}',
            'organization_id': self.org_a,
            'event_type': 'LOGIN_FAILED',
            'occurred_at': (now - timedelta(seconds=120)).isoformat(),
            'account_id': acc_id,
            'source_ip': ip_addr,
            'device_id': dev_id
        }

        self.service.index_sliding_window(ev1, org_id=self.org_a)
        self.service.index_sliding_window(ev2, org_id=self.org_a)
        self.service.index_sliding_window(ev3, org_id=self.org_a)

        # Query 60 second window for account
        recent_acc = self.service.get_sliding_window_events(
            org_id=self.org_a,
            account_id=acc_id,
            window_seconds=60,
            current_time=now
        )
        self.assertEqual(len(recent_acc), 2)
        event_ids = [e['event_id'] for e in recent_acc]
        self.assertIn(ev1['event_id'], event_ids)
        self.assertIn(ev2['event_id'], event_ids)
        self.assertNotIn(ev3['event_id'], event_ids)

        # Query 60 second window for IP
        recent_ip = self.service.get_sliding_window_events(
            org_id=self.org_a,
            source_ip=ip_addr,
            window_seconds=60,
            current_time=now
        )
        self.assertGreaterEqual(len(recent_ip), 2)

    def test_3_dead_letter_queue_and_retry(self):
        """Verifies messages that fail processing exceed retries and route to DLQ."""
        poison_event = {
            'event_id': f'evt-poison-{uuid.uuid4().hex[:6]}',
            'organization_id': self.org_a,
            'event_type': 'POISON_PILL',
            'corrupt': True
        }

        msg_id = self.service.enqueue_event(poison_event, org_id=self.org_a)

        # Simulate failures up to max retries (3)
        for attempt in range(3):
            self.service.record_failure(msg_id, org_id=self.org_a, error_reason="Simulated processing crash")

        # After max retries, message should be routed to dead-letter queue
        dlq_entries = self.service.get_dead_letter_queue(org_id=self.org_a)
        dlq_ids = [d.get('event_id') or d.get('payload', {}).get('event_id') for d in dlq_entries]
        self.assertIn(poison_event['event_id'], dlq_ids)

    def test_4_multi_tenancy_stream_isolation(self):
        """Verifies Tenant A's stream messages cannot be consumed by Tenant B."""
        event_org_a = {
            'event_id': f'evt-org-a-{uuid.uuid4().hex[:6]}',
            'organization_id': self.org_a,
            'event_type': 'LOGIN_FAILED',
            'account_id': 'ACC_SECRET_A'
        }
        event_org_b = {
            'event_id': f'evt-org-b-{uuid.uuid4().hex[:6]}',
            'organization_id': self.org_b,
            'event_type': 'LOGIN_FAILED',
            'account_id': 'ACC_SECRET_B'
        }

        self.service.enqueue_event(event_org_a, org_id=self.org_a)
        self.service.enqueue_event(event_org_b, org_id=self.org_b)

        # Tenant B consumer
        batch_b = self.service.consume_batch(org_id=self.org_b, consumer_name="worker_b", count=50)
        tenant_b_event_ids = [m['payload'].get('event_id') for m in batch_b]

        self.assertIn(event_org_b['event_id'], tenant_b_event_ids)
        self.assertNotIn(event_org_a['event_id'], tenant_b_event_ids)

        # Also verify sliding window isolation
        self.service.index_sliding_window(event_org_a, org_id=self.org_a)
        sw_b = self.service.get_sliding_window_events(org_id=self.org_b, account_id='ACC_SECRET_A', window_seconds=300)
        self.assertEqual(len(sw_b), 0, "Tenant B should not see Tenant A's sliding window events")

    def test_5_bounded_stream_backpressure(self):
        """Verifies stream respects maxlen bounds without unbounded memory consumption."""
        max_limit = 20
        bounded_service = StreamService(max_stream_len=max_limit)

        test_org = f"org-test-{uuid.uuid4().hex[:6]}"
        for i in range(35):
            bounded_service.enqueue_event({
                'event_id': f'evt-bulk-{i}',
                'seq': i
            }, org_id=test_org)

        stats = bounded_service.get_stream_stats(org_id=test_org)
        self.assertLessEqual(stats['stream_length'], max_limit + 5)


if __name__ == '__main__':
    unittest.main()
