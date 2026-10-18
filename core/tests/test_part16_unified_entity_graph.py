"""
Test Suite: Part 16 — Unified Entity Graph, Linkage Model, and Graph-Based Fraud Detection.
Verifies:
1. Automatic entity extraction and linkage from telemetry events (account, device, IP, session, beneficiary, phone_hash).
2. Continuous first_seen_at / last_seen_at and event/link counter updates.
3. Breadth-first graph traversal (depth 1 & 2) generating network-ready node/edge structures.
4. Shared entity detection: device sharing (credential stuffing) and beneficiary concentration (mule rings).
5. Transitive graph risk synthesis.
6. Strict multi-tenant isolation (Tenant A cannot see Tenant B's nodes or links).
7. Entity Graph REST API endpoints.
"""
import unittest
import uuid
import hashlib
from datetime import datetime, timezone

from app import create_app
from app.services.tenant_service import set_current_organization_id
from app.services.auth_service import create_token
from app.services.entity_graph_service import (
    record_event_entities,
    get_entity,
    get_entity_links,
    get_entity_graph,
    find_shared_entities,
    calculate_graph_risk,
    tag_entity,
    clear_entity_graph_stores
)


class TestUnifiedEntityGraph(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config['TESTING'] = True
        cls.client = cls.app.test_client()

        cls.org_a = str(uuid.uuid4())
        cls.org_b = str(uuid.uuid4())

        cls.user_admin_a = str(uuid.uuid4())
        cls.user_admin_b = str(uuid.uuid4())

        cls.token_admin_a = create_token(cls.user_admin_a, "admin@bank-a.et", "admin", organization_id=cls.org_a)
        cls.token_admin_b = create_token(cls.user_admin_b, "admin@bank-b.et", "admin", organization_id=cls.org_b)

    def setUp(self):
        set_current_organization_id(self.org_a)
        clear_entity_graph_stores()

    def tearDown(self):
        set_current_organization_id(None)

    def test_01_record_event_extracts_entities_and_links(self):
        """Test that ingesting an event extracts all entity nodes and establishes semantic links."""
        account_id = f"ACC_{uuid.uuid4().hex[:8]}"
        device_id = f"dfp_{uuid.uuid4().hex[:8]}"
        ip_addr = "196.188.12.34"
        session_id = f"sess_{uuid.uuid4().hex[:8]}"
        dest_hash = hashlib.sha256(b"DEST_MULE_1").hexdigest()
        phone_hash = hashlib.sha256(b"+251911223344").hexdigest()

        event = {
            "event_id": f"ev_{uuid.uuid4().hex[:8]}",
            "organization_id": self.org_a,
            "event_type": "TRANSFER_COMPLETED",
            "occurred_at": "2026-10-18T10:00:00Z",
            "account_id_pub": account_id,
            "device_fingerprint": device_id,
            "source_ip": ip_addr,
            "session_id_pub": session_id,
            "counterparty_ref_hash": dest_hash,
            "msisdn_hash": phone_hash,
            "amount": 15000.0,
            "currency": "ETB"
        }

        record_event_entities(event)

        # 1. Verify entity nodes
        node_acc = get_entity("account", account_id, org_id=self.org_a)
        self.assertIsNotNone(node_acc)
        self.assertEqual(node_acc["entity_type"], "account")
        self.assertEqual(node_acc["entity_value"], account_id)
        self.assertEqual(node_acc["event_count"], 1)

        node_dev = get_entity("device", device_id, org_id=self.org_a)
        self.assertIsNotNone(node_dev)
        self.assertEqual(node_dev["entity_value"], device_id)

        node_ip = get_entity("ip", ip_addr, org_id=self.org_a)
        self.assertIsNotNone(node_ip)

        node_bene = get_entity("beneficiary", dest_hash, org_id=self.org_a)
        self.assertIsNotNone(node_bene)

        # 2. Verify semantic links
        links_acc = get_entity_links("account", account_id, org_id=self.org_a)
        link_types = {l["link_type"] for l in links_acc}
        self.assertIn("used_device", link_types)
        self.assertIn("connected_from_ip", link_types)
        self.assertIn("transferred_to", link_types)
        self.assertIn("registered_phone", link_types)

    def test_02_repeated_events_increment_counts_and_update_timestamps(self):
        """Test repeated events increment event_count and link_count and advance last_seen_at."""
        account_id = f"ACC_{uuid.uuid4().hex[:8]}"
        device_id = f"dfp_{uuid.uuid4().hex[:8]}"

        for i in range(3):
            record_event_entities({
                "event_id": f"ev_{i}_{uuid.uuid4().hex[:6]}",
                "organization_id": self.org_a,
                "event_type": "LOGIN_SUCCESS",
                "occurred_at": f"2026-10-18T10:0{i}:00Z",
                "account_id_pub": account_id,
                "device_fingerprint": device_id,
                "source_ip": "196.188.12.10"
            })

        node_acc = get_entity("account", account_id, org_id=self.org_a)
        self.assertEqual(node_acc["event_count"], 3)
        self.assertEqual(node_acc["first_seen_at"], "2026-10-18T10:00:00Z")
        self.assertEqual(node_acc["last_seen_at"], "2026-10-18T10:02:00Z")

        node_dev = get_entity("device", device_id, org_id=self.org_a)
        self.assertEqual(node_dev["event_count"], 3)

    def test_03_graph_traversal_depth_1_and_2(self):
        """Test breadth-first graph traversal for single and multi-hop neighborhood extraction."""
        acc1 = f"ACC_HUB_{uuid.uuid4().hex[:6]}"
        dev1 = f"DEV_SHARED_{uuid.uuid4().hex[:6]}"
        acc2 = f"ACC_MULE_{uuid.uuid4().hex[:6]}"
        ip1 = "197.156.104.50"

        # Account 1 uses Device 1 and IP 1
        record_event_entities({
            "event_id": f"ev_{uuid.uuid4().hex[:6]}",
            "organization_id": self.org_a,
            "account_id_pub": acc1,
            "device_fingerprint": dev1,
            "source_ip": ip1
        })

        # Account 2 also uses Device 1 (shared device)
        record_event_entities({
            "event_id": f"ev_{uuid.uuid4().hex[:6]}",
            "organization_id": self.org_a,
            "account_id_pub": acc2,
            "device_fingerprint": dev1,
            "source_ip": "196.188.12.88"
        })

        # Depth 1 from Account 1: expects dev1 and ip1
        graph_d1 = get_entity_graph("account", acc1, org_id=self.org_a, depth=1)
        node_ids_d1 = {n["id"] for n in graph_d1["nodes"]}
        self.assertIn(f"account:{acc1}", node_ids_d1)
        self.assertIn(f"device:{dev1}", node_ids_d1)
        self.assertIn(f"ip:{ip1}", node_ids_d1)
        self.assertNotIn(f"account:{acc2}", node_ids_d1)  # Acc2 is 2 hops away

        # Depth 2 from Account 1: expects Acc2 through shared dev1
        graph_d2 = get_entity_graph("account", acc1, org_id=self.org_a, depth=2)
        node_ids_d2 = {n["id"] for n in graph_d2["nodes"]}
        self.assertIn(f"account:{acc2}", node_ids_d2)
        self.assertGreater(graph_d2["summary"]["total_nodes"], graph_d1["summary"]["total_nodes"])

    def test_04_shared_entities_mule_and_credential_stuffing_detection(self):
        """Test detecting shared devices across multiple accounts and mule aggregation rings."""
        device_id = f"dfp_stuffing_{uuid.uuid4().hex[:6]}"
        mule_bene = hashlib.sha256(b"MULE_AGGREGATOR_01").hexdigest()

        # 4 distinct accounts use the same device
        for i in range(4):
            record_event_entities({
                "event_id": f"ev_stuff_{i}_{uuid.uuid4().hex[:6]}",
                "organization_id": self.org_a,
                "account_id_pub": f"VICTIM_ACC_{i}",
                "device_fingerprint": device_id,
                "counterparty_ref_hash": mule_bene,
                "source_ip": "196.188.12.34"
            })

        # 1. Device sharing report
        shared_dev = find_shared_entities("device", device_id, org_id=self.org_a)
        self.assertTrue(shared_dev["is_shared"])
        self.assertEqual(shared_dev["shared_count"], 4)
        self.assertEqual(len(shared_dev["connected_accounts"]), 4)

        # 2. Beneficiary mule ring aggregation
        shared_bene = find_shared_entities("beneficiary", mule_bene, org_id=self.org_a)
        self.assertTrue(shared_bene["is_shared"])
        self.assertEqual(shared_bene["shared_count"], 4)
        self.assertEqual(len(shared_bene["sending_accounts"]), 4)

    def test_05_graph_risk_propagation(self):
        """Test transitive risk propagation from compromised accounts to shared devices."""
        acc_bad = f"ACC_COMPROMISED_{uuid.uuid4().hex[:6]}"
        dev_bad = f"DEV_LINKED_{uuid.uuid4().hex[:6]}"

        record_event_entities({
            "event_id": f"ev_{uuid.uuid4().hex[:6]}",
            "organization_id": self.org_a,
            "account_id_pub": acc_bad,
            "device_fingerprint": dev_bad,
            "source_ip": "196.188.12.99"
        })

        # Initially clean risk
        risk_before = calculate_graph_risk("device", dev_bad, org_id=self.org_a)
        self.assertEqual(risk_before["risk_score"], 0)

        # Analyst or detection engine tags account as compromised
        tag_entity("account", acc_bad, tag="compromised", org_id=self.org_a)

        # Risk propagates to device
        risk_after = calculate_graph_risk("device", dev_bad, org_id=self.org_a)
        self.assertGreaterEqual(risk_after["risk_score"], 50)
        self.assertTrue(any("compromised" in r.lower() for r in risk_after["reasons"]))

    def test_06_strict_multi_tenant_isolation(self):
        """Test that Tenant A and Tenant B maintain strictly isolated entity graphs."""
        shared_ip = "196.188.12.100"
        acc_a = "ACC_TENANT_A"
        acc_b = "ACC_TENANT_B"

        # Tenant A event
        record_event_entities({
            "event_id": f"ev_a_{uuid.uuid4().hex[:6]}",
            "organization_id": self.org_a,
            "account_id_pub": acc_a,
            "source_ip": shared_ip
        })

        # Tenant B event
        record_event_entities({
            "event_id": f"ev_b_{uuid.uuid4().hex[:6]}",
            "organization_id": self.org_b,
            "account_id_pub": acc_b,
            "source_ip": shared_ip
        })

        # Tenant A query for IP only returns Tenant A's account
        links_a = get_entity_links("ip", shared_ip, org_id=self.org_a)
        values_a = {l["target_value"] for l in links_a}
        self.assertIn(acc_a, values_a)
        self.assertNotIn(acc_b, values_a)

        # Tenant B query for IP only returns Tenant B's account
        links_b = get_entity_links("ip", shared_ip, org_id=self.org_b)
        values_b = {l["target_value"] for l in links_b}
        self.assertIn(acc_b, values_b)
        self.assertNotIn(acc_a, values_b)

    def test_07_rest_api_endpoints(self):
        """Test REST API endpoints for entities, graphs, and shared entity detection."""
        acc_id = f"ACC_API_{uuid.uuid4().hex[:6]}"
        dev_id = f"DEV_API_{uuid.uuid4().hex[:6]}"

        record_event_entities({
            "event_id": f"ev_api_{uuid.uuid4().hex[:6]}",
            "organization_id": self.org_a,
            "account_id_pub": acc_id,
            "device_fingerprint": dev_id,
            "source_ip": "196.188.12.20"
        })

        # 1. GET /api/entities/<type>/<value>
        res_entity = self.client.get(
            f"/api/entities/account/{acc_id}",
            headers={"Authorization": f"Bearer {self.token_admin_a}"}
        )
        self.assertEqual(res_entity.status_code, 200)
        data_ent = res_entity.get_json()
        self.assertEqual(data_ent["entity_value"], acc_id)

        # 2. GET /api/entities/<type>/<value>/graph
        res_graph = self.client.get(
            f"/api/entities/account/{acc_id}/graph?depth=1",
            headers={"Authorization": f"Bearer {self.token_admin_a}"}
        )
        self.assertEqual(res_graph.status_code, 200)
        data_graph = res_graph.get_json()
        self.assertIn("nodes", data_graph)
        self.assertIn("edges", data_graph)
        self.assertGreaterEqual(len(data_graph["nodes"]), 2)

        # 3. GET /api/entities/<type>/<value>/shared
        res_shared = self.client.get(
            f"/api/entities/device/{dev_id}/shared",
            headers={"Authorization": f"Bearer {self.token_admin_a}"}
        )
        self.assertEqual(res_shared.status_code, 200)
        data_shared = res_shared.get_json()
        self.assertEqual(data_shared["entity_value"], dev_id)

        # 4. POST /api/entities/<type>/<value>/tag
        res_tag = self.client.post(
            f"/api/entities/account/{acc_id}/tag",
            headers={"Authorization": f"Bearer {self.token_admin_a}"},
            json={"tag": "high_net_worth"}
        )
        self.assertEqual(res_tag.status_code, 200)
        data_tag = res_tag.get_json()
        self.assertIn("high_net_worth", data_tag.get("tags", []))


if __name__ == '__main__':
    unittest.main()
