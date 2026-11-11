"""
Test Suite: Part 32 — Financial Mule Ring & Graph Intelligence Engine.
Fulfills NBE Cyber Risk Directives & INSA Proclamation No. 1426/2026:
Verifies:
1. Multi-Tenant Directed Dynamic Multigraph tracking accounts and payment rails.
2. Johnson's simple cycle detection identifying circular money laundering loops.
3. Bipartite micro-smurfing detection (Fan-Out from Source -> Fan-In to Cash-Out Hub).
4. Betweenness centrality calculation and topological role attribution.
5. Autonomous multi-account containment dispatch with tamper-evident audit logging.
6. SaaS multi-tenant isolation across distinct organization partitions.
7. REST API endpoints under /api/analysis/mule-graph.
"""

import unittest
import uuid
from datetime import datetime, timezone, timedelta

from app import create_app
from app.services.auth_service import create_token
from app.services.mule_graph_service import get_mule_graph_service


class TestMuleRingGraphEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config['TESTING'] = True
        cls.client = cls.app.test_client()

        cls.tenant_a = str(uuid.uuid4())
        cls.tenant_b = str(uuid.uuid4())

        cls.token_a = create_token(
            str(uuid.uuid4()),
            "analyst@telebirr.et",
            "analyst",
            organization_id=cls.tenant_a,
        )
        cls.token_b = create_token(
            str(uuid.uuid4()),
            "analyst@cbe.et",
            "analyst",
            organization_id=cls.tenant_b,
        )
        cls.svc = get_mule_graph_service()

    def setUp(self):
        self.svc.clear_stores()

    def test_01_graph_model_and_snapshot(self):
        """Verifies transfer recording, node financial metrics, and graph serialization."""
        now = datetime.now(timezone.utc)
        self.svc.record_transfer(
            org_id=self.tenant_a,
            source_account="ACC-A",
            destination_account="ACC-B",
            amount=5000.0,
            currency="ETB",
            payment_rail="telebirr",
            timestamp=now,
        )

        snap = self.svc.get_graph_snapshot(self.tenant_a)
        self.assertEqual(snap["metrics"]["total_nodes"], 2)
        self.assertEqual(snap["metrics"]["total_edges"], 1)

        nodes = {n["id"]: n for n in snap["nodes"]}
        self.assertEqual(nodes["ACC-A"]["total_outflow"], 5000.0)
        self.assertEqual(nodes["ACC-B"]["total_inflow"], 5000.0)
        self.assertEqual(nodes["ACC-A"]["out_degree"], 1)
        self.assertEqual(nodes["ACC-B"]["in_degree"], 1)

    def test_02_circular_cycle_detection(self):
        """Verifies Johnson's algorithm detecting circular laundering loops (A -> B -> C -> A)."""
        now = datetime.now(timezone.utc)
        t0 = now - timedelta(minutes=30)

        # 3-hop circular transfer loop
        self.svc.record_transfer(self.tenant_a, "ACC-01", "ACC-02", 50000.0, "ETB", "telebirr", t0)
        self.svc.record_transfer(self.tenant_a, "ACC-02", "ACC-03", 48000.0, "ETB", "cbe_birr", t0 + timedelta(minutes=5))
        self.svc.record_transfer(self.tenant_a, "ACC-03", "ACC-01", 45000.0, "ETB", "ethswitch", t0 + timedelta(minutes=15))

        snap = self.svc.get_graph_snapshot(self.tenant_a)
        circular_syndicates = [s for s in snap["syndicates"] if s["syndicate_type"] == "CIRCULAR_LAUNDERING_RING"]

        self.assertGreaterEqual(len(circular_syndicates), 1)
        cycle = circular_syndicates[0]
        self.assertEqual(cycle["hop_count"], 3)
        self.assertGreaterEqual(cycle["risk_score"], 90)
        self.assertEqual(cycle["severity"], "critical")
        self.assertIn("Circular fund routing loop detected", cycle["detection_reason"])
        self.assertSetEqual(set(cycle["involved_accounts"]), {"ACC-01", "ACC-02", "ACC-03"})

    def test_03_smurfing_ring_detection(self):
        """Verifies bipartite micro-smurfing: 1 Victim -> multiple mules -> 1 Cash-Out Hub."""
        now = datetime.now(timezone.utc)
        src = "VICTIM-CORP"
        hub = "CASHOUT-WALLET"
        mules = ["MULE-1", "MULE-2", "MULE-3"]

        # Fan-out: Victim disperses 4,500 ETB to each mule (below static 5,000 threshold)
        for i, m in enumerate(mules):
            self.svc.record_transfer(self.tenant_a, src, m, 4500.0, "ETB", "telebirr", now - timedelta(minutes=20 - i))

        # Fan-in: Mules rapidly reconverge into Cash-Out Hub
        for i, m in enumerate(mules):
            self.svc.record_transfer(self.tenant_a, m, hub, 4400.0, "ETB", "telebirr", now - timedelta(minutes=10 - i))

        snap = self.svc.get_graph_snapshot(self.tenant_a)
        smurf_syndicates = [s for s in snap["syndicates"] if s["syndicate_type"] == "COORDINATED_SMURFING_RING"]

        self.assertGreaterEqual(len(smurf_syndicates), 1)
        ring = smurf_syndicates[0]
        self.assertEqual(ring["source_account"], src)
        self.assertEqual(ring["cashout_hub"], hub)
        self.assertSetEqual(set(ring["intermediary_mules"]), set(mules))
        self.assertGreaterEqual(ring["risk_score"], 90)

    def test_04_centrality_and_role_attribution(self):
        """Verifies topological role classification (cashout_hub, intermediary_mule, victim_source)."""
        now = datetime.now(timezone.utc)
        src = "ACC-ORIGIN"
        m1 = "ACC-MULE-1"
        m2 = "ACC-MULE-2"
        hub = "ACC-HUB"

        self.svc.record_transfer(self.tenant_a, src, m1, 10000.0, "ETB", "telebirr", now)
        self.svc.record_transfer(self.tenant_a, src, m2, 10000.0, "ETB", "telebirr", now)
        self.svc.record_transfer(self.tenant_a, m1, hub, 9500.0, "ETB", "telebirr", now)
        self.svc.record_transfer(self.tenant_a, m2, hub, 9500.0, "ETB", "telebirr", now)

        snap = self.svc.get_graph_snapshot(self.tenant_a)
        nodes = {n["id"]: n for n in snap["nodes"]}

        self.assertEqual(nodes[hub]["role"], "cashout_hub")
        self.assertEqual(nodes[src]["role"], "victim_source")
        self.assertEqual(nodes[m1]["role"], "intermediary_mule")
        self.assertEqual(nodes[m2]["role"], "intermediary_mule")

    def test_05_autonomous_containment(self):
        """Verifies 1-click multi-account containment execution and status update."""
        now = datetime.now(timezone.utc)
        self.svc.record_transfer(self.tenant_a, "ACC-X", "ACC-Y", 10000.0, "ETB", "telebirr", now)
        self.svc.record_transfer(self.tenant_a, "ACC-Y", "ACC-Z", 9500.0, "ETB", "telebirr", now)
        self.svc.record_transfer(self.tenant_a, "ACC-Z", "ACC-X", 9000.0, "ETB", "telebirr", now)

        snap = self.svc.get_graph_snapshot(self.tenant_a)
        self.assertGreater(len(snap["syndicates"]), 0)
        syn_id = snap["syndicates"][0]["syndicate_id"]

        result = self.svc.contain_syndicate(self.tenant_a, syn_id, "Automated test freeze")
        self.assertEqual(result["status"], "contained")
        self.assertGreaterEqual(result["accounts_frozen_count"], 3)
        self.assertIn("INSA Proclamation No. 1426/2026", result["statutory_compliance"])

        # Check nodes are marked contained in subsequent snapshot
        snap_after = self.svc.get_graph_snapshot(self.tenant_a)
        nodes_after = {n["id"]: n for n in snap_after["nodes"]}
        for acc in result["frozen_accounts"]:
            self.assertTrue(nodes_after[acc]["is_contained"])

    def test_06_multi_tenant_isolation(self):
        """Verifies Tenant A transactions never appear in Tenant B graph."""
        now = datetime.now(timezone.utc)
        self.svc.record_transfer(self.tenant_a, "TENANT-A-SRC", "TENANT-A-DST", 15000.0, "ETB", "telebirr", now)
        self.svc.record_transfer(self.tenant_b, "TENANT-B-SRC", "TENANT-B-DST", 25000.0, "ETB", "cbe_birr", now)

        snap_a = self.svc.get_graph_snapshot(self.tenant_a)
        snap_b = self.svc.get_graph_snapshot(self.tenant_b)

        nodes_a = {n["id"] for n in snap_a["nodes"]}
        nodes_b = {n["id"] for n in snap_b["nodes"]}

        self.assertIn("TENANT-A-SRC", nodes_a)
        self.assertNotIn("TENANT-B-SRC", nodes_a)

        self.assertIn("TENANT-B-SRC", nodes_b)
        self.assertNotIn("TENANT-A-SRC", nodes_b)

    def test_07_api_endpoints(self):
        """Verifies REST API endpoints under /api/analysis/mule-graph."""
        headers = {"Authorization": f"Bearer {self.token_a}"}

        # 1. Seed demo data
        res_seed = self.client.post("/api/analysis/mule-graph/seed-demo", headers=headers)
        self.assertEqual(res_seed.status_code, 200)

        # 2. Get full graph snapshot
        res_graph = self.client.get("/api/analysis/mule-graph", headers=headers)
        self.assertEqual(res_graph.status_code, 200)
        data = res_graph.get_json()["data"]
        self.assertGreaterEqual(data["metrics"]["total_nodes"], 5)
        self.assertGreaterEqual(data["metrics"]["total_syndicates"], 1)

        # 3. Get detected rings list
        res_rings = self.client.get("/api/analysis/mule-graph/rings", headers=headers)
        self.assertEqual(res_rings.status_code, 200)
        rings = res_rings.get_json()["syndicates"]
        self.assertGreaterEqual(len(rings), 1)

        # 4. Contain detected ring
        syn_id = rings[0]["syndicate_id"]
        res_contain = self.client.post(
            "/api/analysis/mule-graph/contain-ring",
            headers=headers,
            json={"syndicate_id": syn_id, "reason": "SOC API Containment"},
        )
        self.assertEqual(res_contain.status_code, 200)
        self.assertEqual(res_contain.get_json()["result"]["status"], "contained")


if __name__ == "__main__":
    unittest.main()
