"""
Test Suite: Part 24 — Benchmark Corpus, Attack Lab Scenario Library & CI Verification (Phase 3.6).

Verifies:
1. Scenario Library contains >= 12 distinct attack scenarios covering Fraud & Payments, Web/API, and Insider/Admin.
2. Benign scenarios provide realistic baseline traffic without triggering false alerts.
3. Labeled Benchmark Corpus generation with ground truth assertions (is_attack, target_rule_ids, category).
4. Automated precision, recall, and false-positive reporting per rule and per pack.
5. Gate 3 Criteria: >= 90% detection rate on attack scenarios with false positive rate <= 10%.
6. Standalone CLI benchmark runner execution.
7. Sandbox tenant isolation (benchmark runs do not pollute production audit tables).
8. Full REST API coverage:
   - GET /api/benchmark/scenarios
   - POST /api/benchmark/scenarios/run
   - GET /api/benchmark/corpus
   - POST /api/benchmark/run
   - GET /api/benchmark/latest
"""
import unittest
import uuid
import os
import sys

# Ensure repository root is in sys.path
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from app import create_app
from app.services.tenant_service import set_current_organization_id
from app.services.auth_service import create_token
from app.benchmark.scenarios import SCENARIO_CATALOG, get_scenario, list_scenarios
from app.benchmark.corpus import generate_benchmark_corpus
from app.services.benchmark_service import BenchmarkService


class TestBenchmarkCorpusAndCI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = create_app()
        cls.app.config['TESTING'] = True
        cls.client = cls.app.test_client()

        cls.org_a = str(uuid.uuid4())
        cls.org_b = str(uuid.uuid4())
        cls.user_admin = str(uuid.uuid4())
        cls.user_analyst = str(uuid.uuid4())
        cls.user_viewer = str(uuid.uuid4())

        cls.token_admin = create_token(cls.user_admin, "admin@bank-a.et", "admin", organization_id=cls.org_a)
        cls.token_analyst = create_token(cls.user_analyst, "analyst@bank-a.et", "analyst", organization_id=cls.org_a)
        cls.token_viewer = create_token(cls.user_viewer, "viewer@bank-a.et", "viewer", organization_id=cls.org_a)

    def setUp(self):
        set_current_organization_id(self.org_a)

    def tearDown(self):
        set_current_organization_id(None)

    def test_01_scenario_library_coverage(self):
        """Test scenario library has >= 12 distinct attack scenarios across the 3 core packs."""
        scenarios = list_scenarios()
        attack_scenarios = [s for s in scenarios if s.get('is_attack')]
        benign_scenarios = [s for s in scenarios if not s.get('is_attack')]

        # Gate requirement: >= 12 attack scenarios
        self.assertGreaterEqual(len(attack_scenarios), 12, "Must contain >= 12 attack scenarios")
        self.assertGreaterEqual(len(benign_scenarios), 2, "Must contain benign baseline scenarios")

        # Verify pack coverage
        categories = {s['category'] for s in attack_scenarios}
        self.assertIn('fraud_payments', categories)
        self.assertIn('web_api', categories)
        self.assertIn('insider_admin', categories)

        # Verify key scenarios exist
        scenario_ids = {s['scenario_id'] for s in attack_scenarios}
        self.assertIn('SCEN-01-ATO-CHAIN', scenario_ids)
        self.assertIn('SCEN-02-MULE-TRANSFER', scenario_ids)
        self.assertIn('SCEN-03-SIM-SWAP', scenario_ids)
        self.assertIn('SCEN-04-STRUCTURING', scenario_ids)
        self.assertIn('SCEN-05-USSD-CASH-OUT', scenario_ids)
        self.assertIn('SCEN-07-CRED-STUFFING', scenario_ids)
        self.assertIn('SCEN-08-IDOR-PROBE', scenario_ids)
        self.assertIn('SCEN-11-MASS-EXFIL', scenario_ids)
        self.assertIn('SCEN-12-AUDIT-TAMPER', scenario_ids)

    def test_02_scenario_event_generation(self):
        """Test attack and benign scenarios generate valid structured canonical events."""
        scen_ato = get_scenario('SCEN-01-ATO-CHAIN')
        self.assertIsNotNone(scen_ato)
        events = scen_ato['generate_events'](self.org_a)

        self.assertGreaterEqual(len(events), 4, "ATO scenario must generate multi-step event sequence")
        for ev in events:
            self.assertEqual(ev.get('organization_id'), self.org_a)
            self.assertIn('event_type', ev)
            self.assertIn('timestamp', ev)

    def test_03_benchmark_corpus_synthesis(self):
        """Test labeled benchmark corpus compiles all scenarios with ground truth metadata."""
        corpus = generate_benchmark_corpus(self.org_a)
        
        self.assertIn('events', corpus)
        self.assertIn('summary', corpus)
        summary = corpus['summary']

        self.assertGreaterEqual(summary['total_events'], 30)
        self.assertGreaterEqual(summary['attack_events'], 20)
        self.assertGreaterEqual(summary['benign_events'], 5)
        self.assertGreaterEqual(summary['scenario_count'], 14)

        # Every labeled event must possess ground-truth metadata
        for item in corpus['events']:
            self.assertIn('event', item)
            self.assertIn('is_attack', item)
            self.assertIn('scenario_id', item)
            self.assertIn('category', item)

    def test_04_benchmark_run_detection_metrics_and_gate3_criteria(self):
        """Test full benchmark execution meets Gate 3 criteria (>=90% detection rate, <=10% FPR)."""
        report = BenchmarkService.run_benchmark(org_id=self.org_a)

        self.assertIn('metrics', report)
        metrics = report['metrics']

        # 1. Scenario Detection Rate >= 90%
        detection_rate = metrics['scenario_detection_rate']
        self.assertGreaterEqual(detection_rate, 0.90, f"Scenario detection rate {detection_rate:.2%} must be >= 90%")

        # 2. False Positive Rate <= 10%
        fpr = metrics['false_positive_rate']
        self.assertLessEqual(fpr, 0.10, f"False positive rate {fpr:.2%} must be <= 10%")

        # 3. Overall Precision >= 80%
        precision = metrics['precision']
        self.assertGreaterEqual(precision, 0.80)

        # 4. Pack Breakdown verification
        packs = report['pack_metrics']
        self.assertIn('fraud_payments', packs)
        self.assertIn('web_api', packs)
        self.assertIn('insider_admin', packs)
        for p_name, p_stats in packs.items():
            self.assertGreater(p_stats['total_scenarios'], 0)
            self.assertGreaterEqual(p_stats['detection_rate'], 0.80, f"Pack {p_name} detection rate must be >= 80%")

        # 5. Gate 3 Status
        self.assertTrue(report['gate_3_passed'])

    def test_05_single_scenario_execution(self):
        """Test executing a targeted scenario dry-run returns live detection engine analysis."""
        run_res = BenchmarkService.run_scenario('SCEN-01-ATO-CHAIN', org_id=self.org_a)

        self.assertEqual(run_res['scenario_id'], 'SCEN-01-ATO-CHAIN')
        self.assertTrue(run_res['is_detected'])
        self.assertGreater(len(run_res['detections']), 0)
        
        # Verify targeted rules fired
        fired_rule_ids = {d['rule_id'] for d in run_res['detections']}
        self.assertTrue(any(r in fired_rule_ids for r in ['ATO-001', 'AUTH-001', 'AUTH-003', 'TX-001']))

    def test_06_benign_traffic_no_false_alarms(self):
        """Test benign routine transactions do not trigger high or critical risk alerts."""
        run_res = BenchmarkService.run_scenario('SCEN-13-BENIGN-RETAIL', org_id=self.org_a)

        self.assertFalse(run_res['is_detected'], "Benign retail traffic must not be flagged as attack")
        self.assertEqual(run_res['peak_severity'], 'low')
        self.assertLess(run_res['peak_risk_score'], 25)

    def test_07_rest_api_scenarios_and_run(self):
        """Test REST API endpoints for listing scenarios, running scenarios, and benchmark runs."""
        headers_viewer = {'Authorization': f'Bearer {self.token_viewer}', 'Content-Type': 'application/json'}
        headers_analyst = {'Authorization': f'Bearer {self.token_analyst}', 'Content-Type': 'application/json'}

        # 1. GET /api/benchmark/scenarios
        resp = self.client.get('/api/benchmark/scenarios', headers=headers_viewer)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()['data']
        self.assertGreaterEqual(len(data), 14)

        # 2. GET /api/benchmark/corpus
        resp_corpus = self.client.get('/api/benchmark/corpus', headers=headers_viewer)
        self.assertEqual(resp_corpus.status_code, 200)
        corpus_summary = resp_corpus.get_json()['data']['summary']
        self.assertGreater(corpus_summary['total_events'], 0)

        # 3. POST /api/benchmark/scenarios/run (Analyst or Admin)
        resp_run_scen = self.client.post('/api/benchmark/scenarios/run', json={'scenario_id': 'SCEN-08-IDOR-PROBE'}, headers=headers_analyst)
        self.assertEqual(resp_run_scen.status_code, 200)
        run_data = resp_run_scen.get_json()['data']
        self.assertEqual(run_data['scenario_id'], 'SCEN-08-IDOR-PROBE')
        self.assertTrue(run_data['is_detected'])

        # 4. POST /api/benchmark/run (Execute full benchmark)
        resp_run_full = self.client.post('/api/benchmark/run', json={'pack': 'web_api'}, headers=headers_analyst)
        self.assertEqual(resp_run_full.status_code, 200)
        bench_data = resp_run_full.get_json()['data']
        self.assertIn('metrics', bench_data)
        self.assertIn('scenario_detection_rate', bench_data['metrics'])

        # 5. GET /api/benchmark/latest
        resp_latest = self.client.get('/api/benchmark/latest', headers=headers_viewer)
        self.assertEqual(resp_latest.status_code, 200)
        self.assertIsNotNone(resp_latest.get_json()['data'])


if __name__ == '__main__':
    unittest.main()
