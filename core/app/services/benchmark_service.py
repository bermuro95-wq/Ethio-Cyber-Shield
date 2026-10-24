"""
Ethio-Cyber-Shield (ECS) — Automated Benchmark Evaluation Service (Phase 3.6).
Evaluates labeled benchmark corpus and attack scenario library against declarative rule packs.
Computes precision, recall, false positive rates, and verifies Gate 3 criteria:
>= 90% scenario detection rate with <= 10% false positive rate.
"""
import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

from app.benchmark.scenarios import SCENARIO_CATALOG, get_scenario, list_scenarios
from app.benchmark.corpus import generate_benchmark_corpus
from app.services.rule_engine_service import get_rule_engine
from app.services.tenant_service import get_current_organization_id

logger = logging.getLogger(__name__)

# In-memory storage for latest benchmark run results
_LATEST_BENCHMARK_RUN: Dict[str, Any] = {}


class BenchmarkService:
    """
    Executes attack scenarios and compiles precision/recall metrics across rule packs.
    """

    @classmethod
    def run_scenario(
        cls,
        scenario_id: str,
        org_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Executes a single scenario by evaluating its event sequence against the declarative rule engine.
        Does not pollute persistent production alert tables.
        """
        oid = org_id or get_current_organization_id() or "00000000-0000-0000-0000-000000000001"
        scen = get_scenario(scenario_id)
        if not scen:
            raise ValueError(f"Scenario '{scenario_id}' not found in catalog")

        events = scen['generate_events'](oid)
        engine = get_rule_engine()

        all_detections: List[Dict[str, Any]] = []
        peak_risk_score = 0
        peak_severity = "low"
        is_attack = scen['is_attack']
        target_rules = set(scen['target_rule_ids'])

        # Sliding window buffer within the scenario run
        window_events: List[Dict[str, Any]] = []

        for ev in events:
            # Evaluate event with sliding window context
            fired = engine.evaluate_event(ev, org_id=oid, sliding_window_events=window_events)
            window_events.append(ev)

            # Compute risk
            event_score = sum(r.get('weight', 0) for r in fired if not r.get('is_shadow'))
            if event_score > peak_risk_score:
                peak_risk_score = min(100, event_score)
                if peak_risk_score >= 75:
                    peak_severity = "critical"
                elif peak_risk_score >= 50:
                    peak_severity = "high"
                elif peak_risk_score >= 25:
                    peak_severity = "medium"
                else:
                    peak_severity = "low"

            for r in fired:
                all_detections.append({
                    'rule_id': r['rule_id'],
                    'name': r['name'],
                    'severity': r['severity'],
                    'weight': r['weight'],
                    'summary': r['summary'],
                    'event_id': ev.get('event_id')
                })

        fired_rule_ids = {d['rule_id'] for d in all_detections}
        target_hits = fired_rule_ids.intersection(target_rules)

        # A scenario is successfully detected if:
        # For attack: any target rule fired OR overall risk score >= 25
        # For benign: no target rules fired AND peak risk score < 25
        if is_attack:
            is_detected = bool(target_hits or peak_risk_score >= 25)
        else:
            is_detected = bool(target_hits or peak_risk_score >= 25)

        return {
            'scenario_id': scenario_id,
            'name': scen['name'],
            'category': scen['category'],
            'is_attack': is_attack,
            'is_detected': is_detected,
            'events_evaluated': len(events),
            'target_rules': list(target_rules),
            'fired_rules': list(fired_rule_ids),
            'target_hits': list(target_hits),
            'peak_risk_score': peak_risk_score,
            'peak_severity': peak_severity,
            'detections': all_detections
        }

    @classmethod
    def run_benchmark(
        cls,
        org_id: Optional[str] = None,
        pack: Optional[str] = None,
        scenarios: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Runs the benchmark suite across attack scenarios and benign baselines.
        Computes scenario detection rate, false positive rate, precision, recall, and F1.
        """
        oid = org_id or get_current_organization_id() or "00000000-0000-0000-0000-000000000001"
        scen_list = list_scenarios(category=pack)

        if scenarios:
            target_ids = set(scenarios)
            scen_list = [s for s in scen_list if s['scenario_id'] in target_ids]

        results = []
        attack_detected = 0
        attack_total = 0
        benign_false_alarms = 0
        benign_total = 0

        # Pack-level tracking
        pack_stats: Dict[str, Dict[str, Any]] = {}

        # Rule-level tracking
        rule_stats: Dict[str, Dict[str, int]] = {}

        for item in scen_list:
            s_id = item['scenario_id']
            run_res = cls.run_scenario(s_id, org_id=oid)
            results.append(run_res)

            cat = run_res['category']
            if cat not in pack_stats and cat != 'benign':
                pack_stats[cat] = {
                    'total_scenarios': 0,
                    'detected_scenarios': 0,
                    'detection_rate': 0.0
                }

            is_atk = run_res['is_attack']
            if is_atk:
                attack_total += 1
                if cat in pack_stats:
                    pack_stats[cat]['total_scenarios'] += 1

                if run_res['is_detected']:
                    attack_detected += 1
                    if cat in pack_stats:
                        pack_stats[cat]['detected_scenarios'] += 1
            else:
                benign_total += 1
                if run_res['is_detected']:  # Alerted on benign = false positive
                    benign_false_alarms += 1

            # Track rule hits
            for r_id in run_res['target_rules']:
                if r_id not in rule_stats:
                    rule_stats[r_id] = {'expected': 0, 'fired': 0}
                rule_stats[r_id]['expected'] += 1
                if r_id in run_res['fired_rules']:
                    rule_stats[r_id]['fired'] += 1

        # Calculate pack detection rates
        for cat, stats in pack_stats.items():
            tot = stats['total_scenarios']
            det = stats['detected_scenarios']
            stats['detection_rate'] = round(det / tot, 4) if tot > 0 else 1.0

        # Overall Metrics
        tp = attack_detected
        fn = attack_total - attack_detected
        fp = benign_false_alarms
        tn = benign_total - benign_false_alarms

        scenario_detection_rate = round(tp / attack_total, 4) if attack_total > 0 else 1.0
        false_positive_rate = round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0.0
        precision = round(tp / (tp + fp), 4) if (tp + fp) > 0 else 1.0
        recall = round(tp / (tp + fn), 4) if (tp + fn) > 0 else 1.0
        f1 = round(2 * (precision * recall) / (precision + recall), 4) if (precision + recall) > 0 else 0.0

        gate_3_passed = (scenario_detection_rate >= 0.90) and (false_positive_rate <= 0.10)

        report = {
            'benchmark_id': str(uuid.uuid4()),
            'organization_id': oid,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'gate_3_passed': gate_3_passed,
            'gate_criteria': {
                'min_detection_rate': 0.90,
                'max_false_positive_rate': 0.10
            },
            'metrics': {
                'scenario_detection_rate': scenario_detection_rate,
                'false_positive_rate': false_positive_rate,
                'precision': precision,
                'recall': recall,
                'f1_score': f1,
                'true_positives': tp,
                'false_positives': fp,
                'false_negatives': fn,
                'true_negatives': tn,
                'total_attack_scenarios': attack_total,
                'total_benign_scenarios': benign_total,
                'total_scenarios_evaluated': len(results)
            },
            'pack_metrics': pack_stats,
            'rule_metrics': rule_stats,
            'scenario_results': results
        }

        global _LATEST_BENCHMARK_RUN
        _LATEST_BENCHMARK_RUN = report

        return report

    @classmethod
    def get_latest_benchmark_report(cls) -> Optional[Dict[str, Any]]:
        """Returns the most recent benchmark run results."""
        global _LATEST_BENCHMARK_RUN
        if not _LATEST_BENCHMARK_RUN:
            # Automatically run on first request
            return cls.run_benchmark()
        return _LATEST_BENCHMARK_RUN
