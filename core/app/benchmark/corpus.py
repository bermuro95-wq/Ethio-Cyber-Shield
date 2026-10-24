"""
Ethio-Cyber-Shield (ECS) — Labeled Benchmark Corpus (Phase 3.6).
Compiles reproducible, labeled benchmark datasets pairing canonical events with ground truth
assertions for offline and automated CI evaluation of precision, recall, and false positive rates.
"""
from typing import Dict, Any, List, Optional
from app.benchmark.scenarios import SCENARIO_CATALOG, list_scenarios


def generate_benchmark_corpus(org_id: str = "00000000-0000-0000-0000-000000000001") -> Dict[str, Any]:
    """
    Generates a full labeled benchmark corpus across all 15 scenarios in the catalog.
    Returns:
    {
        'summary': { ... },
        'events': [
            {
                'event': {...},
                'is_attack': bool,
                'scenario_id': str,
                'category': str,
                'expected_rule_ids': [...]
            }, ...
        ]
    }
    """
    corpus_events: List[Dict[str, Any]] = []
    category_counts: Dict[str, int] = {}
    attack_count = 0
    benign_count = 0

    for s_id, scen in SCENARIO_CATALOG.items():
        events = scen['generate_events'](org_id)
        cat = scen['category']
        category_counts[cat] = category_counts.get(cat, 0) + len(events)

        is_attack = scen['is_attack']
        if is_attack:
            attack_count += len(events)
        else:
            benign_count += len(events)

        for ev in events:
            corpus_events.append({
                'event': ev,
                'is_attack': is_attack,
                'scenario_id': s_id,
                'category': cat,
                'expected_rule_ids': scen['target_rule_ids']
            })

    summary = {
        'total_events': len(corpus_events),
        'attack_events': attack_count,
        'benign_events': benign_count,
        'scenario_count': len(SCENARIO_CATALOG),
        'category_distribution': category_counts
    }

    return {
        'summary': summary,
        'events': corpus_events
    }
