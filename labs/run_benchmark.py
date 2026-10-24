#!/usr/bin/env python3
"""
Ethio-Cyber-Shield (ECS) — Standalone Benchmark & CI Gate Runner (Phase 3.6).
Evaluates the labeled benchmark corpus against declarative detection rule packs.
Enforces Gate 3 criteria:
  - Scenario Detection Rate >= 90%
  - False Positive Rate <= 10%

Usage:
  python labs/run_benchmark.py
  python labs/run_benchmark.py --min-recall 0.90 --max-fpr 0.10 --output benchmark_result.json
"""
import sys
import os
import json
import argparse
from typing import Dict, Any

# Ensure core is on Python path
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
core_path = os.path.join(repo_root, 'core')
if core_path not in sys.path:
    sys.path.insert(0, core_path)
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from app.services.benchmark_service import BenchmarkService


def format_table(headers, rows):
    col_widths = [len(h) for h in headers]
    for row in rows:
        for i, val in enumerate(row):
            col_widths[i] = max(col_widths[i], len(str(val)))

    header_line = " | ".join(f"{h:<{col_widths[i]}}" for i, h in enumerate(headers))
    sep_line = "-+-".join("-" * col_widths[i] for i in range(len(headers)))
    row_lines = [" | ".join(f"{str(v):<{col_widths[i]}}" for i, v in enumerate(r)) for r in rows]

    return f"{header_line}\n{sep_line}\n" + "\n".join(row_lines)


def main():
    parser = argparse.ArgumentParser(description="Ethio-Cyber-Shield Detection Benchmark Runner")
    parser.add_argument("--pack", choices=["fraud_payments", "web_api", "insider_admin"], default=None,
                        help="Filter benchmark to a specific rule pack")
    parser.add_argument("--min-recall", type=float, default=0.90,
                        help="Minimum scenario detection rate threshold (default: 0.90)")
    parser.add_argument("--max-fpr", type=float, default=0.10,
                        help="Maximum false positive rate threshold (default: 0.10)")
    parser.add_argument("--output", default=None,
                        help="Path to write JSON benchmark report")
    args = parser.parse_args()

    print("=" * 80)
    print("ETHIO-CYBER-SHIELD (ECS) v3.0 — DETECTION BENCHMARK EVALUATOR")
    print("=" * 80)
    print(f"Gate 3 Target: Detection Rate >= {args.min_recall:.1%}, False Positive Rate <= {args.max_fpr:.1%}\n")

    report = BenchmarkService.run_benchmark(pack=args.pack)
    metrics = report['metrics']
    packs = report['pack_metrics']
    scen_results = report['scenario_results']

    # 1. Print Scenario Evaluation Table
    scen_rows = []
    for r in scen_results:
        status_symbol = "✓ DETECTED" if r['is_detected'] else ("✓ BENIGN" if not r['is_attack'] else "✗ MISSED")
        scen_rows.append([
            r['scenario_id'],
            r['name'][:34],
            r['category'],
            "ATTACK" if r['is_attack'] else "BENIGN",
            status_symbol,
            ", ".join(r['fired_rules'][:3]) or "None"
        ])

    print("SCENARIO EXECUTION RESULTS:")
    print(format_table(["Scenario ID", "Name", "Category", "Type", "Outcome", "Fired Rules"], scen_rows))
    print("\n" + "-" * 80 + "\n")

    # 2. Print Pack Breakdown Table
    pack_rows = []
    for p_name, p_data in packs.items():
        pack_rows.append([
            p_name,
            p_data['total_scenarios'],
            p_data['detected_scenarios'],
            f"{p_data['detection_rate']:.1%}"
        ])
    print("RULE PACK PERFORMANCE SUMMARY:")
    print(format_table(["Rule Pack", "Total Scenarios", "Detected", "Detection Rate"], pack_rows))
    print("\n" + "-" * 80 + "\n")

    # 3. Overall Gate Evaluation
    det_rate = metrics['scenario_detection_rate']
    fpr = metrics['false_positive_rate']
    precision = metrics['precision']
    f1 = metrics['f1_score']

    passed = (det_rate >= args.min_recall) and (fpr <= args.max_fpr)

    print("OVERALL DETECTION BENCHMARK METRICS:")
    print(f"  • Attack Scenario Detection Rate : {det_rate:.2%} (Target >= {args.min_recall:.1%})")
    print(f"  • False Positive Rate (FPR)      : {fpr:.2%} (Target <= {args.max_fpr:.1%})")
    print(f"  • Overall Detection Precision    : {precision:.2%}")
    print(f"  • Overall F1 Score               : {f1:.4f}")
    print(f"  • Total Scenarios Evaluated      : {metrics['total_scenarios_evaluated']}")
    print("-" * 80)

    if passed:
        print(">>> GATE 3 VERIFICATION: PASSED (Detection requirements satisfied) <<<")
    else:
        print(">>> GATE 3 VERIFICATION: FAILED (Detection rate or FPR failed thresholds) <<<")

    if args.output:
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2)
        print(f"\nBenchmark JSON report saved to: {args.output}")

    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
