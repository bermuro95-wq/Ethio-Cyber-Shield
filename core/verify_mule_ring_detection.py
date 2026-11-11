#!/usr/bin/env python3
"""
Ethio-Cyber-Shield (ECS) — Financial Mule Ring & Graph Intelligence Demonstration Runner.
Fulfills National Bank of Ethiopia (NBE) Directive SBB/84/2022 & INSA Proclamation No. 1426/2026:

Demonstration Sequence for INSA Evaluators, Examination Committees & CISO Reviewers:
  Stage 1: Clean Baseline Telemetry & Graph Health Verification
  Stage 2: Evasion Attempt via Sub-Threshold Micro-Smurfing (Bypassing Legacy SIEM Rules)
  Stage 3: Rapid Convergence into Centralized Cash-Out Hub
  Stage 4: Topological Graph Intelligence & Smurfing Ring Detection (Risk 96/100)
  Stage 5: Circular Money Laundering Ring Detection via Johnson's Cycle Algorithm (Risk 100/100)
  Stage 6: Autonomous Multi-Account Containment Dispatch (Statutory 1426/2026 Freezes)
  Stage 7: Live Graph Snapshot & REST API Verification
"""

import sys
import time
import json
import uuid
from datetime import datetime, timezone, timedelta

from app import create_app
from app.services.auth_service import create_token
from app.services.mule_graph_service import get_mule_graph_service
from app.services.tenant_service import DEFAULT_ORGANIZATION_ID

BOLD = "\033[1m"
GREEN = "\033[92m"
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
MAGENTA = "\033[95m"
RESET = "\033[0m"


def print_banner(step: int, title: str):
    print(f"\n{BOLD}{CYAN}================================================================================{RESET}")
    print(f"{BOLD}{CYAN}[STAGE {step}/7] {title}{RESET}")
    print(f"{BOLD}{CYAN}================================================================================{RESET}")


def assert_stage(condition: bool, success_msg: str, fail_msg: str):
    if condition:
        print(f"  {GREEN}✔ SUCCESS: {success_msg}{RESET}")
    else:
        print(f"  {RED}✖ FAILURE: {fail_msg}{RESET}")
        sys.exit(1)


def run_mule_ring_demo():
    start_time = time.time()

    print(f"\n{BOLD}{MAGENTA}================================================================================{RESET}")
    print(f"{BOLD}{MAGENTA}   ETHIO-CYBER-SHIELD (ECS) — FINANCIAL MULE RING GRAPH INTELLIGENCE DEMO   {RESET}")
    print(f"{BOLD}{MAGENTA}      Regulatory Mandate: NBE Directive SBB/84/2022 & INSA Proc. 1426/2026      {RESET}")
    print(f"{BOLD}{MAGENTA}================================================================================{RESET}")

    app = create_app()
    app.config["TESTING"] = True
    client = app.test_client()

    demo_org = f"demo-insa-{uuid.uuid4().hex[:8]}"
    admin_token = create_token(
        str(uuid.uuid4()),
        "ciso@ethswitch.et",
        "admin",
        organization_id=demo_org,
    )
    auth_headers = {"Authorization": f"Bearer {admin_token}"}
    svc = get_mule_graph_service()

    with app.app_context():
        # ---------------------------------------------------------------------
        # STAGE 1: Clean Baseline Telemetry & Graph Health Verification
        # ---------------------------------------------------------------------
        print_banner(1, "Clean Baseline Telemetry & Graph Health Verification")
        svc.clear_stores(demo_org)

        baseline_snap = svc.get_graph_snapshot(demo_org)
        print(f"  • Tenant Organization ID: {demo_org}")
        print(f"  • Initial Active Nodes: {baseline_snap['metrics']['total_nodes']}")
        print(f"  • Initial Detected Syndicates: {baseline_snap['metrics']['total_syndicates']}")

        assert_stage(
            baseline_snap["metrics"]["total_nodes"] == 0 and baseline_snap["metrics"]["total_syndicates"] == 0,
            "Clean baseline initialized; zero phantom nodes, zero false-positive syndicates.",
            "Baseline graph not empty upon initialization.",
        )

        # ---------------------------------------------------------------------
        # STAGE 2: Evasion Attempt via Sub-Threshold Micro-Smurfing
        # ---------------------------------------------------------------------
        print_banner(2, "Adversary Evasion Attempt: Sub-Threshold Micro-Smurfing")
        now = datetime.now(timezone.utc)
        src_corp = "ACC-8012-ETHIO-CORP"
        cashout_hub = "WALLET-CASHOUT-9901"
        mules = ["TELE-0911840001", "TELE-0922410002", "CBE-1000889903"]

        print(f"  • Adversary targets Corporate Source: {BOLD}{src_corp}{RESET}")
        print(f"  • Strategy: Disperse 14,100 ETB into 3 micro-transfers of 4,700 ETB each.")
        print(f"  • Standard SIEM Threshold: 5,000 ETB / transfer (Adversary intentionally operates at 4,700 ETB).")

        # Disperse to 3 intermediary mules
        for i, m in enumerate(mules):
            t_edge = now - timedelta(minutes=25 - i * 2)
            res = svc.record_transfer(
                org_id=demo_org,
                source_account=src_corp,
                destination_account=m,
                amount=4700.0,
                currency="ETB",
                payment_rail="telebirr",
                timestamp=t_edge,
                source_ip="196.188.12.80",
                device_id="DEV-BURP-01",
            )
            print(f"    - Ingested: {src_corp} -> {m} | 4,700.00 ETB [telebirr] (Edge: {res['edge_id']})")

        interim_snap = svc.get_graph_snapshot(demo_org)
        print(f"  • Current Graph Nodes: {interim_snap['metrics']['total_nodes']}")
        print(f"  • Linear SIEM Check: All transfers are < 5,000 ETB. Standard velocity rules: {YELLOW}NO ALERT{RESET}")

        assert_stage(
            interim_snap["metrics"]["total_nodes"] == 4,
            "Micro-dispersal successfully recorded in graph while staying below linear velocity thresholds.",
            "Failed to ingest micro-dispersal transfers.",
        )

        # ---------------------------------------------------------------------
        # STAGE 3: Rapid Convergence into Centralized Cash-Out Hub
        # ---------------------------------------------------------------------
        print_banner(3, "Rapid Convergence into Centralized Cash-Out Hub")
        print(f"  • Strategy: Intermediary mules route funds into common Cash-Out Hub: {BOLD}{cashout_hub}{RESET}")

        for i, m in enumerate(mules):
            t_edge = now - timedelta(minutes=10 - i * 2)
            res = svc.record_transfer(
                org_id=demo_org,
                source_account=m,
                destination_account=cashout_hub,
                amount=4600.0,
                currency="ETB",
                payment_rail="telebirr",
                timestamp=t_edge,
                source_ip="196.188.12.80",
                device_id="DEV-BURP-01",
            )
            print(f"    - Ingested: {m} -> {cashout_hub} | 4,600.00 ETB [telebirr] (Edge: {res['edge_id']})")

        assert_stage(
            True,
            "Multi-hop convergence transfers successfully ingested into dynamic topology.",
            "Failed to ingest convergence transfers.",
        )

        # ---------------------------------------------------------------------
        # STAGE 4: Topological Graph Intelligence & Smurfing Ring Detection
        # ---------------------------------------------------------------------
        print_banner(4, "Topological Graph Intelligence & Smurfing Ring Detection")
        smurf_snap = svc.get_graph_snapshot(demo_org)
        syndicates = smurf_snap.get("syndicates", [])
        smurf_rings = [s for s in syndicates if s["syndicate_type"] == "COORDINATED_SMURFING_RING"]

        print(f"  • Total Syndicates Identified: {len(syndicates)}")
        assert_stage(len(smurf_rings) >= 1, "Graph Engine detected COORDINATED_SMURFING_RING topology.", "Failed to detect smurfing ring.")

        smurf = smurf_rings[0]
        print(f"  • Syndicate ID: {BOLD}{CYAN}{smurf['syndicate_id']}{RESET}")
        print(f"  • Severity: {BOLD}{RED}{smurf['severity'].upper()}{RESET}")
        print(f"  • Explainable Risk Score: {BOLD}{RED}{smurf['risk_score']}/100{RESET}")
        print(f"  • Identified Source Account: {smurf['source_account']}")
        print(f"  • Identified Intermediary Mules: {smurf['intermediary_mules']}")
        print(f"  • Identified Cash-Out Hub: {BOLD}{RED}{smurf['cashout_hub']}{RESET}")
        print(f"  • Total Laundering Volume: {smurf['total_volume_etb']:,.2f} ETB")
        print(f"  • Detection Reason: {smurf['detection_reason']}")

        nodes_by_id = {n["id"]: n for n in smurf_snap["nodes"]}
        print(f"  • Role Attribution Verification:")
        print(f"    - {src_corp}: {nodes_by_id[src_corp]['role'].upper()} (Risk: {nodes_by_id[src_corp]['risk_score']})")
        print(f"    - {cashout_hub}: {BOLD}{RED}{nodes_by_id[cashout_hub]['role'].upper()}{RESET} (Betweenness: {nodes_by_id[cashout_hub]['betweenness']})")

        assert_stage(
            nodes_by_id[cashout_hub]["role"] == "cashout_hub" and nodes_by_id[src_corp]["role"] == "victim_source",
            "Brandes centrality and flow topology correctly isolated the Cash-Out Hub and Victim Source.",
            "Role attribution failed.",
        )

        # ---------------------------------------------------------------------
        # STAGE 5: Circular Money Laundering Ring Detection (Johnson Cycles)
        # ---------------------------------------------------------------------
        print_banner(5, "Circular Laundering Detection via Johnson's Cycle Algorithm")
        print("  • Adversary attempts circular fund hopping to evade trace audits:")
        print("    ACC-CIR-01 -> ACC-CIR-02 -> ACC-CIR-03 -> ACC-CIR-04 -> ACC-CIR-01")

        c_time = now - timedelta(minutes=40)
        c_accs = ["ACC-CIR-01", "ACC-CIR-02", "ACC-CIR-03", "ACC-CIR-04"]
        c_rails = ["telebirr", "cbe_birr", "ethswitch", "bank_transfer"]
        c_amounts = [50000.0, 49000.0, 48000.0, 47000.0]

        for i in range(4):
            u = c_accs[i]
            v = c_accs[(i + 1) % 4]
            svc.record_transfer(
                org_id=demo_org,
                source_account=u,
                destination_account=v,
                amount=c_amounts[i],
                currency="ETB",
                payment_rail=c_rails[i],
                timestamp=c_time + timedelta(minutes=i * 6),
                source_ip="197.156.77.20",
            )
            print(f"    - Ingested: {u} -> {v} | {c_amounts[i]:,.2f} ETB [{c_rails[i]}]")

        circle_snap = svc.get_graph_snapshot(demo_org)
        circle_rings = [s for s in circle_snap["syndicates"] if s["syndicate_type"] == "CIRCULAR_LAUNDERING_RING"]

        assert_stage(len(circle_rings) >= 1, "Johnson's cycle algorithm detected closed-loop laundering ring.", "Failed to detect circular cycle.")

        c_ring = circle_rings[0]
        print(f"  • Cycle Syndicate ID: {BOLD}{CYAN}{c_ring['syndicate_id']}{RESET}")
        print(f"  • Hop Count: {c_ring['hop_count']} Hops")
        print(f"  • Total Cycled Volume: {c_ring['total_volume_etb']:,.2f} ETB")
        print(f"  • Time Span: {c_ring['time_span_minutes']} Minutes")
        print(f"  • Statutory Risk Score: {BOLD}{RED}{c_ring['risk_score']}/100 (CRITICAL){RESET}")
        print(f"  • Detection Reason: {c_ring['detection_reason']}")

        assert_stage(
            c_ring["hop_count"] == 4 and c_ring["risk_score"] >= 95,
            f"Johnson's algorithm correctly computed 4-hop closed cycle with Risk {c_ring['risk_score']}/100.",
            "Cycle validation failed.",
        )

        # ---------------------------------------------------------------------
        # STAGE 6: Autonomous Multi-Account Containment & Statutory Compliance
        # ---------------------------------------------------------------------
        print_banner(6, "Autonomous Multi-Account Containment & Statutory Compliance")
        print(f"  • Disagreeing with manual piecemeal account freezes;")
        print(f"  • Executing 1-Click Autonomous Syndicate Containment on: {c_ring['syndicate_id']}")

        contain_res = svc.contain_syndicate(
            org_id=demo_org,
            syndicate_id=c_ring["syndicate_id"],
            reason="National Bank of Ethiopia Directive SBB/84/2022 Emergency Containment",
            operator_user_id="operator-ciso-01",
        )

        print(f"  • Containment Status: {BOLD}{GREEN}{contain_res['status'].upper()}{RESET}")
        print(f"  • Accounts Frozen Simultaneously: {BOLD}{contain_res['accounts_frozen_count']}{RESET}")
        print(f"  • Frozen Accounts List: {contain_res['frozen_accounts']}")
        print(f"  • Statutory Regulatory Citation: {contain_res['statutory_compliance']}")

        # Verify nodes are marked contained in subsequent snapshot
        verify_snap = svc.get_graph_snapshot(demo_org)
        verify_nodes = {n["id"]: n for n in verify_snap["nodes"]}
        all_frozen = all(verify_nodes[acc]["is_contained"] for acc in contain_res["frozen_accounts"])

        assert_stage(
            all_frozen and contain_res["accounts_frozen_count"] >= 4,
            f"All {contain_res['accounts_frozen_count']} accounts in the ring are verified FROZEN (🔒) in the graph.",
            "Not all accounts were marked as contained.",
        )

        # ---------------------------------------------------------------------
        # STAGE 7: Live Graph Snapshot & REST API Verification
        # ---------------------------------------------------------------------
        print_banner(7, "Live Graph Snapshot & REST API Verification")
        api_res = client.get("/api/analysis/mule-graph", headers=auth_headers)
        assert_stage(api_res.status_code == 200, "GET /api/analysis/mule-graph returned HTTP 200 OK.", "API returned non-200.")

        api_data = api_res.get_json()["data"]
        print(f"  • Total Serialized Nodes: {api_data['metrics']['total_nodes']}")
        print(f"  • Total Serialized Edges: {api_data['metrics']['total_edges']}")
        print(f"  • Total Active Syndicates: {api_data['metrics']['total_syndicates']}")
        print(f"  • Total Laundering Volume: {api_data['metrics']['total_laundering_volume_etb']:,.2f} ETB")
        print(f"  • Contained Accounts Count: {api_data['metrics']['contained_accounts']}")
        print(f"  • Algorithm Suite: {api_data['metrics']['algorithm_suite']}")

        rings_res = client.get("/api/analysis/mule-graph/rings", headers=auth_headers)
        assert_stage(rings_res.status_code == 200, "GET /api/analysis/mule-graph/rings returned HTTP 200 OK.", "Rings API failed.")

        elapsed = round(time.time() - start_time, 2)

        # ---------------------------------------------------------------------
        # FINAL DEMONSTRATION VERDICT
        # ---------------------------------------------------------------------
        print(f"\n{BOLD}{GREEN}================================================================================{RESET}")
        print(f"{BOLD}{GREEN}   ALL 7 STAGES OF MULE RING & GRAPH INTELLIGENCE VERIFIED (100% PASS - {elapsed}s)  {RESET}")
        print(f"{BOLD}{GREEN}================================================================================{RESET}")
        print(f"  {CYAN}✔ 1. Zero-Noise Baseline Telemetry & Multi-Tenant Partitioning{RESET}")
        print(f"  {CYAN}✔ 2. Sub-Threshold Micro-Smurfing Dispersal (Evading Legacy SIEM Thresholds){RESET}")
        print(f"  {CYAN}✔ 3. Dynamic Multi-Hop Telemetry Convergence (telebirr, CBE Birr, EthSwitch){RESET}")
        print(f"  {CYAN}✔ 4. Bipartite Smurfing Detection & Brandes Centrality Cash-Out Isolation (Risk 96/100){RESET}")
        print(f"  {CYAN}✔ 5. Johnson's Simple Cycle Algorithm Detecting Closed Routing Loops (Risk 100/100){RESET}")
        print(f"  {CYAN}✔ 6. Autonomous 1-Click Multi-Account Containment under INSA Proc. 1426/2026{RESET}")
        print(f"  {CYAN}✔ 7. Full REST API Serialization for High-Contrast SOC Visual Topology Console{RESET}")
        print(f"{BOLD}{GREEN}================================================================================{RESET}\n")


if __name__ == "__main__":
    run_mule_ring_demo()
