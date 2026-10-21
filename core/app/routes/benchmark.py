"""
Ethio-Cyber-Shield (ECS) — Benchmark & Attack Lab REST API (Phase 3.6).
Provides endpoints for:
- GET /api/benchmark/scenarios: List attack scenarios with target rules and metadata.
- POST /api/benchmark/scenarios/run: Execute individual attack scenarios and inspect detections.
- GET /api/benchmark/corpus: Summary of labeled benchmark corpus events.
- POST /api/benchmark/run: Execute full benchmark evaluation with precision/recall reporting.
- GET /api/benchmark/latest: Retrieve the latest benchmark run and Gate 3 status.
"""
from flask import Blueprint, request, jsonify, g
from app.services.auth_service import login_required, role_required
from app.benchmark.scenarios import list_scenarios, get_scenario
from app.benchmark.corpus import generate_benchmark_corpus
from app.services.benchmark_service import BenchmarkService

benchmark_bp = Blueprint('benchmark', __name__)


@benchmark_bp.route('/scenarios', methods=['GET'])
@login_required
def get_scenarios():
    """Lists attack and benign scenarios available in the Attack Lab library."""
    cat = request.args.get('category') or request.args.get('pack')
    scenarios = list_scenarios(category=cat)
    return jsonify({
        'status': 'success',
        'count': len(scenarios),
        'data': scenarios
    }), 200


@benchmark_bp.route('/scenarios/run', methods=['POST'])
@login_required
@role_required('admin', 'analyst', 'responder')
def run_single_scenario():
    """Runs a single scenario against the detection engine and returns detection outcomes."""
    org_id = g.organization_id
    data = request.get_json() or {}
    scenario_id = data.get('scenario_id')
    if not scenario_id:
        return jsonify({'error': 'scenario_id is required'}), 400

    try:
        res = BenchmarkService.run_scenario(scenario_id, org_id=org_id)
        return jsonify({
            'status': 'success',
            'organization_id': org_id,
            'data': res
        }), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 404


@benchmark_bp.route('/corpus', methods=['GET'])
@login_required
def get_corpus():
    """Returns summary and sample events from the labeled benchmark corpus."""
    org_id = g.organization_id
    corpus = generate_benchmark_corpus(org_id=org_id)
    return jsonify({
        'status': 'success',
        'organization_id': org_id,
        'data': {
            'summary': corpus['summary'],
            'sample_events': corpus['events'][:5]
        }
    }), 200


@benchmark_bp.route('/run', methods=['POST'])
@login_required
@role_required('admin', 'analyst')
def run_benchmark_suite():
    """Executes the benchmark corpus across rule packs and computes precision/recall metrics."""
    org_id = g.organization_id
    data = request.get_json() or {}
    pack = data.get('pack') or data.get('category')
    scenarios = data.get('scenarios')

    report = BenchmarkService.run_benchmark(org_id=org_id, pack=pack, scenarios=scenarios)
    return jsonify({
        'status': 'success',
        'organization_id': org_id,
        'data': report
    }), 200


@benchmark_bp.route('/latest', methods=['GET'])
@login_required
def get_latest():
    """Retrieves the latest benchmark execution results and Gate 3 compliance status."""
    report = BenchmarkService.get_latest_benchmark_report()
    return jsonify({
        'status': 'success',
        'data': report
    }), 200
