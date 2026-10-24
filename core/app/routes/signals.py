"""
Community Defense & Privacy-Preserving Signal Exchange REST API Routes for Ethio-Cyber-Shield (ECS) v3.0 (Phase 6).
Endpoints:
  GET  /api/signals/preferences          - Get tenant sharing preferences & consent status
  PUT  /api/signals/preferences          - Update sharing preferences (opt-in/opt-out, allowed TLPs)
  POST /api/signals/contribute           - Contribute threat signal to community exchange
  GET  /api/signals/feed                 - Consume community feed (anonymized & TLP filtered)
  POST /api/signals/retract              - Retract false or benign signal (anti-poisoning)
  POST /api/signals/match                - Evaluate candidate indicator against community exchange
  GET  /api/signals/stix/export          - Export STIX 2.1 bundle for EthioCERT / INSA integration
  POST /api/signals/stix/import          - Import EthioCERT advisory bundle
  GET  /api/signals/metrics              - Network effect metrics & participant reputation score
"""
from flask import Blueprint, request, jsonify, g
from app.services.auth_service import login_required, role_required
from app.services.signal_exchange_service import SignalExchangeService
from app.services.tenant_service import get_current_organization_id
import logging

logger = logging.getLogger(__name__)
signals_bp = Blueprint('signals', __name__)


def _get_org_id() -> str:
    org_id = g.user.get('organization_id') if hasattr(g, 'user') and g.user else None
    return str(org_id or get_current_organization_id() or "00000000-0000-0000-0000-000000000001")


@signals_bp.route('/preferences', methods=['GET'])
@login_required
def get_preferences():
    """Retrieves tenant sharing preferences and consent configuration."""
    org_id = _get_org_id()
    prefs = SignalExchangeService.get_sharing_preferences(org_id)
    return jsonify(prefs), 200


@signals_bp.route('/preferences', methods=['PUT'])
@role_required('admin')
def set_preferences():
    """Updates tenant sharing consent and permitted TLP levels."""
    org_id = _get_org_id()
    data = request.get_json() or {}
    updated = SignalExchangeService.set_sharing_preferences(org_id, data)
    return jsonify(updated), 200


@signals_bp.route('/contribute', methods=['POST'])
@role_required('admin', 'analyst', 'responder')
def contribute_signal():
    """Contributes a threat signal to the community exchange."""
    org_id = _get_org_id()
    data = request.get_json() or {}

    itype = data.get('indicator_type')
    ival = data.get('indicator_value')
    cat = data.get('threat_category')

    if not itype or not ival or not cat:
        return jsonify({'error': 'indicator_type, indicator_value, and threat_category are required'}), 400

    actor_name = g.user.get('full_name') if hasattr(g, 'user') else 'SOC Analyst'

    try:
        signal = SignalExchangeService.contribute_signal(
            org_id=org_id,
            indicator_type=itype,
            raw_indicator_value=ival,
            threat_category=cat,
            severity=data.get('severity', 'medium'),
            confidence=float(data.get('confidence', 0.85)),
            tlp=data.get('tlp', 'GREEN'),
            ttl_hours=int(data.get('ttl_hours', 168)),
            actor_name=actor_name
        )
        return jsonify(signal), 201
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


@signals_bp.route('/feed', methods=['GET'])
@login_required
def get_feed():
    """Consumes community threat signals filtered by permitted TLP and anonymized."""
    org_id = _get_org_id()
    min_conf = float(request.args.get('min_confidence', 0.50))
    corroborated_only = request.args.get('corroborated_only', 'false').lower() == 'true'
    limit = int(request.args.get('limit', 100))

    tlp_filter = request.args.get('tlp')
    tlps = [t.strip().upper() for t in tlp_filter.split(',')] if tlp_filter else None

    feed = SignalExchangeService.get_community_feed(
        org_id=org_id,
        min_confidence=min_conf,
        tlp_filter=tlps,
        corroborated_only=corroborated_only,
        limit=limit
    )
    return jsonify({'total_signals': len(feed), 'feed': feed}), 200


@signals_bp.route('/retract', methods=['POST'])
@role_required('admin', 'analyst')
def retract_signal():
    """Retracts a previously contributed signal upon benign discovery."""
    org_id = _get_org_id()
    data = request.get_json() or {}
    signal_hash = data.get('signal_hash')
    reason = data.get('reason', 'Benign false positive verified by SOC')

    if not signal_hash:
        return jsonify({'error': 'signal_hash is required'}), 400

    try:
        retracted = SignalExchangeService.retract_signal(org_id, signal_hash, reason)
        return jsonify(retracted), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


@signals_bp.route('/match', methods=['POST'])
@login_required
def match_indicator():
    """Evaluates an indicator against active community signals."""
    org_id = _get_org_id()
    data = request.get_json() or {}
    itype = data.get('indicator_type')
    ival = data.get('indicator_value')

    if not itype or not ival:
        return jsonify({'error': 'indicator_type and indicator_value are required'}), 400

    match = SignalExchangeService.evaluate_community_match(org_id, itype, ival)
    if not match:
        return jsonify({'matched': False}), 200
    return jsonify({'matched': True, 'match': match}), 200


@signals_bp.route('/stix/export', methods=['GET'])
@login_required
def export_stix():
    """Exports active community signals as an OASIS STIX 2.1 JSON Bundle."""
    org_id = _get_org_id()
    stix_bundle = SignalExchangeService.export_stix_bundle(org_id)
    return jsonify(stix_bundle), 200


@signals_bp.route('/stix/import', methods=['POST'])
@role_required('admin', 'analyst')
def import_stix():
    """Ingests official EthioCERT STIX threat advisory bundle."""
    org_id = _get_org_id()
    data = request.get_json() or {}
    res = SignalExchangeService.import_cert_advisories(org_id, data)
    return jsonify(res), 200


@signals_bp.route('/metrics', methods=['GET'])
@login_required
def get_metrics():
    """Retrieves network effect and participant reputation metrics."""
    org_id = _get_org_id()
    metrics = SignalExchangeService.get_community_metrics(org_id)
    return jsonify(metrics), 200
