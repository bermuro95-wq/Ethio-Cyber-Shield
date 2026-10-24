"""
Incident Readiness Engine REST API Routes for Ethio-Cyber-Shield (ECS) v3.0 (Phase 5).
Endpoints:
  GET  /api/readiness/policy                       - Retrieve tenant readiness policy & CISO contact
  PUT  /api/readiness/policy                       - Update readiness policy (Admin)
  POST /api/readiness/classify/<incident_id>       - Evaluate reportability triggers
  POST /api/readiness/confirm/<incident_id>        - Confirm reportable status & lock detection timestamp
  GET  /api/readiness/clock/<incident_id>          - 48-hour statutory countdown clock diagnostics
  POST /api/readiness/clock/escalate               - Trigger 48-hour clock escalation watchdog
  POST /api/readiness/ethiocert/generate/<id>      - Generate official Bilingual EthioCERT submission package
  POST /api/readiness/ethiocert/submit/<id>        - Record official submission & reference number
  POST /api/readiness/vault/<incident_id>          - Create immutable Evidence Vault snapshot
  GET  /api/readiness/vault/<vault_id_or_ref>      - Retrieve Evidence Vault
  POST /api/readiness/vault/<vault_id>/verify      - Verify Evidence Vault cryptographic manifest seal
  GET  /api/readiness/vault/<vault_id>/custody     - List chain-of-custody audit log
  GET  /api/readiness/obligations                  - List statutory obligation-to-evidence register
  GET  /api/readiness/obligations/evaluation       - Evaluate compliance support readiness score
  GET  /api/readiness/audit-pack                   - One-click sealed audit pack bundle export
"""
from flask import Blueprint, request, jsonify, g, Response
from app.services.auth_service import login_required, role_required
from app.services.readiness_service import ReadinessService
from app.services.case_service import CaseService
from app.services.tenant_service import get_current_organization_id
import logging

logger = logging.getLogger(__name__)
readiness_bp = Blueprint('readiness', __name__)


def _get_org_id() -> str:
    org_id = g.user.get('organization_id') if hasattr(g, 'user') and g.user else None
    return str(org_id or get_current_organization_id() or "00000000-0000-0000-0000-000000000001")


@readiness_bp.route('/policy', methods=['GET'])
@login_required
def get_policy():
    """Retrieves tenant readiness policy and CISO contacts."""
    org_id = _get_org_id()
    policy = ReadinessService.get_readiness_policy(org_id)
    return jsonify(policy), 200


@readiness_bp.route('/policy', methods=['PUT'])
@role_required('admin')
def set_policy():
    """Updates tenant readiness policy."""
    org_id = _get_org_id()
    data = request.get_json() or {}
    updated = ReadinessService.set_readiness_policy(org_id, data)
    return jsonify(updated), 200


@readiness_bp.route('/classify/<incident_id>', methods=['POST'])
@role_required('admin', 'analyst', 'responder', 'auditor')
def classify_incident(incident_id):
    """Evaluates whether incident meets statutory reportability criteria under Proclamation 1426/2026."""
    org_id = _get_org_id()
    incident = CaseService.get_case(org_id, incident_id)
    if not incident:
        return jsonify({'error': 'Incident not found'}), 404

    data = request.get_json() or {}
    is_reportable, reason, diag = ReadinessService.evaluate_reportability(incident, data.get('custom_criteria'))
    return jsonify({
        'incident_id': incident_id,
        'is_reportable': is_reportable,
        'reason': reason,
        'diagnostics': diag
    }), 200


@readiness_bp.route('/confirm/<incident_id>', methods=['POST'])
@role_required('admin', 'analyst', 'responder')
def confirm_reportable(incident_id):
    """Analyst confirmation: explicitly flags reportable status and locks detection timestamp."""
    org_id = _get_org_id()
    data = request.get_json() or {}
    is_reportable = bool(data.get('is_reportable', True))
    reason = data.get('reason', 'Statutory criteria evaluated by lead responder.')

    officer_name = g.user.get('full_name') if hasattr(g, 'user') else 'SOC Lead'
    officer_role = g.user.get('role') if hasattr(g, 'user') else 'analyst'

    try:
        res = ReadinessService.confirm_reportable_status(
            org_id=org_id,
            incident_id=incident_id,
            is_reportable=is_reportable,
            reason=reason,
            officer_name=officer_name,
            officer_role=officer_role
        )
        return jsonify(res), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 404


@readiness_bp.route('/clock/<incident_id>', methods=['GET'])
@login_required
def get_48h_clock(incident_id):
    """Retrieves 48-hour statutory countdown clock diagnostics."""
    org_id = _get_org_id()
    incident = CaseService.get_case(org_id, incident_id)
    if not incident:
        return jsonify({'error': 'Incident not found'}), 404

    clock = ReadinessService.calculate_48h_clock(incident)
    return jsonify(clock), 200


@readiness_bp.route('/clock/escalate', methods=['POST'])
@role_required('admin', 'analyst')
def trigger_clock_escalation():
    """Triggers 48-hour clock escalation watchdog for milestone warnings."""
    org_id = _get_org_id()
    escalations = ReadinessService.check_48h_clock_escalations(org_id)
    return jsonify({'escalated_count': len(escalations), 'escalations': escalations}), 200


@readiness_bp.route('/ethiocert/generate/<incident_id>', methods=['POST'])
@role_required('admin', 'analyst', 'responder', 'auditor')
def generate_ethiocert_package(incident_id):
    """Generates official bilingual submission package conforming to ECS-IRS-v1.0."""
    org_id = _get_org_id()
    data = request.get_json() or {}

    officer = data.get('certifying_officer')
    if not officer and hasattr(g, 'user'):
        officer = {
            'certifying_officer_name': g.user.get('full_name', 'Lead Security Officer'),
            'certifying_officer_role': g.user.get('role', 'CISO')
        }

    try:
        pkg = ReadinessService.generate_ethiocert_report_package(org_id, incident_id, certifying_officer=officer)
        return jsonify(pkg), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 404


@readiness_bp.route('/ethiocert/submit/<incident_id>', methods=['POST'])
@role_required('admin', 'analyst')
def record_submission(incident_id):
    """Records formal submission to EthioCERT / INSA."""
    org_id = _get_org_id()
    data = request.get_json() or {}
    cert_ref = data.get('cert_reference_no')
    if not cert_ref:
        return jsonify({'error': 'cert_reference_no is required'}), 400

    channel = data.get('submission_channel', 'portal')
    officer = g.user.get('full_name') if hasattr(g, 'user') else 'CISO'

    try:
        res = ReadinessService.record_cert_submission(
            org_id=org_id,
            incident_id=incident_id,
            cert_reference_no=cert_ref,
            submission_channel=channel,
            officer_name=officer
        )
        return jsonify(res), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 404


@readiness_bp.route('/vault/<incident_id>', methods=['POST'])
@role_required('admin', 'analyst', 'responder')
def create_vault(incident_id):
    """Creates an immutable Evidence Vault snapshot with SHA-256 manifest seal."""
    org_id = _get_org_id()
    officer_name = g.user.get('full_name') if hasattr(g, 'user') else 'Forensic Lead'
    officer_role = g.user.get('role') if hasattr(g, 'user') else 'analyst'

    try:
        vault = ReadinessService.create_evidence_vault(
            org_id=org_id,
            incident_id=incident_id,
            officer_name=officer_name,
            officer_role=officer_role
        )
        return jsonify(vault), 201
    except ValueError as e:
        return jsonify({'error': str(e)}), 404


@readiness_bp.route('/vault/<vault_id_or_ref>', methods=['GET'])
@role_required('admin', 'analyst', 'responder', 'auditor')
def get_vault(vault_id_or_ref):
    """Retrieves an Evidence Vault by ID or report reference."""
    org_id = _get_org_id()
    vault = ReadinessService.get_evidence_vault(org_id, vault_id_or_ref)
    if not vault:
        return jsonify({'error': 'Evidence Vault not found'}), 404
    return jsonify(vault), 200


@readiness_bp.route('/vault/<vault_id>/verify', methods=['POST'])
@role_required('admin', 'analyst', 'responder', 'auditor')
def verify_vault(vault_id):
    """Verifies cryptographic SHA-256 manifest seal of Evidence Vault."""
    org_id = _get_org_id()
    actor_name = g.user.get('full_name') if hasattr(g, 'user') else 'Auditor'
    res = ReadinessService.verify_vault_integrity(org_id, vault_id, actor_name=actor_name)
    return jsonify(res), 200


@readiness_bp.route('/vault/<vault_id>/custody', methods=['GET'])
@role_required('admin', 'analyst', 'responder', 'auditor')
def list_custody(vault_id):
    """Lists chain-of-custody audit log for an Evidence Vault."""
    org_id = _get_org_id()
    records = ReadinessService.list_chain_of_custody(org_id, vault_id)
    return jsonify(records), 200


@readiness_bp.route('/obligations', methods=['GET'])
@login_required
def list_obligations():
    """Lists statutory obligation-to-evidence register."""
    obligations = ReadinessService.get_obligation_register()
    return jsonify(obligations), 200


@readiness_bp.route('/obligations/evaluation', methods=['GET'])
@login_required
def evaluate_compliance():
    """Evaluates compliance support readiness score and gap analysis."""
    org_id = _get_org_id()
    eval_res = ReadinessService.evaluate_compliance_readiness_support(org_id)
    return jsonify(eval_res), 200


@readiness_bp.route('/audit-pack', methods=['GET'])
@role_required('admin', 'analyst', 'auditor')
def get_audit_pack():
    """Compiles one-click sealed audit pack bundle for regulatory inspection."""
    org_id = _get_org_id()
    officer = g.user.get('full_name') if hasattr(g, 'user') else 'Regulatory Compliance Officer'
    pack = ReadinessService.generate_audit_pack(org_id, certifying_officer=officer)
    return jsonify(pack), 200
