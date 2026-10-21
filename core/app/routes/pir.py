"""
Post-Incident Review (PIR) REST API Routes for Ethio-Cyber-Shield (ECS) v3.0 (Phase 4.7).
Endpoints:
  POST /api/pir/generate/<incident_id>    - Auto-compile formal Post-Incident Review
  GET  /api/pir/<pir_id>                  - Retrieve PIR by ID
  GET  /api/pir/incident/<incident_id>    - Retrieve PIR for a given incident
  PUT  /api/pir/<pir_id>                  - Update draft PIR sections
  POST /api/pir/<pir_id>/seal             - Cryptographically lock & SHA-256 seal PIR
  GET  /api/pir/<pir_id>/verify           - Verify SHA-256 cryptographic seal
  GET  /api/pir/<pir_id>/export/markdown  - Export bilingual Amharic/English Markdown document
"""
from flask import Blueprint, request, jsonify, g, Response
from app.services.auth_service import login_required, role_required
from app.services.pir_service import PIRService
from app.services.tenant_service import get_current_organization_id
import logging

logger = logging.getLogger(__name__)
pir_bp = Blueprint('pir', __name__)


def _get_org_id() -> str:
    org_id = g.user.get('organization_id') if hasattr(g, 'user') and g.user else None
    return str(org_id or get_current_organization_id() or "00000000-0000-0000-0000-000000000001")


@pir_bp.route('/generate/<incident_id>', methods=['POST'])
@role_required('admin', 'analyst', 'responder')
def generate_pir(incident_id):
    """Compiles a formal Post-Incident Review for a contained or resolved incident."""
    org_id = _get_org_id()
    user_id = g.user.get('id') if hasattr(g, 'user') else None

    try:
        pir = PIRService.generate_pir(org_id, incident_id, created_by=user_id)
        return jsonify(pir), 201
    except ValueError as e:
        return jsonify({'error': str(e)}), 404


@pir_bp.route('/<pir_id>', methods=['GET'])
@login_required
def get_pir(pir_id):
    """Retrieves a PIR by ID."""
    org_id = _get_org_id()
    pir = PIRService.get_pir(org_id, pir_id)
    if not pir:
        return jsonify({'error': 'Post-Incident Review not found'}), 404
    return jsonify(pir), 200


@pir_bp.route('/incident/<incident_id>', methods=['GET'])
@login_required
def get_pir_by_incident(incident_id):
    """Retrieves the PIR for a specific incident."""
    org_id = _get_org_id()
    pir = PIRService.get_pir_by_incident(org_id, incident_id)
    if not pir:
        return jsonify({'error': 'PIR for this incident not found'}), 404
    return jsonify(pir), 200


@pir_bp.route('/<pir_id>', methods=['PUT'])
@role_required('admin', 'analyst', 'responder')
def update_pir(pir_id):
    """Updates editable sections of a draft PIR before sealing."""
    org_id = _get_org_id()
    data = request.get_json() or {}
    user_id = g.user.get('id') if hasattr(g, 'user') else None

    try:
        updated = PIRService.update_pir(org_id, pir_id, data, user_id=user_id)
        return jsonify(updated), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


@pir_bp.route('/<pir_id>/seal', methods=['POST'])
@role_required('admin', 'analyst')
def seal_pir(pir_id):
    """Cryptographically locks the PIR with a SHA-256 seal."""
    org_id = _get_org_id()
    user_id = g.user.get('id') if hasattr(g, 'user') else None

    try:
        sealed = PIRService.seal_pir(org_id, pir_id, user_id=user_id)
        return jsonify(sealed), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


@pir_bp.route('/<pir_id>/verify', methods=['GET'])
@login_required
def verify_pir_seal(pir_id):
    """Verifies SHA-256 cryptographic seal integrity."""
    org_id = _get_org_id()
    res = PIRService.verify_pir_seal(org_id, pir_id)
    return jsonify(res), 200


@pir_bp.route('/<pir_id>/export/markdown', methods=['GET'])
@login_required
def export_pir_markdown(pir_id):
    """Exports the PIR as a formatted bilingual Markdown document."""
    org_id = _get_org_id()
    try:
        md_text = PIRService.export_pir_markdown(org_id, pir_id)
        return Response(md_text, mimetype='text/markdown', headers={
            'Content-Disposition': f'inline; filename="PIR_{pir_id}.md"'
        })
    except ValueError as e:
        return jsonify({'error': str(e)}), 404
