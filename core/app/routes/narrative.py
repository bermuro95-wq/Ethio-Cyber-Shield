"""
Narrative & Explainability REST API Routes for Ethio-Cyber-Shield (ECS) v3.0 (Phase 8.1).
Endpoints:
  POST /api/narrative/incident/<incident_id>  - Generate explainable multilingual narrative
  GET  /api/narrative/incident/<incident_id>  - Retrieve cached narrative
"""
from flask import Blueprint, request, jsonify, g
from app.services.auth_service import login_required, role_required
from app.services.tenant_service import get_current_organization_id
from app.services.narrative_service import NarrativeService
import logging

logger = logging.getLogger(__name__)
narrative_bp = Blueprint('narrative', __name__)


def _get_org_id() -> str:
    org_id = g.user.get('organization_id') if hasattr(g, 'user') and g.user else None
    return str(org_id or get_current_organization_id() or "00000000-0000-0000-0000-000000000001")


@narrative_bp.route('/incident/<incident_id>', methods=['POST'])
@login_required
def generate_incident_narrative(incident_id):
    """Generates an explainable incident narrative in English, Amharic, or Afaan Oromo."""
    org_id = _get_org_id()
    data = request.get_json() or {}
    lang = data.get('language') or request.args.get('lang', 'en')

    try:
        narrative = NarrativeService.generate_incident_narrative(
            org_id=org_id,
            incident_id=incident_id,
            lang=lang
        )
        return jsonify(narrative), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 404


@narrative_bp.route('/incident/<incident_id>', methods=['GET'])
@login_required
def get_incident_narrative(incident_id):
    """Retrieves an existing cached narrative."""
    org_id = _get_org_id()
    lang = request.args.get('lang', 'en')

    narrative = NarrativeService.get_narrative(org_id=org_id, incident_id=incident_id, lang=lang)
    if not narrative:
        return jsonify({'error': 'Narrative not found. Generate first via POST.'}), 404

    return jsonify(narrative), 200
