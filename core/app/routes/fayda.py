"""
National Identity Assurance (Fayda Digital ID) REST API Routes for Ethio-Cyber-Shield (ECS) v3.0 (Phase 8.4).
Endpoints:
  POST /api/fayda/verify               - Ingest Fayda ID verification event
  GET  /api/fayda/account/<account_no> - Get account identity assurance status
"""
from flask import Blueprint, request, jsonify, g
from app.services.auth_service import login_required, role_required
from app.services.tenant_service import get_current_organization_id
from app.services.fayda_id_service import FaydaIdService
import logging

logger = logging.getLogger(__name__)
fayda_bp = Blueprint('fayda', __name__)


def _get_org_id() -> str:
    org_id = g.user.get('organization_id') if hasattr(g, 'user') and g.user else None
    return str(org_id or get_current_organization_id() or "00000000-0000-0000-0000-000000000001")


@fayda_bp.route('/verify', methods=['POST'])
@login_required
def ingest_fayda_verification():
    """Ingests a Fayda authentication verification event and outputs identity assurance weighting."""
    org_id = _get_org_id()
    data = request.get_json() or {}

    fayda_fin = data.get('fayda_fin')
    account_number = data.get('account_number')
    auth_mode = data.get('auth_mode', 'demographic')
    auth_status = data.get('auth_status', 'verified')

    if not fayda_fin or not account_number:
        return jsonify({'error': 'fayda_fin and account_number are required'}), 400

    record = FaydaIdService.ingest_verification_event(
        org_id=org_id,
        fayda_fin=fayda_fin,
        account_number=account_number,
        auth_mode=auth_mode,
        auth_status=auth_status,
        kyc_tier=data.get('kyc_tier', 'tier_3'),
        ip_address=data.get('ip_address')
    )
    return jsonify(record), 201


@fayda_bp.route('/account/<account_number>', methods=['GET'])
@login_required
def get_account_assurance(account_number):
    """Retrieves identity assurance status and risk adjustment for an account."""
    org_id = _get_org_id()
    assurance = FaydaIdService.get_account_identity_assurance(org_id=org_id, account_number=account_number)
    return jsonify({'organization_id': org_id, 'identity_assurance': assurance}), 200
