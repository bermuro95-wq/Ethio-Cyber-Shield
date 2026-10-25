"""
Tenant Management API for Ethio-Cyber-Shield (ECS) SaaS Platform.
Provides multi-tenant organization onboarding, cross-tenant telemetry oversight,
isolated target system provisioning, and tenant user governance.
"""
from flask import Blueprint, request, jsonify, g
import logging
from app.services.auth_service import login_required, role_required
from app.services.tenant_mgmt_service import (
    is_superadmin,
    list_tenants_summary,
    get_tenant_detail,
    create_tenant,
    update_tenant,
    delete_tenant,
    generate_sdk_snippets
)
from app.services.db import get_service_supabase
from app.services.tenant_service import DEFAULT_ORGANIZATION_ID

logger = logging.getLogger(__name__)
tenants_bp = Blueprint('tenants', __name__)


@tenants_bp.route('', methods=['GET'])
@login_required
def get_all_tenants():
    """
    Returns summary list of all tenant organizations.
    Accessible to Superadmin. Regular tenant admins receive only their own organization.
    """
    if is_superadmin(g.user):
        summary = list_tenants_summary()
        return jsonify(summary), 200

    # Non-superadmin: return scoped tenant detail
    org_id = g.user.get('organization_id') or DEFAULT_ORGANIZATION_ID
    detail = get_tenant_detail(org_id)
    if not detail:
        return jsonify({'error': 'Organization not found'}), 404
    return jsonify([detail.get('organization')]), 200


@tenants_bp.route('', methods=['POST'])
@login_required
def register_new_tenant():
    """
    Provisions a new tenant organization in ECS SaaS platform.
    Requires Superadmin privileges.
    """
    if not is_superadmin(g.user):
        return jsonify({'error': 'Superadmin privileges required to register tenants'}), 403

    data = request.get_json() or {}
    try:
        result = create_tenant(data, creator_id=g.user.get('id'))
        return jsonify(result), 201
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Tenant registration failure: {e}", exc_info=True)
        return jsonify({'error': f'Failed to create tenant: {str(e)}'}), 500


@tenants_bp.route('/<tenant_id>', methods=['GET'])
@login_required
def get_single_tenant(tenant_id):
    """
    Retrieves full profile, connected targets, users, and posture metrics for a single tenant.
    """
    org_id = str(g.user.get('organization_id') or '')
    if not is_superadmin(g.user) and org_id != str(tenant_id):
        return jsonify({'error': 'Insufficient permissions for this tenant'}), 403

    detail = get_tenant_detail(tenant_id)
    if not detail:
        return jsonify({'error': 'Tenant not found'}), 404
    return jsonify(detail), 200


@tenants_bp.route('/<tenant_id>', methods=['PUT'])
@login_required
def update_single_tenant(tenant_id):
    """
    Updates tenant organization profile, sector, or activation state.
    """
    org_id = str(g.user.get('organization_id') or '')
    if not is_superadmin(g.user) and org_id != str(tenant_id):
        return jsonify({'error': 'Insufficient permissions to update this tenant'}), 403

    data = request.get_json() or {}
    try:
        updated = update_tenant(tenant_id, data, updater_id=g.user.get('id'))
        return jsonify(updated), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': f'Failed to update tenant: {str(e)}'}), 500


@tenants_bp.route('/<tenant_id>', methods=['DELETE'])
@login_required
def deactivate_tenant(tenant_id):
    """
    Soft-deactivates tenant organization. Superadmin only.
    """
    if not is_superadmin(g.user):
        return jsonify({'error': 'Superadmin privileges required'}), 403

    try:
        delete_tenant(tenant_id, deleter_id=g.user.get('id'))
        return jsonify({'message': f'Tenant {tenant_id} successfully deactivated'}), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        return jsonify({'error': f'Failed to deactivate tenant: {str(e)}'}), 500


@tenants_bp.route('/<tenant_id>/targets', methods=['GET'])
@login_required
def get_tenant_targets(tenant_id):
    """Lists target systems belonging to specified tenant."""
    org_id = str(g.user.get('organization_id') or '')
    if not is_superadmin(g.user) and org_id != str(tenant_id):
        return jsonify({'error': 'Insufficient permissions'}), 403

    sb = get_service_supabase()
    targets = []
    try:
        res = sb.table('target_systems').select('*').eq('organization_id', tenant_id).execute()
        targets = res.data or []
    except Exception:
        from app.services.target_system_service import _LOCAL_TARGETS
        targets = [t for t in _LOCAL_TARGETS.values() if str(t.get('organization_id') or '') == str(tenant_id)]

    # Mask secrets
    for t in targets:
        sec = t.get('secret_key') or ''
        t['secret_key_masked'] = f"{sec[:4]}...{sec[-4:]}" if len(sec) >= 8 else '****'
        t.pop('secret_key', None)

    return jsonify(targets), 200


@tenants_bp.route('/<tenant_id>/users', methods=['GET'])
@login_required
def get_tenant_users(tenant_id):
    """Lists users belonging to specified tenant."""
    org_id = str(g.user.get('organization_id') or '')
    if not is_superadmin(g.user) and org_id != str(tenant_id):
        return jsonify({'error': 'Insufficient permissions'}), 403

    sb = get_service_supabase()
    users = []
    try:
        res = sb.table('users').select('id, organization_id, email, full_name, role, is_active, created_at').eq('organization_id', tenant_id).order('created_at', desc=True).execute()
        users = res.data or []
    except Exception as e:
        logger.debug(f"Tenant users lookup fallback: {e}")

    return jsonify(users), 200


@tenants_bp.route('/<tenant_id>/sdk-snippets', methods=['GET'])
@login_required
def get_sdk_snippets_route(tenant_id):
    """Generates pre-populated SDK code snippets for target integration."""
    org_id = str(g.user.get('organization_id') or '')
    if not is_superadmin(g.user) and org_id != str(tenant_id):
        return jsonify({'error': 'Insufficient permissions'}), 403

    detail = get_tenant_detail(tenant_id)
    if not detail or not detail.get('organization'):
        return jsonify({'error': 'Tenant not found'}), 404

    targets = detail.get('targets') or []
    first_target = targets[0] if targets else {
        'name': f"{detail['organization'].get('name')} Switch",
        'key_id': f"ecs_{detail['organization'].get('slug', 'app')[:8]}_key"
    }

    snippets = generate_sdk_snippets(
        detail['organization'],
        first_target,
        first_target.get('secret_key') or 'YOUR_HMAC_SECRET_KEY'
    )
    return jsonify(snippets), 200
