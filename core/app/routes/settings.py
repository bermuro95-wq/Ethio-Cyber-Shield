from flask import Blueprint, request, jsonify, g
from app.services.auth_service import login_required, role_required
from app.services.db import get_service_supabase
from app.services.audit_service import log_action
from app.services.security_rules import get_fraud_thresholds
from app.services.tenant_service import get_current_organization_id
from app.services.editions_service import EditionsService
from app.services.i18n_service import I18nService

settings_bp = Blueprint('settings', __name__)

DEFAULT_FRAUD = {
    'high_amount': 500000,
    'critical_amount': 1500000,
    'night_amount': 200000,
    'burst_count': 4,
    'burst_window_minutes': 30,
    'velocity_amount': 800000,
    'new_device_amount': 200000,
    'multi_account_device': 3,
    'shared_ip_accounts': 4,
    'large_withdrawal': 300000,
    'rapid_transfer_amount': 150000,
    'rapid_window_minutes': 10,
}


def _get_org_id() -> str:
    org_id = g.user.get('organization_id') if hasattr(g, 'user') and g.user else None
    return str(org_id or get_current_organization_id() or "00000000-0000-0000-0000-000000000001")


@settings_bp.route('/fraud-rules', methods=['GET'])
@login_required
def get_fraud_rules():
    return jsonify(get_fraud_thresholds())


@settings_bp.route('/fraud-rules', methods=['PUT'])
@role_required('admin')
def update_fraud_rules():
    data = request.get_json() or {}
    current = get_fraud_thresholds()
    updated = dict(current)
    for k, default in DEFAULT_FRAUD.items():
        if k in data:
            try:
                if isinstance(default, int) and not isinstance(default, bool):
                    updated[k] = int(data[k])
                else:
                    updated[k] = float(data[k])
            except (TypeError, ValueError):
                return jsonify({'error': f'Invalid value for {k}'}), 400
            if updated[k] < 0:
                return jsonify({'error': f'{k} must be >= 0'}), 400
    sb = get_service_supabase()
    # upsert
    existing = sb.table('system_settings').select('key').eq('key', 'fraud_rules').execute()
    payload = {'key': 'fraud_rules', 'value': updated, 'updated_by': g.user['id']}
    if existing.data:
        sb.table('system_settings').update({'value': updated, 'updated_by': g.user['id']}).eq('key', 'fraud_rules').execute()
    else:
        sb.table('system_settings').insert(payload).execute()
    log_action(g.user['id'], 'settings_updated', 'settings', None, {'fraud_rules': updated})
    return jsonify(updated)


# =============================================================================
# PHASE 7.1 EDITIONS & ENTITLEMENTS ROUTES
# =============================================================================

@settings_bp.route('/editions', methods=['GET'])
@login_required
def get_editions_settings():
    """Lists available editions and returns current tenant edition & entitlements."""
    org_id = _get_org_id()
    current_edition = EditionsService.get_tenant_edition(org_id)
    return jsonify({
        'organization_id': org_id,
        'current_edition': current_edition,
        'available_editions': EditionsService.list_editions()
    }), 200


@settings_bp.route('/editions', methods=['PUT'])
@role_required('admin')
def update_tenant_edition():
    """Updates the active edition for the current tenant."""
    org_id = _get_org_id()
    data = request.get_json() or {}
    edition_id = data.get('edition') or data.get('edition_id')
    if not edition_id:
        return jsonify({'error': 'Missing edition_id in request body'}), 400

    try:
        updated_edition = EditionsService.set_tenant_edition(org_id, edition_id)
        user_id = g.user.get('id') if hasattr(g, 'user') else 'admin'
        log_action(user_id, 'edition_updated', 'organization', org_id, {'edition': edition_id})
        return jsonify({
            'message': f"Organization edition updated to {edition_id}",
            'organization_id': org_id,
            'edition': updated_edition
        }), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 400


# =============================================================================
# PHASE 7.4 MULTILINGUAL (i18n) TERMINOLOGY ROUTES
# =============================================================================

@settings_bp.route('/i18n', methods=['GET'])
@login_required
def get_i18n_settings():
    """Returns supported languages and glossary translations."""
    lang = request.args.get('lang', 'en').lower().strip()
    return jsonify({
        'supported_languages': I18nService.list_languages(),
        'active_language': lang,
        'translations': I18nService.get_translations(lang)
    }), 200
