from flask import Blueprint, request, jsonify, g
import jwt
import logging
import re
from datetime import datetime, timezone, timedelta
from app.config import Config
from app.services.auth_service import (
    authenticate_user, create_token, login_required, role_required,
    create_user, get_current_user, revoke_token, clear_user_active_session,
    generate_totp_secret, get_totp_uri, verify_totp_code,
    create_scoped_api_token, verify_scoped_api_token, revoke_api_token,
    VALID_ROLES, _USER_MFA_SECRETS
)
from app.services.crypto_service import encrypt_secret, decrypt_secret
from app.services.audit_service import log_action
from app.services.db import get_service_supabase
from app.services.tenant_service import DEFAULT_ORGANIZATION_ID
from app.services.tenant_mgmt_service import is_superadmin

logger = logging.getLogger(__name__)
auth_bp = Blueprint('auth', __name__)

def _enrich_user_payload(u: dict) -> dict:
    org_id = u.get('organization_id') or DEFAULT_ORGANIZATION_ID
    is_sup = is_superadmin(u)
    org_name = 'Commercial Bank of Ethiopia (Primary)'
    if org_id:
        try:
            sb = get_service_supabase()
            res = sb.table('organizations').select('name').eq('id', str(org_id)).execute()
            if res.data and res.data[0].get('name'):
                org_name = res.data[0]['name']
        except Exception:
            pass
    return {
        'id': u.get('id'),
        'email': u.get('email'),
        'full_name': u.get('full_name'),
        'role': u.get('role'),
        'organization_id': org_id,
        'organization_name': org_name,
        'is_superadmin': is_sup
    }

SQLI_PATTERNS = [
    re.compile(r"""(?:'\s*(?:or|and)\s+(?:'?[^'\s]+'?\s*=\s*'?[^'\s]+'?|\d+\s*=\s*\d+|true|false))""", re.I),
    re.compile(r"""(?:'\s*or\s+''=')""", re.I),
    re.compile(r"""(?:\b(?:or|and)\b\s+['"]?[\w]+['"]?\s*=\s*['"]?[\w]+['"]?)""", re.I),
    re.compile(r"""(?:['"]\s*(?:--|#|\/\*))""", re.I),
    re.compile(r"""(?:--\s*$)""", re.I),
    re.compile(r"""(?:\bunion\b\s+(?:all\s+)?\bselect\b)""", re.I),
    re.compile(r"""(?:;\s*(?:drop|alter|truncate|delete|insert|update|exec|execute|declare|select)\b)""", re.I),
    re.compile(r"""(?:\b(?:sleep|pg_sleep|waitfor\s+delay|benchmark)\s*\(?)""", re.I),
    re.compile(r"""(?:\b(?:schema|information_schema|database\(\)|version\(\)|user\(\)|load_file|into\s+outfile|xp_cmdshell)\b)""", re.I),
    re.compile(r"""(?:\b(?:extractvalue|updatexml|floor\(rand)\b)""", re.I),
    re.compile(r"""(?:0x[0-9a-fA-F]{4,}|\bchar\(\d+)""", re.I),
]

def check_sqli_attack(text: str) -> tuple[bool, str]:
    if not text or not isinstance(text, str):
        return False, ""
    for pat in SQLI_PATTERNS:
        m = pat.search(text)
        if m:
            return True, m.group(0)
    return False, ""

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    raw_email = str(data.get('email') or '').strip()
    email = raw_email.lower()
    password = str(data.get('password') or '')

    # 1. Proactive Web Application Parameter Injection (SQLi) Detection on ECS Login
    is_sqli_user, user_sample = check_sqli_attack(raw_email)
    is_sqli_pass, pass_sample = check_sqli_attack(password)

    if is_sqli_user or is_sqli_pass:
        field_name = 'email' if is_sqli_user else 'password'
        detected_sample = user_sample if is_sqli_user else '[REDACTED_PASSWORD_SQLI]'
        log_action(None, 'sqli_login_attempt_blocked', details={
            'field': field_name,
            'sample': detected_sample[:80],
            'endpoint': request.path
        })
        try:
            from app.services.event_service import ingest_event
            import uuid
            ingest_event({
                'event_id': f"ev-sqli-{uuid.uuid4().hex[:12]}",
                'event_type': 'SUSPICIOUS_PARAMETER_PATTERN',
                'source_system': 'ECS Admin Portal',
                'user_id': raw_email[:60] if raw_email else 'anonymous',
                'account_id': raw_email[:60] if raw_email else 'anonymous',
                'source_ip': request.remote_addr or '127.0.0.1',
                'endpoint': request.path,
                'result': 'BLOCKED',
                'attributes': {
                    'pattern_class': 'SQLI',
                    'field_name': field_name,
                    'sample': detected_sample[:80],
                    'attack_type': 'SQL_INJECTION',
                    'payload': detected_sample[:100],
                    'identifier': raw_email[:60],
                    'user_agent': request.headers.get('User-Agent', '')
                }
            })
            ingest_event({
                'event_id': f"ev-auth-{uuid.uuid4().hex[:12]}",
                'event_type': 'LOGIN_FAILED',
                'source_system': 'ECS Admin Portal',
                'user_id': raw_email[:60] if raw_email else 'anonymous',
                'account_id': raw_email[:60] if raw_email else 'anonymous',
                'source_ip': request.remote_addr or '127.0.0.1',
                'endpoint': request.path,
                'result': 'FAILURE',
                'attributes': {
                    'identifier': raw_email[:60],
                    'failure_reason': 'SQL_INJECTION_ATTEMPT',
                    'consecutive_failures_for_identifier': 1,
                    'user_agent': request.headers.get('User-Agent', '')
                }
            })
        except Exception as e_ev:
            logger.error(f"Failed to ingest login SQLi event: {e_ev}")

        return jsonify({
            'error': 'Malicious SQL injection signature detected in authentication request. Event recorded in SOC telemetry.',
            'code': 'SQL_INJECTION_DETECTED'
        }), 400

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    user = authenticate_user(email, password)
    if not user:
        log_action(None, 'login_failed', details={'email': email})
        try:
            from app.services.event_service import ingest_event
            import uuid
            ingest_event({
                'event_id': f"ev-auth-{uuid.uuid4().hex[:12]}",
                'event_type': 'LOGIN_FAILED',
                'source_system': 'ECS Admin Portal',
                'user_id': email,
                'account_id': email,
                'source_ip': request.remote_addr or '127.0.0.1',
                'endpoint': request.path,
                'result': 'FAILURE',
                'attributes': {
                    'identifier': email,
                    'failure_reason': 'BAD_PASSWORD',
                    'consecutive_failures_for_identifier': 1,
                    'user_agent': request.headers.get('User-Agent', '')
                }
            })
        except Exception as e_ev:
            logger.debug(f"Auth failure ingest notice: {e_ev}")
        return jsonify({'error': 'Invalid credentials'}), 401

    # Check if MFA is required for this user
    if user.get('mfa_enabled'):
        challenge_token = jwt.encode({
            'sub': user['id'],
            'email': user['email'],
            'role': user['role'],
            'organization_id': user.get('organization_id'),
            'mfa_pending': True,
            'exp': datetime.now(timezone.utc) + timedelta(minutes=5)
        }, Config.JWT_SECRET, algorithm='HS256')
        return jsonify({
            'mfa_required': True,
            'mfa_token': challenge_token,
            'message': 'Two-factor authentication code required'
        })

    token = create_token(user['id'], user['email'], user['role'], user.get('organization_id'))
    log_action(user['id'], 'login_success', details={'email': email})

    return jsonify({
        'token': token,
        'user': _enrich_user_payload(user)
    })

@auth_bp.route('/mfa/verify', methods=['POST'])
def verify_mfa_login():
    """Validates 6-digit TOTP challenge during login and issues full JWT token."""
    data = request.get_json() or {}
    mfa_token = data.get('mfa_token')
    code = data.get('code')

    if not mfa_token or not code:
        return jsonify({'error': 'mfa_token and code are required'}), 400

    try:
        payload = jwt.decode(mfa_token, Config.JWT_SECRET, algorithms=['HS256'])
        if not payload.get('mfa_pending'):
            return jsonify({'error': 'Invalid challenge token'}), 400
    except Exception:
        return jsonify({'error': 'Challenge expired or invalid'}), 401

    sb = get_service_supabase()
    res = sb.table('users').select('*').eq('id', payload['sub']).execute()
    if not res.data:
        return jsonify({'error': 'User not found'}), 404

    user = res.data[0]
    secret = user.get('mfa_secret')
    if secret and secret.startswith('enc:'):
        secret = decrypt_secret(secret)

    if not verify_totp_code(secret, code):
        return jsonify({'error': 'Invalid authentication code'}), 401

    full_token = create_token(user['id'], user['email'], user['role'], user.get('organization_id'))
    log_action(user['id'], 'mfa_login_success', details={'email': user['email']})
    return jsonify({
        'token': full_token,
        'user': _enrich_user_payload(user)
    })

@auth_bp.route('/mfa/setup', methods=['POST'])
@login_required
def setup_mfa():
    """Generates a new TOTP secret and provisioning URI for the authenticated user."""
    secret = generate_totp_secret()
    uri = get_totp_uri(secret, g.user['email'])
    return jsonify({
        'secret': secret,
        'uri': uri,
        'issuer': 'Ethio-Cyber-Shield'
    })

@auth_bp.route('/mfa/enable', methods=['POST'])
@login_required
def enable_mfa():
    """Verifies initial code and saves encrypted TOTP secret to user profile."""
    data = request.get_json() or {}
    secret = data.get('secret')
    code = data.get('code')

    if not secret or not code:
        return jsonify({'error': 'secret and code are required'}), 400

    if not verify_totp_code(secret, code):
        return jsonify({'error': 'Verification failed: invalid code'}), 400

    encrypted = encrypt_secret(secret)
    _USER_MFA_SECRETS[str(g.user['id'])] = encrypted
    sb = get_service_supabase()
    try:
        sb.table('users').update({
            'mfa_enabled': True,
            'mfa_secret': encrypted
        }).eq('id', g.user['id']).execute()
    except Exception as e:
        logger.debug(f"MFA profile save fallback: {e}")

    log_action(g.user['id'], 'mfa_enabled')
    return jsonify({'message': 'MFA successfully enabled'})

@auth_bp.route('/logout', methods=['POST'])
@login_required
def logout():
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        revoke_token(auth_header[7:].strip())
    if hasattr(g, 'user') and g.user and g.user.get('id'):
        clear_user_active_session(g.user['id'])
    log_action(g.user['id'], 'logout')
    return jsonify({'message': 'Logged out successfully'})

@auth_bp.route('/me', methods=['GET'])
@login_required
def me():
    sb = get_service_supabase()
    try:
        res = sb.table('users').select('id, email, full_name, role, organization_id, created_at').eq('id', g.user['id']).execute()
    except Exception:
        res = sb.table('users').select('*').eq('id', g.user['id']).execute()
    if not res.data:
        return jsonify({'error': 'User not found'}), 404
    user_data = dict(res.data[0])
    user_data.pop('password_hash', None)
    return jsonify(_enrich_user_payload(user_data))

@auth_bp.route('/users', methods=['POST'])
@role_required('admin')
def create_new_user():
    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''
    full_name = (data.get('full_name') or '').strip()
    role = data.get('role', 'viewer')
    target_org = data.get('organization_id')

    if not email or not password or not full_name:
        return jsonify({'error': 'email, password and full_name are required'}), 400
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    if role not in VALID_ROLES:
        return jsonify({'error': f'Invalid role. Allowed: {VALID_ROLES}'}), 400

    # Superadmin can assign user to any organization; regular admin assigns to own
    if is_superadmin(g.user):
        org_id = target_org or g.user.get('organization_id') or DEFAULT_ORGANIZATION_ID
    else:
        org_id = g.user.get('organization_id') or DEFAULT_ORGANIZATION_ID

    user = create_user(email, password, full_name, role, organization_id=org_id)
    if not user:
        return jsonify({'error': 'Could not create user (email may already exist)'}), 400

    log_action(g.user['id'], 'user_created', 'user', user['id'], {'email': email, 'role': role, 'organization_id': org_id})
    return jsonify({
        'id': user['id'],
        'email': user['email'],
        'full_name': user['full_name'],
        'role': user['role'],
        'organization_id': user.get('organization_id')
    }), 201

@auth_bp.route('/users', methods=['GET'])
@role_required('admin', 'analyst')
def list_users():
    sb = get_service_supabase()
    is_sup = is_superadmin(g.user)
    requested_org = request.args.get('organization_id')

    # Build organizations map for name display
    org_map = {}
    try:
        org_res = sb.table('organizations').select('id, name, slug').execute()
        for o in (org_res.data or []):
            org_map[str(o.get('id'))] = {
                'name': o.get('name'),
                'slug': o.get('slug')
            }
    except Exception:
        pass

    query = sb.table('users').select('id, email, full_name, role, is_active, created_at, organization_id')

    if is_sup:
        if requested_org and requested_org != 'all':
            query = query.eq('organization_id', requested_org)
    else:
        org_id = g.user.get('organization_id') or DEFAULT_ORGANIZATION_ID
        query = query.eq('organization_id', org_id)

    try:
        res = query.order('created_at', desc=True).execute()
        users = res.data or []
    except Exception:
        try:
            res = sb.table('users').select('id, email, full_name, role, is_active, created_at').order('created_at', desc=True).execute()
            users = res.data or []
        except Exception:
            users = []

    # Resolve organization_id for all users (handling fallback when column is missing in DB)
    from app.services.auth_service import _USER_ORGS
    for u in users:
        if not u.get('organization_id'):
            u['organization_id'] = _USER_ORGS.get(str(u.get('id'))) or _USER_ORGS.get(u.get('email')) or DEFAULT_ORGANIZATION_ID

    # Filter out by org for non-superadmins or when specific org is requested
    if is_sup:
        if requested_org and requested_org != 'all':
            users = [u for u in users if str(u.get('organization_id')) == str(requested_org)]
    else:
        my_org = str(g.user.get('organization_id') or DEFAULT_ORGANIZATION_ID)
        users = [u for u in users if str(u.get('organization_id')) == my_org]

    # Annotate organization name and slug
    for u in users:
        oid = str(u.get('organization_id') or DEFAULT_ORGANIZATION_ID)
        ometa = org_map.get(oid, {})
        u['organization_name'] = ometa.get('name') or ('Commercial Bank of Ethiopia (Primary)' if oid == DEFAULT_ORGANIZATION_ID else 'Organization')
        u['organization_slug'] = ometa.get('slug') or 'cbe'

    return jsonify(users)

@auth_bp.route('/users/<user_id>', methods=['PUT'])
@role_required('admin')
def update_user_endpoint(user_id):
    data = request.get_json() or {}
    sb = get_service_supabase()

    try:
        res = sb.table('users').select('*').eq('id', user_id).execute()
        if not res.data:
            return jsonify({'error': 'User not found'}), 404
        existing = res.data[0]
    except Exception as e:
        return jsonify({'error': f'User lookup failed: {e}'}), 500

    is_sup = is_superadmin(g.user)
    if not is_sup and str(existing.get('organization_id')) != str(g.user.get('organization_id')):
        return jsonify({'error': 'Insufficient permissions for this user'}), 403

    updates = {}
    if 'full_name' in data and data['full_name']:
        updates['full_name'] = str(data['full_name']).strip()
    if 'role' in data and data['role'] in VALID_ROLES:
        updates['role'] = data['role']
    if 'is_active' in data:
        updates['is_active'] = bool(data['is_active'])
    if 'organization_id' in data and is_sup:
        updates['organization_id'] = data['organization_id']

    if updates:
        try:
            up_res = sb.table('users').update(updates).eq('id', user_id).execute()
            log_action(g.user['id'], 'user_updated', 'user', user_id, updates)
            ret = up_res.data[0] if up_res.data else {**existing, **updates}
            ret.pop('password_hash', None)
            return jsonify(ret), 200
        except Exception as e:
            return jsonify({'error': f'Failed to update user: {e}'}), 500

    existing.pop('password_hash', None)
    return jsonify(existing), 200

@auth_bp.route('/users/<user_id>/reset-password', methods=['POST'])
@role_required('admin')
def reset_user_password_endpoint(user_id):
    data = request.get_json() or {}
    new_password = str(data.get('password') or '')
    if not new_password or len(new_password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400

    sb = get_service_supabase()
    try:
        res = sb.table('users').select('*').eq('id', user_id).execute()
        if not res.data:
            return jsonify({'error': 'User not found'}), 404
        existing = res.data[0]
    except Exception:
        return jsonify({'error': 'User lookup failed'}), 500

    is_sup = is_superadmin(g.user)
    if not is_sup and str(existing.get('organization_id')) != str(g.user.get('organization_id')):
        return jsonify({'error': 'Insufficient permissions for this user'}), 403

    new_hash = hash_password(new_password)
    try:
        sb.table('users').update({'password_hash': new_hash}).eq('id', user_id).execute()
        log_action(g.user['id'], 'password_reset_by_admin', 'user', user_id)
        return jsonify({'message': 'Password successfully reset'}), 200
    except Exception as e:
        return jsonify({'error': f'Failed to reset password: {e}'}), 500

@auth_bp.route('/users/<user_id>', methods=['DELETE'])
@role_required('admin')
def delete_user_endpoint(user_id):
    sb = get_service_supabase()
    try:
        res = sb.table('users').select('*').eq('id', user_id).execute()
        if not res.data:
            return jsonify({'error': 'User not found'}), 404
        existing = res.data[0]
    except Exception:
        return jsonify({'error': 'User lookup failed'}), 500

    is_sup = is_superadmin(g.user)
    if not is_sup and str(existing.get('organization_id')) != str(g.user.get('organization_id')):
        return jsonify({'error': 'Insufficient permissions for this user'}), 403

    if str(user_id) == str(g.user.get('id')):
        return jsonify({'error': 'Cannot delete your own administrator account'}), 400

    try:
        sb.table('users').update({'is_active': False}).eq('id', user_id).execute()
        log_action(g.user['id'], 'user_deactivated', 'user', user_id)
        return jsonify({'message': f'User {user_id} successfully deactivated'}), 200
    except Exception as e:
        return jsonify({'error': f'Failed to deactivate user: {e}'}), 500

@auth_bp.route('/api-tokens', methods=['POST'])
@role_required('admin')
def create_api_token_endpoint():
    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    scopes = data.get('scopes') or ['ingest:events']
    expires_days = int(data.get('expires_days', 90))

    if not name:
        return jsonify({'error': 'name is required'}), 400

    token_info = create_scoped_api_token(
        name=name,
        organization_id=g.user.get('organization_id'),
        scopes=scopes,
        expires_days=expires_days
    )
    log_action(g.user['id'], 'api_token_created', 'api_token', token_info['token_id'], {'name': name, 'scopes': scopes})
    return jsonify(token_info), 201

@auth_bp.route('/api-tokens', methods=['GET'])
@role_required('admin')
def list_api_tokens_endpoint():
    from app.services.auth_service import _API_TOKENS
    org_id = g.user.get('organization_id')
    sb = get_service_supabase()
    tokens = []
    try:
        q = sb.table('api_tokens').select('id, name, scopes, created_at, expires_at, revoked, organization_id')
        if org_id:
            q = q.eq('organization_id', org_id)
        res = q.order('created_at', desc=True).execute()
        tokens = res.data or []
    except Exception:
        pass

    if not tokens:
        tokens = [
            {
                'id': rec['id'],
                'name': rec['name'],
                'scopes': rec['scopes'],
                'created_at': rec['created_at'],
                'expires_at': rec['expires_at'],
                'revoked': rec.get('revoked', False),
                'organization_id': rec['organization_id']
            }
            for rec in _API_TOKENS.values()
            if not org_id or str(rec.get('organization_id')) == str(org_id)
        ]
    return jsonify(tokens)

@auth_bp.route('/api-tokens/<token_id>', methods=['DELETE'])
@role_required('admin')
def revoke_api_token_endpoint(token_id):
    revoke_api_token(token_id, g.user.get('organization_id'))
    log_action(g.user['id'], 'api_token_revoked', 'api_token', token_id)
    return jsonify({'message': 'API token revoked successfully'})


@auth_bp.route('/forgot-password', methods=['POST'])
def forgot_password():
    """Request a password reset token. Stores token in Supabase. For MVP, returns reset link in response for testing."""
    import secrets
    from datetime import datetime, timedelta, timezone
    from app.services.auth_service import hash_password  # noqa: F401 - not used here

    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    if not email:
        return jsonify({'error': 'Email is required'}), 400

    sb = get_service_supabase()
    result = sb.table('users').select('id, email, is_active').eq('email', email).eq('is_active', True).execute()

    # Always return same message to avoid email enumeration
    generic_msg = 'If an account exists with that email, a password reset link has been generated.'

    if not result.data:
        log_action(None, 'forgot_password_unknown', details={'email': email})
        return jsonify({'message': generic_msg, 'reset_token': None})

    user = result.data[0]
    token = secrets.token_urlsafe(32)
    expires = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()

    # Invalidate previous unused tokens for this user
    try:
        sb.table('password_reset_tokens').delete().eq('user_id', user['id']).is_('used_at', 'null').execute()
    except Exception:
        pass

    sb.table('password_reset_tokens').insert({
        'user_id': user['id'],
        'token': token,
        'expires_at': expires
    }).execute()

    log_action(user['id'], 'forgot_password_requested', details={'email': email})

    # MVP: return token so frontend can show reset link (production would email it)
    return jsonify({
        'message': generic_msg,
        'reset_token': token,
        'expires_in_minutes': 60
    })


@auth_bp.route('/reset-password', methods=['POST'])
def reset_password():
    """Reset password using a valid token stored in Supabase."""
    from datetime import datetime, timezone
    from app.services.auth_service import hash_password

    data = request.get_json() or {}
    token = (data.get('token') or '').strip()
    new_password = data.get('password') or ''

    if not token:
        return jsonify({'error': 'Reset token is required'}), 400
    if len(new_password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400

    sb = get_service_supabase()
    res = sb.table('password_reset_tokens').select('*').eq('token', token).execute()
    if not res.data:
        return jsonify({'error': 'Invalid or expired reset token'}), 400

    row = res.data[0]
    if row.get('used_at'):
        return jsonify({'error': 'This reset link has already been used'}), 400

    expires = row.get('expires_at')
    if expires:
        from dateutil import parser
        exp_dt = parser.isoparse(expires)
        if exp_dt.tzinfo is None:
            exp_dt = exp_dt.replace(tzinfo=timezone.utc)
        if datetime.now(timezone.utc) > exp_dt:
            return jsonify({'error': 'Reset token has expired. Please request a new one.'}), 400

    password_hash = hash_password(new_password)
    sb.table('users').update({'password_hash': password_hash}).eq('id', row['user_id']).execute()
    sb.table('password_reset_tokens').update({
        'used_at': datetime.now(timezone.utc).isoformat()
    }).eq('id', row['id']).execute()

    log_action(row['user_id'], 'password_reset_success')
    return jsonify({'message': 'Password has been reset successfully. You can now log in.'})


@auth_bp.route('/users/<user_id>', methods=['PUT'])
@role_required('admin')
def update_user(user_id):
    data = request.get_json() or {}
    sb = get_service_supabase()
    existing = sb.table('users').select('*').eq('id', user_id).execute()
    if not existing.data:
        return jsonify({'error': 'User not found'}), 404
    updates = {}
    if 'full_name' in data and str(data['full_name']).strip():
        updates['full_name'] = str(data['full_name']).strip()[:255]
    if 'role' in data:
        if data['role'] not in ('admin', 'analyst', 'viewer'):
            return jsonify({'error': 'Invalid role. Use admin, analyst, or viewer'}), 400
        updates['role'] = data['role']
    if 'is_active' in data:
        updates['is_active'] = bool(data['is_active'])
    if 'password' in data and data['password']:
        if len(data['password']) < 8:
            return jsonify({'error': 'Password must be at least 8 characters'}), 400
        from app.services.auth_service import hash_password
        updates['password_hash'] = hash_password(data['password'])
    if not updates:
        return jsonify({'error': 'No valid fields'}), 400
    res = sb.table('users').update(updates).eq('id', user_id).execute()
    log_action(g.user['id'], 'user_updated', 'user', user_id, {k: updates[k] for k in updates if k != 'password_hash'})
    u = res.data[0] if res.data else existing.data[0]
    return jsonify({
        'id': u['id'], 'email': u['email'], 'full_name': u.get('full_name'),
        'role': u.get('role'), 'is_active': u.get('is_active')
    })

@auth_bp.route('/users/<user_id>', methods=['DELETE'])
@role_required('admin')
def delete_user(user_id):
    if user_id == g.user['id']:
        return jsonify({'error': 'Cannot delete your own account'}), 400
    sb = get_service_supabase()
    existing = sb.table('users').select('id').eq('id', user_id).execute()
    if not existing.data:
        return jsonify({'error': 'User not found'}), 404
    # Soft delete
    sb.table('users').update({'is_active': False}).eq('id', user_id).execute()
    log_action(g.user['id'], 'user_deactivated', 'user', user_id)
    return jsonify({'message': 'User deactivated'})
