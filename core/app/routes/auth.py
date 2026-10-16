from flask import Blueprint, request, jsonify, g
from app.services.auth_service import (
    authenticate_user, create_token, login_required, role_required,
    create_user, get_current_user
)
from app.services.audit_service import log_action
from app.services.db import get_service_supabase

auth_bp = Blueprint('auth', __name__)

@auth_bp.route('/login', methods=['POST'])
def login():
    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''

    if not email or not password:
        return jsonify({'error': 'Email and password are required'}), 400

    user = authenticate_user(email, password)
    if not user:
        log_action(None, 'login_failed', details={'email': email})
        return jsonify({'error': 'Invalid credentials'}), 401

    token = create_token(user['id'], user['email'], user['role'])
    log_action(user['id'], 'login_success', details={'email': email})

    return jsonify({
        'token': token,
        'user': {
            'id': user['id'],
            'email': user['email'],
            'full_name': user['full_name'],
            'role': user['role']
        }
    })

@auth_bp.route('/logout', methods=['POST'])
@login_required
def logout():
    log_action(g.user['id'], 'logout')
    return jsonify({'message': 'Logged out successfully'})

@auth_bp.route('/me', methods=['GET'])
@login_required
def me():
    sb = get_service_supabase()
    res = sb.table('users').select('id, email, full_name, role, created_at').eq('id', g.user['id']).execute()
    if not res.data:
        return jsonify({'error': 'User not found'}), 404
    return jsonify(res.data[0])

@auth_bp.route('/users', methods=['POST'])
@role_required('admin')
def create_new_user():
    data = request.get_json() or {}
    email = (data.get('email') or '').strip().lower()
    password = data.get('password') or ''
    full_name = (data.get('full_name') or '').strip()
    role = data.get('role', 'viewer')

    if not email or not password or not full_name:
        return jsonify({'error': 'email, password and full_name are required'}), 400
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters'}), 400
    if role not in ('admin', 'analyst', 'viewer'):
        return jsonify({'error': 'Invalid role'}), 400

    user = create_user(email, password, full_name, role)
    if not user:
        return jsonify({'error': 'Could not create user (email may already exist)'}), 400

    log_action(g.user['id'], 'user_created', 'user', user['id'], {'email': email, 'role': role})
    return jsonify({
        'id': user['id'],
        'email': user['email'],
        'full_name': user['full_name'],
        'role': user['role']
    }), 201

@auth_bp.route('/users', methods=['GET'])
@role_required('admin', 'analyst')
def list_users():
    sb = get_service_supabase()
    res = sb.table('users').select('id, email, full_name, role, is_active, created_at').order('created_at', desc=True).execute()
    return jsonify(res.data or [])


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
