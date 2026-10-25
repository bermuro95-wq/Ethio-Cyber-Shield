"""
Authentication, Authorization, Identity, and Multi-Tenant RBAC Service for ECS.
Supports:
- Password hashing (bcrypt)
- JWT token generation, decoding, and session revocation
- Role-based Access Control (admin, analyst, responder, viewer, auditor)
- Multi-factor authentication (TOTP RFC 6238 via pyotp)
- Scoped API tokens with granular permissions and revocation for machine connectors
- Strict tenant boundary isolation
"""
import bcrypt
import jwt
import pyotp
import secrets
import hashlib
import uuid
import logging
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import request, jsonify, g
from dateutil import parser

from app.config import Config
from app.services.db import get_supabase, get_service_supabase
from app.services.audit_service import log_action
from app.services.tenant_service import (
    get_current_organization_id,
    set_current_organization_id,
    DEFAULT_ORGANIZATION_ID
)

logger = logging.getLogger(__name__)

# In-memory stores for revocation and token caching (works in test & standalone, backed by DB)
_REVOKED_TOKENS = set()
_ACTIVE_USER_SESSIONS = {}  # user_id -> {'jti': str, 'token': str, 'logged_in_at': str, 'ip': str, 'user_agent': str}
_API_TOKENS = {}
_USER_MFA_SECRETS = {}
_USER_ORGS = {}

VALID_ROLES = ('admin', 'analyst', 'responder', 'viewer', 'auditor')


def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(Config.BCRYPT_ROUNDS)).decode('utf-8')


def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    except Exception:
        return False


# -----------------------------------------------------------------------------
# JWT & Session Management
# -----------------------------------------------------------------------------

def create_token(user_id: str, email: str, role: str, organization_id: str = None) -> str:
    org_id = organization_id or get_current_organization_id()
    new_jti = str(uuid.uuid4())

    # Multi-device concurrent login enabled: Each device/browser receives its own valid JWT session
    payload = {
        'sub': user_id,
        'jti': new_jti,
        'email': email,
        'role': role,
        'organization_id': org_id,
        'iat': datetime.now(timezone.utc),
        'exp': datetime.now(timezone.utc) + timedelta(hours=Config.JWT_EXPIRY_HOURS)
    }
    token = jwt.encode(payload, Config.JWT_SECRET, algorithm='HS256')
    return token


def decode_token(token: str) -> dict | None:
    if is_token_revoked(token):
        return None
    try:
        payload = jwt.decode(token, Config.JWT_SECRET, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

    return payload


def clear_user_active_session(user_id: str):
    """Clears tracked active session on explicit user logout."""
    _ACTIVE_USER_SESSIONS.pop(user_id, None)


def revoke_token(token: str):
    """Revokes a JWT token session immediately."""
    token_str = str(token).strip()
    _REVOKED_TOKENS.add(token_str)
    _REVOKED_TOKENS.add(hashlib.sha256(token_str.encode()).hexdigest())


def is_token_revoked(token: str) -> bool:
    """Checks if a JWT token has been placed on the revocation blacklist."""
    token_str = str(token).strip()
    if token_str in _REVOKED_TOKENS:
        return True
    sig_hash = hashlib.sha256(token_str.encode()).hexdigest()
    return sig_hash in _REVOKED_TOKENS


# -----------------------------------------------------------------------------
# TOTP Multi-Factor Authentication (RFC 6238)
# -----------------------------------------------------------------------------

def generate_totp_secret() -> str:
    """Generates a random cryptographically secure base32 secret for TOTP MFA."""
    return pyotp.random_base32()


def get_totp_uri(secret: str, email: str) -> str:
    """Generates an otpauth:// URI suitable for authenticator apps (Google Authenticator, Authy)."""
    totp = pyotp.TOTP(secret)
    return totp.provisioning_uri(name=email, issuer_name="Ethio-Cyber-Shield")


def verify_totp_code(secret: str, code: str) -> bool:
    """Verifies a 6-digit TOTP code against the secret with 1-step window tolerance."""
    if not secret or not code:
        return False
    try:
        totp = pyotp.TOTP(secret)
        return bool(totp.verify(str(code).strip(), valid_window=1))
    except Exception as e:
        logger.debug(f"TOTP verification error: {e}")
        return False


# -----------------------------------------------------------------------------
# Scoped API Tokens for Connectors & Automation
# -----------------------------------------------------------------------------

def create_scoped_api_token(name: str, organization_id: str, scopes: list, expires_days: int = 90) -> dict:
    """
    Creates a scoped API token (ecs_pat_...) with specific granular scopes.
    Stores token hash (SHA-256) securely and returns plaintext token only once.
    """
    raw_secret = secrets.token_urlsafe(32)
    raw_token = f"ecs_pat_{raw_secret}"
    token_hash = hashlib.sha256(raw_token.encode('utf-8')).hexdigest()
    token_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)
    expires_at = (now + timedelta(days=expires_days)).isoformat()

    record = {
        'id': token_id,
        'name': name,
        'organization_id': organization_id or DEFAULT_ORGANIZATION_ID,
        'token_hash': token_hash,
        'scopes': scopes or ['ingest:events'],
        'created_at': now.isoformat(),
        'expires_at': expires_at,
        'revoked': False
    }
    _API_TOKENS[token_hash] = record

    # Store in database if table available
    try:
        sb = get_service_supabase()
        sb.table('api_tokens').insert({
            'id': token_id,
            'name': name,
            'organization_id': record['organization_id'],
            'token_hash': token_hash,
            'scopes': scopes,
            'expires_at': expires_at
        }).execute()
    except Exception as e:
        logger.debug(f"api_tokens table insert fallback to memory: {e}")

    return {
        'token_id': token_id,
        'raw_token': raw_token,
        'name': name,
        'scopes': scopes,
        'expires_at': expires_at,
        'organization_id': record['organization_id']
    }


def verify_scoped_api_token(raw_token: str, required_scope: str = None) -> dict | None:
    """
    Verifies a scoped API token against token hash, revocation status, expiry, and scope.
    """
    if not raw_token or not raw_token.startswith('ecs_pat_'):
        return None

    token_hash = hashlib.sha256(raw_token.encode('utf-8')).hexdigest()
    record = _API_TOKENS.get(token_hash)

    if not record:
        try:
            sb = get_service_supabase()
            res = sb.table('api_tokens').select('*').eq('token_hash', token_hash).execute()
            if res.data and len(res.data) > 0:
                record = res.data[0]
                _API_TOKENS[token_hash] = record
        except Exception:
            pass

    if not record or record.get('revoked'):
        return None

    # Check expiry
    expires_at = record.get('expires_at')
    if expires_at:
        try:
            exp_dt = parser.isoparse(expires_at)
            if exp_dt.tzinfo is None:
                exp_dt = exp_dt.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) > exp_dt:
                return None
        except Exception:
            pass

    # Check scopes
    scopes = record.get('scopes') or []
    if required_scope:
        if '*' not in scopes and 'admin:*' not in scopes and required_scope not in scopes:
            return None

    org_id = record.get('organization_id') or DEFAULT_ORGANIZATION_ID
    set_current_organization_id(org_id)
    return {
        'id': f"token:{record.get('id')}",
        'email': f"{record.get('name')} (API Token)",
        'role': 'admin' if ('admin:*' in scopes or '*' in scopes) else 'connector',
        'organization_id': org_id,
        'scopes': scopes
    }


def revoke_api_token(token_id: str, organization_id: str = None) -> bool:
    """Revokes an API token immediately."""
    for h, rec in _API_TOKENS.items():
        if str(rec.get('id')) == str(token_id):
            rec['revoked'] = True

    try:
        sb = get_service_supabase()
        q = sb.table('api_tokens').update({'revoked': True}).eq('id', token_id)
        if organization_id:
            q = q.eq('organization_id', organization_id)
        q.execute()
    except Exception:
        pass
    return True


# -----------------------------------------------------------------------------
# Request Context & Route Decorators
# -----------------------------------------------------------------------------

def get_current_user():
    """Extract and validate user from Authorization header with tenant context"""
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return None
    raw_token = auth_header[7:].strip()

    # 1. Scoped API token
    if raw_token.startswith('ecs_pat_'):
        return verify_scoped_api_token(raw_token)

    # 2. Check revoked JWT
    if is_token_revoked(raw_token):
        return None

    # 3. Decode JWT
    payload = decode_token(raw_token)
    if not payload:
        return None

    org_id = payload.get('organization_id') or DEFAULT_ORGANIZATION_ID
    set_current_organization_id(org_id)
    return {
        'id': payload.get('sub'),
        'email': payload.get('email'),
        'role': payload.get('role'),
        'organization_id': org_id
    }


def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({'error': 'Authentication required'}), 401
        g.user = user
        g.organization_id = user['organization_id']
        return f(*args, **kwargs)
    return decorated


def role_required(*roles):
    allowed_roles = set()
    for r in roles:
        if isinstance(r, (list, tuple, set)):
            allowed_roles.update(r)
        else:
            allowed_roles.add(r)

    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = get_current_user()
            if not user:
                return jsonify({'error': 'Authentication required'}), 401
            if user['role'] not in allowed_roles and not (user.get('role') == 'superadmin' or user.get('is_superadmin')):
                return jsonify({'error': 'Insufficient permissions'}), 403
            g.user = user
            g.organization_id = user['organization_id']
            return f(*args, **kwargs)
        return decorated
    return decorator



# -----------------------------------------------------------------------------
# User Lifecycle
# -----------------------------------------------------------------------------

def authenticate_user(email: str, password: str) -> dict | None:
    """Authenticate user against database with organization context"""
    try:
        norm_email = email.lower().strip()
        if norm_email == 'admin':
            norm_email = 'admin@ethiocybershield.et'
        sb = get_service_supabase()
        result = sb.table('users').select('*').eq('email', norm_email).eq('is_active', True).execute()
        if not result.data or len(result.data) == 0:
            return None
        user = result.data[0]
        if not verify_password(password, user['password_hash']):
            return None
        org_id = user.get('organization_id') or _USER_ORGS.get(str(user.get('id'))) or _USER_ORGS.get(norm_email) or DEFAULT_ORGANIZATION_ID
        set_current_organization_id(org_id)
        return {
            'id': user['id'],
            'email': user['email'],
            'full_name': user['full_name'],
            'role': user['role'],
            'organization_id': org_id,
            'mfa_enabled': bool(user.get('mfa_enabled', False)),
            'mfa_secret': user.get('mfa_secret')
        }
    except Exception as e:
        logger.error(f"Auth error: {e}")
        return None


def create_user(email: str, password: str, full_name: str, role: str = 'viewer', organization_id: str = None) -> dict | None:
    """Create a new user (admin only) with tenant scoping"""
    if role not in VALID_ROLES:
        return None
    try:
        sb = get_service_supabase()
        password_hash = hash_password(password)
        org_id = str(organization_id or get_current_organization_id())
        norm_email = email.lower().strip()
        _USER_ORGS[norm_email] = org_id

        data = {
            'email': norm_email,
            'password_hash': password_hash,
            'full_name': full_name.strip(),
            'role': role,
            'organization_id': org_id
        }
        try:
            result = sb.table('users').insert(data).execute()
            if result.data:
                u = result.data[0]
                _USER_ORGS[str(u.get('id'))] = org_id
                return u
        except Exception as e_insert:
            logger.debug(f"User insert with org_id fallback: {e_insert}")
            min_data = {
                'email': norm_email,
                'password_hash': password_hash,
                'full_name': full_name.strip(),
                'role': role
            }
            res_min = sb.table('users').insert(min_data).execute()
            if res_min.data:
                u = res_min.data[0]
                u['organization_id'] = org_id
                _USER_ORGS[str(u.get('id'))] = org_id
                return u
        return None
    except Exception as e:
        logger.error(f"Create user error: {e}")
        return None
