import bcrypt
import jwt
from datetime import datetime, timedelta, timezone
from functools import wraps
from flask import request, jsonify, g
from app.config import Config
from app.services.db import get_supabase, get_service_supabase
from app.services.audit_service import log_action
import logging

logger = logging.getLogger(__name__)

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt(Config.BCRYPT_ROUNDS)).decode('utf-8')

def verify_password(password: str, password_hash: str) -> bool:
    try:
        return bcrypt.checkpw(password.encode('utf-8'), password_hash.encode('utf-8'))
    except Exception:
        return False

def create_token(user_id: str, email: str, role: str) -> str:
    payload = {
        'sub': user_id,
        'email': email,
        'role': role,
        'iat': datetime.now(timezone.utc),
        'exp': datetime.now(timezone.utc) + timedelta(hours=Config.JWT_EXPIRY_HOURS)
    }
    return jwt.encode(payload, Config.JWT_SECRET, algorithm='HS256')

def decode_token(token: str) -> dict | None:
    try:
        return jwt.decode(token, Config.JWT_SECRET, algorithms=['HS256'])
    except jwt.ExpiredSignatureError:
        return None
    except jwt.InvalidTokenError:
        return None

def get_current_user():
    """Extract and validate user from Authorization header"""
    auth_header = request.headers.get('Authorization', '')
    if not auth_header.startswith('Bearer '):
        return None
    token = auth_header[7:]
    payload = decode_token(token)
    if not payload:
        return None
    return {
        'id': payload.get('sub'),
        'email': payload.get('email'),
        'role': payload.get('role')
    }

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        user = get_current_user()
        if not user:
            return jsonify({'error': 'Authentication required'}), 401
        g.user = user
        return f(*args, **kwargs)
    return decorated

def role_required(*roles):
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            user = get_current_user()
            if not user:
                return jsonify({'error': 'Authentication required'}), 401
            if user['role'] not in roles:
                return jsonify({'error': 'Insufficient permissions'}), 403
            g.user = user
            return f(*args, **kwargs)
        return decorated
    return decorator

def authenticate_user(email: str, password: str) -> dict | None:
    """Authenticate user against database"""
    try:
        sb = get_service_supabase()
        result = sb.table('users').select('*').eq('email', email.lower().strip()).eq('is_active', True).execute()
        if not result.data or len(result.data) == 0:
            return None
        user = result.data[0]
        if not verify_password(password, user['password_hash']):
            return None
        return {
            'id': user['id'],
            'email': user['email'],
            'full_name': user['full_name'],
            'role': user['role']
        }
    except Exception as e:
        logger.error(f"Auth error: {e}")
        return None

def create_user(email: str, password: str, full_name: str, role: str = 'viewer') -> dict | None:
    """Create a new user (admin only)"""
    if role not in ('admin', 'analyst', 'viewer'):
        return None
    try:
        sb = get_service_supabase()
        password_hash = hash_password(password)
        data = {
            'email': email.lower().strip(),
            'password_hash': password_hash,
            'full_name': full_name.strip(),
            'role': role
        }
        result = sb.table('users').insert(data).execute()
        if result.data:
            return result.data[0]
        return None
    except Exception as e:
        logger.error(f"Create user error: {e}")
        return None
