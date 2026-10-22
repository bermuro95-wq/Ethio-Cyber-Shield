"""
Target System Integration Service for Ethio-Cyber Shield (ECS).
Implements cryptographic signing protocol, anti-replay nonce persistence,
target database resolution, and bidirectional mitigation controls per §10/§11.
"""
import hmac
import hashlib
import time
import uuid
import json
import logging
import requests
import os
from datetime import datetime, timezone, timedelta
from app.services.db import get_service_supabase
from app.services.audit_service import log_action

logger = logging.getLogger(__name__)

TARGET_URL = os.getenv('TARGET_SYSTEM_URL', 'http://127.0.0.1:8081')
TARGET_KEY_ID = os.getenv('TARGET_KEY_ID', 'ecs_live_prod_key_01')
TARGET_SECRET = os.getenv('TARGET_SECRET', 'super-secret-key-32b')

DEFAULT_TARGET = {
    'id': 'default-target-shieldbank',
    'name': 'ShieldBank Core Testbed',
    'system_type': 'testbed',
    'base_url': TARGET_URL,
    'key_id': TARGET_KEY_ID,
    'secret_key': TARGET_SECRET,
    'sync_mode': 'bidirectional',
    'poll_interval_seconds': 10,
    'is_active': True,
    'health_status': 'healthy',
    'created_at': datetime.now(timezone.utc).isoformat(),
}
_LOCAL_TARGETS = {'default-target-shieldbank': DEFAULT_TARGET}


# =========================================================================
# 1. DATABASE TARGET RESOLUTION
# =========================================================================

def get_target_by_id(target_id: str) -> dict | None:
    """Fetches a target system record by UUID or local fallback."""
    if not target_id:
        return None
    try:
        sb = get_service_supabase()
        res = sb.table('target_systems').select('*').eq('id', target_id).limit(1).execute()
        if res.data:
            return res.data[0]
    except Exception as e:
        logger.debug(f"Could not load target by id {target_id} from table: {e}")
    return _LOCAL_TARGETS.get(target_id)


def get_target_by_key_id(key_id: str) -> dict | None:
    """Fetches a target system record by its public key_id."""
    if not key_id:
        return None
    try:
        sb = get_service_supabase()
        res = sb.table('target_systems').select('*').eq('key_id', key_id).limit(1).execute()
        if res.data:
            return res.data[0]
    except Exception as e:
        logger.debug(f"Could not load target by key_id {key_id} from table: {e}")
    for t in _LOCAL_TARGETS.values():
        if t.get('key_id') == key_id or key_id in ('ecs-outbound-key-01', 'ecs_live_prod_key_01', 'ecs-live-prod-key-01'):
            return t
    return None


def list_active_targets() -> list:
    """Returns all active target systems configured for monitoring."""
    try:
        sb = get_service_supabase()
        res = sb.table('target_systems').select('*').eq('is_active', True).execute()
        if res.data:
            return res.data
    except Exception as e:
        logger.debug(f"Could not load active targets from table: {e}")
    return [t for t in _LOCAL_TARGETS.values() if t.get('is_active')]


# =========================================================================
# 2. PERSISTENT NONCE ANTI-REPLAY DEFENSE
# =========================================================================

_LOCAL_NONCES = {}


def verify_and_record_nonce(key_id: str, nonce: str) -> tuple[bool, str | None]:
    """
    Checks if a nonce has already been seen; if not, persists it with a 10-minute TTL.
    Eliminates replay attacks at the memory and database layer.
    """
    if not key_id or not nonce:
        return False, "Missing key_id or nonce"

    now_ts = time.time()
    nonce_key = f"{key_id}:{nonce}"
    if nonce_key in _LOCAL_NONCES:
        exp = _LOCAL_NONCES[nonce_key]
        if now_ts < exp:
            return False, "Replayed nonce detected"
        else:
            del _LOCAL_NONCES[nonce_key]

    # Clean stale entries if cache grows
    if len(_LOCAL_NONCES) > 1000:
        for k in list(_LOCAL_NONCES.keys()):
            if now_ts > _LOCAL_NONCES[k]:
                del _LOCAL_NONCES[k]

    _LOCAL_NONCES[nonce_key] = now_ts + 600

    try:
        sb = get_service_supabase()
        now = datetime.now(timezone.utc)
        expires_at = (now + timedelta(minutes=10)).isoformat()

        # Check existing nonce in DB
        existing = sb.table('api_nonces').select('id').eq('key_id', key_id).eq('nonce', nonce).limit(1).execute()
        if existing.data:
            return False, "Replayed nonce detected"

        # Record nonce in DB
        sb.table('api_nonces').insert({
            'key_id': key_id,
            'nonce': nonce,
            'expires_at': expires_at,
        }).execute()
    except Exception as e:
        logger.debug(f"DB api_nonces sync: {e}")

    return True, None


# =========================================================================
# 3. HMAC SIGNING AND CANONICAL DISPATCH (§10 Direction B)
# =========================================================================

def sign_headers(key_id: str, secret: str, method: str, path: str, raw_body: bytes) -> dict:
    """
    Constructs canonical string and computes HMAC-SHA256 signature per §10.
    Canonical format: {ts}\\n{nonce}\\n{method}\\n{path}\\n{body_hash}
    """
    ts = str(int(time.time()))
    nonce = str(uuid.uuid4())
    body_hash = hashlib.sha256(raw_body).hexdigest()
    canonical = f"{ts}\n{nonce}\n{method.upper()}\n{path}\n{body_hash}"
    sig = hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()

    return {
        "X-ECS-Key-Id": key_id,
        "X-ECS-Timestamp": ts,
        "X-ECS-Nonce": nonce,
        "X-ECS-Signature": sig,
        "Content-Type": "application/json",
    }


def call_target(method: str, path: str, payload=None, base_url: str = None, key_id: str = None, secret: str = None, extra_headers: dict = None):
    """
    Makes an HMAC-signed HTTP request to the target banking system.
    """
    base = (base_url or TARGET_URL).rstrip('/')
    kid = key_id or TARGET_KEY_ID
    from app.services.crypto_service import decrypt_secret
    sec = decrypt_secret(secret or TARGET_SECRET)

    raw = json.dumps(payload, separators=(",", ":")).encode() if payload is not None else b""
    headers = sign_headers(kid, sec, method, path, raw)
    from app.services.tenant_service import get_current_organization_id
    org_id = get_current_organization_id()
    if org_id:
        headers["X-ECS-Tenant"] = org_id
    if extra_headers:
        headers.update(extra_headers)

    try:
        resp = requests.request(method, base + path, data=raw, headers=headers, timeout=10)
        return resp
    except requests.exceptions.ConnectionError as ce:
        logger.debug(f"Target system offline or unreachable at {base}{path}: {ce}")
        raise
    except Exception as e:
        logger.error(f"Failed to communicate with target system at {base}{path}: {e}")
        raise


def check_target_health(base_url: str = None):
    """
    Checks target system public health endpoint GET /api/public/security/health
    """
    base = (base_url or TARGET_URL).rstrip('/')
    try:
        resp = requests.get(f"{base}/api/public/security/health", timeout=5)
        return resp.json() if resp.ok else {'status': 'down', 'code': resp.status_code}
    except Exception as e:
        return {'status': 'down', 'error': str(e)}


# =========================================================================
# 4. CONTROLLED RESPONSE EXECUTION & LIFECYCLE LOGGING (§11)
# =========================================================================

def execute_target_control(action_type: str, target_entity_id: str, reason: str,
                           alert_id: str = None, incident_id: str = None, target_id: str = None,
                           requested_by: str = None, extra_payload: dict = None) -> dict:
    """
    Executes a mitigation control action on the target system and records the action
    lifecycle (PENDING -> CONFIRMED / FAILED) in the response_actions and audit_logs tables.
    """
    sb = get_service_supabase()

    # Resolve target
    target = get_target_by_id(target_id)
    base_url = target.get('base_url') if target else TARGET_URL
    key_id = target.get('key_id') if target else TARGET_KEY_ID
    secret = target.get('secret_key') if target else TARGET_SECRET
    target_uuid = target.get('id') if target else target_id

    # 1. Create response_actions row in pending status
    base_action = {
        'action_type': action_type,
        'description': f"[{action_type}] {reason} (Entity: {target_entity_id})",
        'incident_id': incident_id,
        'recommended_by': str(requested_by or 'system'),
        'status': 'pending',
    }
    v3_fields = {
        'target_system_id': target_uuid,
        'target_entity_type': action_type.split('_')[-1] if '_' in action_type else 'entity',
        'target_entity_id': target_entity_id,
        'alert_id': alert_id,
        'reason': reason,
        'requested_by': requested_by,
        'requested_at': datetime.now(timezone.utc).isoformat(),
    }

    inserted_action_id = None
    try:
        res = sb.table('response_actions').insert({**base_action, **v3_fields}).execute()
        if res.data:
            inserted_action_id = res.data[0]['id']
    except Exception:
        try:
            res = sb.table('response_actions').insert(base_action).execute()
            if res.data:
                inserted_action_id = res.data[0]['id']
        except Exception as e:
            logger.warning(f"Could not record response_action: {e}")

    # Map action to endpoint and payload
    act_norm = action_type.replace('_', '-')
    act_key = action_type.replace('-', '_')
    endpoint = f"/api/public/security/controls/{act_norm}"
    payload = {
        'reason': reason,
        'alert_id': alert_id or f"ALT-{int(time.time())}",
        **(extra_payload or {})
    }

    if act_key == 'freeze_transaction':
        payload['transaction_id'] = target_entity_id
        payload['idempotency_key'] = f"{alert_id or 'auto'}-freeze-{target_entity_id}"
    elif act_key == 'revoke_session':
        payload['session_id'] = target_entity_id
        payload['user_id'] = (extra_payload or {}).get('user_id')
    elif act_key == 'block_ip':
        payload['ip'] = target_entity_id
        payload['duration_hours'] = (extra_payload or {}).get('duration_hours', 24)
    elif act_key == 'require_step_up':
        payload['user_id'] = target_entity_id
    elif act_key == 'disable_beneficiary':
        payload['beneficiary_id'] = target_entity_id
    elif act_key == 'lock_account':
        payload['account_id'] = target_entity_id
        payload['account_number'] = target_entity_id
    elif act_key == 'revert':
        endpoint = "/api/public/security/controls/revert"
        payload['control_action_id'] = target_entity_id

    # 2. Dispatch signed API call to target
    try:
        resp = call_target("POST", endpoint, payload, base_url=base_url, key_id=key_id, secret=secret)
        resp_data = resp.json() if resp.ok else {'error': resp.text, 'status_code': resp.status_code}
        is_success = resp.ok and (resp_data.get('status') == 'CONFIRMED' or resp.status_code in (200, 201))

        # 3. Update response_actions status
        if inserted_action_id:
            try:
                sb.table('response_actions').update({
                    'status': 'confirmed' if is_success else 'failed',
                    'confirmed_at': datetime.now(timezone.utc).isoformat() if is_success else None,
                    'target_response': resp_data,
                    'error_message': None if is_success else str(resp_data.get('error') or resp.status_code)
                }).eq('id', inserted_action_id).execute()
            except Exception:
                try:
                    sb.table('response_actions').update({
                        'status': 'confirmed' if is_success else 'failed',
                        'description': f"[{action_type}] Status: {'CONFIRMED' if is_success else 'FAILED'} - {resp_data.get('message') or resp_data.get('error') or ''}",
                    }).eq('id', inserted_action_id).execute()
                except Exception as update_err:
                    logger.debug(f"Could not update response_action {inserted_action_id}: {update_err}")

        # Audit
        try:
            entity_uuid = str(inserted_action_id) if (isinstance(inserted_action_id, str) and len(str(inserted_action_id)) == 36 and '-' in str(inserted_action_id)) else None
            log_action(requested_by, f"mitigation_{action_type}", 'response_action', entity_uuid, {
                'action_id': inserted_action_id,
                'target_entity': target_entity_id,
                'success': is_success,
                'target_response': resp_data
            })
        except Exception:
            pass

        return {
            'action_id': inserted_action_id,
            'status': 'confirmed' if is_success else 'failed',
            'response': resp_data,
            'status_code': resp.status_code
        }
    except Exception as e:
        logger.error(f"Failed to execute control {action_type} on target: {e}")
        if inserted_action_id:
            try:
                sb.table('response_actions').update({
                    'status': 'failed',
                    'error_message': str(e)
                }).eq('id', inserted_action_id).execute()
            except Exception:
                try:
                    sb.table('response_actions').update({
                        'status': 'failed',
                        'description': f"[{action_type}] Error: {str(e)}"
                    }).eq('id', inserted_action_id).execute()
                except Exception:
                    pass

        return {
            'action_id': inserted_action_id,
            'status': 'failed',
            'error': str(e),
            'status_code': 500
        }


def freeze_target_transaction(transaction_id: str, reason: str, alert_id: str, target_id: str = None, requested_by: str = None):
    """Executes automated transaction freeze: POST /api/public/security/controls/freeze-transaction"""
    return execute_target_control('freeze_transaction', transaction_id, reason, alert_id=alert_id, target_id=target_id, requested_by=requested_by)


def revoke_target_session(session_id: str, reason: str = "ECS threat containment", alert_id: str = None, target_id: str = None, requested_by: str = None):
    """Terminates suspicious sessions: POST /api/public/security/controls/revoke-session"""
    return execute_target_control('revoke_session', session_id, reason, alert_id=alert_id, target_id=target_id, requested_by=requested_by)


def block_target_ip(ip: str, reason: str, duration_hours: int = 24, alert_id: str = None, target_id: str = None, requested_by: str = None):
    """Temporarily blocks IP address at target gateway: POST /api/public/security/controls/block-ip"""
    return execute_target_control('block_ip', ip, reason, alert_id=alert_id, target_id=target_id, requested_by=requested_by, extra_payload={'duration_hours': duration_hours})


def require_step_up(user_id: str, reason: str, alert_id: str = None, target_id: str = None, requested_by: str = None):
    """Forces MFA/Step-up verification on next action: POST /api/public/security/controls/require-step-up"""
    return execute_target_control('require_step_up', user_id, reason, alert_id=alert_id, target_id=target_id, requested_by=requested_by)


def disable_beneficiary(beneficiary_id: str, reason: str, alert_id: str = None, target_id: str = None, requested_by: str = None):
    """Disables suspicious beneficiary: POST /api/public/security/controls/disable-beneficiary"""
    return execute_target_control('disable_beneficiary', beneficiary_id, reason, alert_id=alert_id, target_id=target_id, requested_by=requested_by)


def lock_account(account_number: str, reason: str, alert_id: str = None, target_id: str = None, requested_by: str = None):
    """Temporarily restricts an account: POST /api/public/security/controls/lock-account"""
    return execute_target_control('lock_account', account_number, reason, alert_id=alert_id, target_id=target_id, requested_by=requested_by)


def revert_target_action(control_action_id: str, reason: str = "Analyst rollback", target_id: str = None, requested_by: str = None):
    """Reverts a previously executed control: POST /api/public/security/controls/revert"""
    return execute_target_control('revert', control_action_id, reason, target_id=target_id, requested_by=requested_by)


def run_target_scenario(scenario_name: str, target_account: str = None, base_url: str = None, key_id: str = None, secret: str = None, simulated_ip: str = None):
    """Triggers simulated attack scenario on target: POST /api/public/lab/run-scenario"""
    payload = {
        "scenario": scenario_name,
        "target_account": target_account,
    }
    headers = {}
    if simulated_ip:
        payload["simulated_ip"] = simulated_ip
        headers["X-Sim-Source-Ip"] = simulated_ip

    resp = call_target("POST", "/api/public/lab/run-scenario", payload, base_url=base_url, key_id=key_id, secret=secret, extra_headers=headers)
    try:
        resp_json = resp.json()
    except Exception:
        resp_json = {'text': resp.text, 'status_code': resp.status_code}
    return resp_json, resp.status_code
