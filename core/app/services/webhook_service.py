"""
Ethio-Cyber-Shield (ECS) — Inbound Webhook Service.
Manages webhook source configurations, multi-tenant isolation, cryptographic
signature verification (Token & HMAC-SHA256), and pipeline event ingestion.
"""
import hmac
import hashlib
import secrets
import uuid
import logging
from typing import Dict, Any, Tuple, List, Optional
from datetime import datetime, timezone

from app.services.db import get_service_supabase
from app.services.crypto_service import encrypt_secret, decrypt_secret
from app.services.audit_service import log_action
from app.services.field_mapper import apply_mapping
from app.services.event_service import ingest_event

logger = logging.getLogger(__name__)

# In-memory storage for high-speed local evaluation and offline/test support
_LOCAL_WEBHOOK_SOURCES: Dict[str, Dict[str, Any]] = {}


def _mask_secret(sec: Optional[str]) -> str:
    """Masks secret token for safe API display."""
    if not sec:
        return ""
    decrypted = decrypt_secret(sec)
    if len(decrypted) <= 8:
        return "sec_****"
    return f"{decrypted[:4]}...{decrypted[-4:]}"


def _clean_source_output(record: Dict[str, Any]) -> Dict[str, Any]:
    """Prepares safe API representation of webhook source (secrets masked)."""
    out = dict(record)
    raw_sec = out.get('secret_token') or ''
    out['secret_token_masked'] = _mask_secret(raw_sec)
    out.pop('secret_token', None)
    out.pop('encrypted_secret_token', None)
    return out


def create_webhook_source(data: Dict[str, Any], org_id: str) -> Dict[str, Any]:
    """
    Registers a new inbound webhook source scoped to a specific organization.
    Encrypts the secret token using envelope encryption (AES-256-GCM) at rest.
    """
    source_id = str(data.get('source_id') or f"src-{uuid.uuid4().hex[:8]}").strip().lower()
    name = str(data.get('name') or source_id).strip()
    auth_type = str(data.get('auth_type') or 'token').strip().lower()
    if auth_type not in ('token', 'hmac_sha256', 'none'):
        auth_type = 'token'

    sig_header = str(data.get('signature_header') or ('X-Signature-SHA256' if auth_type == 'hmac_sha256' else 'X-Webhook-Secret')).strip()

    raw_secret = data.get('secret_token')
    if not raw_secret and auth_type != 'none':
        raw_secret = secrets.token_hex(24)
    elif raw_secret:
        raw_secret = str(raw_secret).strip()
    else:
        raw_secret = ""

    # Envelope encrypt secret at rest
    encrypted_secret = encrypt_secret(raw_secret) if raw_secret else ""

    now_iso = datetime.now(timezone.utc).isoformat()
    record = {
        'id': str(uuid.uuid4()),
        'organization_id': org_id,
        'source_id': source_id,
        'name': name,
        'auth_type': auth_type,
        'signature_header': sig_header,
        'secret_token': encrypted_secret,
        'mapping_rules': data.get('mapping_rules') or {},
        'sample_payload': data.get('sample_payload'),
        'is_active': bool(data.get('is_active', True)),
        'total_received': 0,
        'last_received_at': None,
        'last_error': None,
        'created_at': now_iso,
        'updated_at': now_iso
    }

    # Persist in Postgres/Supabase if available
    try:
        sb = get_service_supabase()
        db_record = dict(record)
        sb.table('webhook_sources').insert(db_record).execute()
    except Exception as e:
        logger.debug(f"Webhook source fallback to memory store: {e}")

    _LOCAL_WEBHOOK_SOURCES[source_id] = record

    try:
        log_action(
            action='WEBHOOK_SOURCE_CREATED',
            entity_type='webhook_source',
            entity_id=source_id,
            details={'name': name, 'auth_type': auth_type, 'organization_id': org_id}
        )
    except Exception:
        pass

    return _clean_source_output(record)


def get_webhook_source(source_id: str, org_id: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """Fetches webhook source by source_id, validating tenant boundary if org_id is provided."""
    if not source_id:
        return None

    record = None
    try:
        sb = get_service_supabase()
        res = sb.table('webhook_sources').select('*').eq('source_id', source_id).limit(1).execute()
        if res.data and len(res.data) > 0:
            record = res.data[0]
            _LOCAL_WEBHOOK_SOURCES[source_id] = record
    except Exception as e:
        logger.debug(f"Could not load webhook source {source_id} from table: {e}")

    if not record:
        record = _LOCAL_WEBHOOK_SOURCES.get(source_id)

    if not record:
        return None

    if org_id and str(record.get('organization_id')) != str(org_id):
        return None

    return record


def list_webhook_sources(org_id: str) -> List[Dict[str, Any]]:
    """Lists all webhook sources scoped to an organization."""
    sources: List[Dict[str, Any]] = []
    try:
        sb = get_service_supabase()
        res = sb.table('webhook_sources').select('*').eq('organization_id', org_id).order('created_at', desc=True).execute()
        if res.data:
            sources = res.data
    except Exception as e:
        logger.debug(f"Could not list webhook sources from table: {e}")

    if not sources:
        sources = [s for s in _LOCAL_WEBHOOK_SOURCES.values() if str(s.get('organization_id')) == str(org_id)]

    return [_clean_source_output(s) for s in sources]


def update_webhook_source(source_id: str, update_data: Dict[str, Any], org_id: str) -> Optional[Dict[str, Any]]:
    """Updates an existing webhook source ensuring strict tenant boundary."""
    source = get_webhook_source(source_id, org_id=org_id)
    if not source:
        return None

    now_iso = datetime.now(timezone.utc).isoformat()
    fields_to_update: Dict[str, Any] = {'updated_at': now_iso}

    if 'name' in update_data:
        fields_to_update['name'] = str(update_data['name']).strip()
    if 'auth_type' in update_data:
        at = str(update_data['auth_type']).strip().lower()
        if at in ('token', 'hmac_sha256', 'none'):
            fields_to_update['auth_type'] = at
    if 'signature_header' in update_data:
        fields_to_update['signature_header'] = str(update_data['signature_header']).strip()
    if 'mapping_rules' in update_data and isinstance(update_data['mapping_rules'], dict):
        fields_to_update['mapping_rules'] = update_data['mapping_rules']
    if 'sample_payload' in update_data:
        fields_to_update['sample_payload'] = update_data['sample_payload']
    if 'is_active' in update_data:
        fields_to_update['is_active'] = bool(update_data['is_active'])

    if 'secret_token' in update_data and update_data['secret_token']:
        raw_sec = str(update_data['secret_token']).strip()
        fields_to_update['secret_token'] = encrypt_secret(raw_sec)

    # Apply updates
    source.update(fields_to_update)
    _LOCAL_WEBHOOK_SOURCES[source_id] = source

    try:
        sb = get_service_supabase()
        sb.table('webhook_sources').update(fields_to_update).eq('source_id', source_id).execute()
    except Exception as e:
        logger.debug(f"Webhook source update fallback: {e}")

    return _clean_source_output(source)


def delete_webhook_source(source_id: str, org_id: str) -> bool:
    """Deletes a webhook source scoped to tenant."""
    source = get_webhook_source(source_id, org_id=org_id)
    if not source:
        return False

    _LOCAL_WEBHOOK_SOURCES.pop(source_id, None)
    try:
        sb = get_service_supabase()
        sb.table('webhook_sources').delete().eq('source_id', source_id).eq('organization_id', org_id).execute()
    except Exception as e:
        logger.debug(f"Webhook source delete error: {e}")

    try:
        log_action(
            action='WEBHOOK_SOURCE_DELETED',
            entity_type='webhook_source',
            entity_id=source_id,
            details={'organization_id': org_id}
        )
    except Exception:
        pass

    return True


def _update_source_stats(source_id: str, success: bool = True, error: Optional[str] = None):
    """Updates reception metrics for a webhook source."""
    now_iso = datetime.now(timezone.utc).isoformat()
    source = _LOCAL_WEBHOOK_SOURCES.get(source_id)
    if source:
        if success:
            source['total_received'] = int(source.get('total_received') or 0) + 1
            source['last_error'] = None
        else:
            source['last_error'] = error
        source['last_received_at'] = now_iso

    try:
        sb = get_service_supabase()
        updates = {'last_received_at': now_iso}
        if success:
            updates['last_error'] = None
        elif error:
            updates['last_error'] = error
        sb.table('webhook_sources').update(updates).eq('source_id', source_id).execute()
    except Exception:
        pass


def verify_webhook_auth(source: Dict[str, Any], headers: Dict[str, Any], raw_body: bytes) -> Tuple[bool, Optional[str]]:
    """
    Verifies authentication and cryptographic integrity of an inbound webhook request.
    Supports:
    - 'none': Open webhook without verification.
    - 'token': Shared secret token in designated header or Authorization bearer.
    - 'hmac_sha256': HMAC-SHA256 signature verification over raw body bytes.
    """
    auth_type = source.get('auth_type', 'token')
    if auth_type == 'none':
        return True, None

    enc_secret = source.get('secret_token')
    if not enc_secret:
        return False, "Webhook source has no secret configured"

    try:
        decrypted_secret = decrypt_secret(enc_secret).strip()
    except Exception as e:
        logger.error(f"Failed to decrypt webhook secret for {source.get('source_id')}: {e}")
        return False, "Failed to decrypt webhook secret"

    # Normalize headers to lowercase keys for case-insensitive lookup
    norm_headers = {k.lower(): str(v).strip() for k, v in headers.items()}
    sig_header = str(source.get('signature_header') or 'X-Webhook-Secret').lower()

    if auth_type == 'token':
        # Check custom header first
        provided_token = norm_headers.get(sig_header)
        # Check fallback Authorization header
        if not provided_token:
            auth_val = norm_headers.get('authorization', '')
            if auth_val.startswith('Bearer ') or auth_val.startswith('bearer '):
                provided_token = auth_val[7:].strip()
            elif auth_val:
                provided_token = auth_val.strip()

        if not provided_token:
            return False, f"Missing authentication header '{source.get('signature_header', 'X-Webhook-Secret')}'"

        if not hmac.compare_digest(provided_token, decrypted_secret):
            return False, "Invalid webhook secret token"

        return True, None

    elif auth_type == 'hmac_sha256':
        provided_sig = norm_headers.get(sig_header)
        if not provided_sig:
            return False, f"Missing signature header '{source.get('signature_header', 'X-Signature-SHA256')}'"

        # Handle 'sha256=<hex>' prefix if present
        if provided_sig.startswith('sha256='):
            provided_sig = provided_sig[7:].strip()

        expected_sig = hmac.new(
            decrypted_secret.encode('utf-8'),
            raw_body or b'',
            hashlib.sha256
        ).hexdigest()

        if not hmac.compare_digest(provided_sig.lower(), expected_sig.lower()):
            return False, "Invalid HMAC-SHA256 signature"

        return True, None

    return False, f"Unsupported auth_type '{auth_type}'"


def process_inbound_webhook(
    source_id: str,
    headers: Dict[str, Any],
    raw_body: bytes,
    json_payload: Dict[str, Any]
) -> Tuple[int, Dict[str, Any]]:
    """
    Processes an inbound third-party webhook:
    1. Resolves source.
    2. Validates activity and cryptographic signature.
    3. Transforms payload via Field Mapper.
    4. Ingests normalized event into ECS detection pipeline.
    """
    source = get_webhook_source(source_id)
    if not source:
        return 404, {'error': f"Webhook source '{source_id}' not found"}

    if not source.get('is_active', True):
        return 400, {'error': "Webhook source is inactive"}

    # Authenticate
    is_authenticated, auth_err = verify_webhook_auth(source, headers, raw_body)
    if not is_authenticated:
        _update_source_stats(source_id, success=False, error=auth_err)
        try:
            from app.services.data_quality_service import record_schema_violation
            record_schema_violation(
                org_id=source.get('organization_id') or '00000000-0000-0000-0000-000000000001',
                source_id=source_id,
                source_name=source.get('name') or source_id,
                violation_type='CRYPTO_SIGNATURE_FAILURE',
                error_message=auth_err or 'Webhook authentication failed',
                raw_sample={'source_id': source_id}
            )
        except Exception:
            pass
        return 401, {'error': auth_err}

    # Map payload
    mapping_rules = source.get('mapping_rules') or {}
    source_name = source.get('name') or source_id
    org_id = source['organization_id']

    is_valid, norm_event, errors = apply_mapping(
        payload=json_payload,
        mapping_rules=mapping_rules,
        default_org_id=org_id,
        source_name=source_name
    )

    if not is_valid:
        err_msg = f"Mapping validation failed: {'; '.join(errors)}"
        _update_source_stats(source_id, success=False, error=err_msg)
        try:
            from app.services.data_quality_service import record_schema_violation
            record_schema_violation(
                org_id=org_id,
                source_id=source_id,
                source_name=source_name,
                violation_type='MAPPING_FAILURE',
                error_message=err_msg,
                raw_sample=json_payload
            )
        except Exception:
            pass
        return 422, {
            'error': "Webhook payload mapping/validation failed",
            'details': errors
        }


    # Ingest event into ECS pipeline
    try:
        ingest_event(
            norm_event,
            target={'organization_id': org_id, 'name': source_name}
        )
        _update_source_stats(source_id, success=True)
    except Exception as e:
        logger.error(f"Inbound webhook ingestion error: {e}")
        _update_source_stats(source_id, success=False, error=str(e))
        return 500, {'error': f"Internal error during event ingestion: {str(e)}"}

    return 202, {
        'status': 'accepted',
        'event_id': norm_event['event_id'],
        'source_id': source_id,
        'organization_id': org_id
    }
