"""
Central Telemetry Event Ingestion & Normalization Service for Ethio-Cyber Shield (ECS).
Processes canonical v1.0 security events, writes to security_events table,
normalizes into domain entities (transactions, indicators, devices), and hooks into detection.
"""
import logging
from datetime import datetime, timezone
from app.services.db import get_service_supabase
from app.services.security_rules import analyze_transaction

logger = logging.getLogger(__name__)

# In-memory sliding buffer for real-time correlation and zero-latency lookups
_RECENT_EVENTS_BUFFER = []
MAX_BUFFER_SIZE = 1000

EVENT_TYPE_MAP = {
    'auth.login.failed': 'LOGIN_FAILED',
    'auth.login.succeeded': 'LOGIN_SUCCESS',
    'auth.login.success': 'LOGIN_SUCCESS',
    'auth.device.unrecognized': 'DEVICE_REGISTERED',
    'device.registered': 'DEVICE_REGISTERED',
    'beneficiary.created': 'BENEFICIARY_CREATED',
    'transaction.transfer.held': 'TRANSFER_CREATED',
    'transaction.transfer.created': 'TRANSFER_CREATED',
    'transaction.transfer.initiated': 'TRANSFER_CREATED',
    'transaction.transfer.completed': 'TRANSFER_COMPLETED',
    'authz.denied': 'AUTHZ_DENIED',
    'admin.action': 'ADMIN_ACTION',
}


def get_recent_in_memory_events() -> list:
    """Returns a snapshot of the in-memory recent event buffer."""
    return list(_RECENT_EVENTS_BUFFER)


def ingest_event(data: dict, target: dict = None, target_system_id: str = None, **kwargs) -> dict:
    """
    Ingests a single v1.0 security event.
    Guarantees idempotency via event_id and normalizes into entity tables.
    """
    event_id = data.get('event_id')
    raw_event_type = data.get('event_type')

    if not event_id or not raw_event_type:
        raise ValueError("event_id and event_type are required fields")

    # Normalize canonical dot-notation or custom names to standard upper-case
    event_type = EVENT_TYPE_MAP.get(str(raw_event_type).lower(), str(raw_event_type).upper())

    occurred_at = data.get('occurred_at') or datetime.now(timezone.utc).isoformat()
    source_system = data.get('source_system') or (target.get('name') if target else 'shieldbank-testbed')
    user_id_pub = data.get('user_id') or data.get('user_id_pub')
    account_id_pub = data.get('account_id') or data.get('account_id_pub')
    session_id_pub = data.get('session_id') or data.get('session_id_pub')
    device_id_pub = data.get('device_id') or data.get('device_id_pub')
    source_ip = data.get('source_ip')
    endpoint = data.get('endpoint')
    result = data.get('result', 'SUCCESS')
    currency = data.get('currency', 'ETB')
    beneficiary_id_pub = data.get('beneficiary_id') or data.get('beneficiary_id_pub')
    transaction_id_pub = data.get('transaction_id') or data.get('transaction_id_pub')
    attributes = data.get('attributes') or {}
    lab_scenario = attributes.get('lab_scenario_id')

    # Compute amount minor / major (checks top-level and attributes)
    amount_minor = data.get('amount_minor')
    amount_major = data.get('amount')
    if amount_major is None and isinstance(attributes, dict) and 'amount' in attributes:
        amount_major = attributes.get('amount')

    if amount_minor is None and amount_major is not None:
        try:
            amount_minor = int(round(float(amount_major) * 100))
        except (ValueError, TypeError):
            amount_minor = None
    elif amount_minor is not None and amount_major is None:
        amount_major = float(amount_minor) / 100.0

    sb = get_service_supabase()
    target_id = (target.get('id') if target else None) or target_system_id or data.get('target_system_id')

    canonical_event = {
        'event_id': event_id,
        'event_type': event_type,
        'occurred_at': occurred_at,
        'source_system': source_system,
        'user_id': user_id_pub,
        'account_id': account_id_pub,
        'session_id': session_id_pub,
        'device_id': device_id_pub,
        'source_ip': source_ip,
        'endpoint': endpoint,
        'result': result,
        'attributes': attributes,
    }
    extended_fields = {
        'seq': data.get('seq'),
        'user_id_pub': user_id_pub,
        'account_id_pub': account_id_pub,
        'session_id_pub': session_id_pub,
        'device_id_pub': device_id_pub,
        'amount_minor': amount_minor,
        'currency': currency,
        'beneficiary_id_pub': beneficiary_id_pub,
        'transaction_id_pub': transaction_id_pub,
        'delivery_status': 'DELIVERED',
        'raw_payload': data,
    }
    if target_id:
        canonical_event['target_system_id'] = target_id

    try:
        sb.table('security_events').upsert({**canonical_event, **extended_fields}, on_conflict='event_id').execute()
    except Exception:
        try:
            sb.table('security_events').upsert(canonical_event, on_conflict='event_id').execute()
        except Exception as e:
            logger.error(f"Error persisting security_event {event_id}: {e}")

    # 2. Extract & normalize transactions
    if event_type in ('TRANSFER_CREATED', 'TRANSFER_INITIATED') and amount_major:
        try:
            tx_record = {
                'account_number': account_id_pub or 'ACC_UNKNOWN',
                'amount': float(amount_major),
                'currency': currency or 'ETB',
                'transaction_type': 'transfer',
                'device_id': device_id_pub,
                'ip_address': source_ip,
                'status': 'flagged' if attributes.get('held_for_review') else 'completed',
                'is_suspicious': bool(attributes.get('held_for_review') or lab_scenario),
            }
            if target_id:
                tx_record['target_system_id'] = target_id
            if event_id:
                tx_record['raw_event_id'] = event_id

            try:
                tx_res = sb.table('transactions').insert(tx_record).execute()
            except Exception:
                tx_record.pop('target_system_id', None)
                tx_record.pop('raw_event_id', None)
                tx_res = sb.table('transactions').insert(tx_record).execute()

            if tx_res.data:
                analyze_transaction(tx_res.data[0]['id'])
        except Exception as e:
            logger.error(f"Failed to normalize transaction from event {event_id}: {e}")

    # 3. Extract & update threat indicators (IPs, accounts, devices)
    if source_ip and (lab_scenario or event_type in ('LOGIN_FAILED', 'AUTHZ_DENIED')):
        try:
            sb.table('indicators').upsert({
                'indicator_type': 'ip',
                'value': source_ip,
                'status': 'malicious' if lab_scenario else 'suspicious',
                'description': f"Observed in event {event_type} ({lab_scenario or 'Target System'})",
                'source': 'Target System Telemetry',
            }, on_conflict='indicator_type,value').execute()
        except Exception as e:
            logger.warning(f"Could not upsert indicator for {source_ip}: {e}")

    # 4. Record into in-memory sliding buffer for real-time correlation
    buffered_item = {
        **canonical_event,
        **extended_fields,
        'amount': amount_major,
        'raw_event_type': raw_event_type,
    }
    _RECENT_EVENTS_BUFFER.insert(0, buffered_item)
    if len(_RECENT_EVENTS_BUFFER) > MAX_BUFFER_SIZE:
        _RECENT_EVENTS_BUFFER.pop()

    # 5. Multi-Layer Detection & Explainable Risk Engine evaluation (SRS §9, §21)
    detection_result = None
    try:
        from app.services.detection_engine import evaluate_event_stream
        event_for_detection = dict(buffered_item)
        detection_result = evaluate_event_stream(event_for_detection)
    except Exception as e:
        logger.error(f"Error evaluating event {event_id} through detection engine: {e}")

    return {
        'status': 'received',
        'event_id': event_id,
        'event_type': event_type,
        'lab_scenario_id': lab_scenario,
        'detection': detection_result or {},
    }


def ingest_batch(events_list: list, target: dict = None) -> int:
    """
    Ingests a sequence of events (e.g. from a polling sync batch).
    Returns the count of successfully processed events.
    """
    success_count = 0
    for ev in events_list:
        try:
            ingest_event(ev, target=target)
            success_count += 1
        except Exception as e:
            logger.error(f"Failed to ingest event in batch: {e}")
    return success_count


def query_events(event_type: str = None, target_id: str = None, account: str = None,
                 user_id: str = None, source_ip: str = None, limit: int = 50) -> list:
    """
    Retrieves recent security events matching the given criteria.
    """
    sb = get_service_supabase()
    query = sb.table('security_events').select('*')

    if event_type:
        query = query.eq('event_type', event_type)
    if target_id:
        query = query.eq('target_system_id', target_id)
    if account:
        query = query.eq('account_id_pub', account)
    if user_id:
        query = query.eq('user_id_pub', user_id)
    if source_ip:
        query = query.eq('source_ip', source_ip)

    max_limit = min(max(1, limit), 500)
    res = query.order('occurred_at', desc=True).limit(max_limit).execute()
    return res.data or []
