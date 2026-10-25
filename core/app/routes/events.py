"""
Security Telemetry Ingestion & Query API for Ethio-Cyber Shield.
Receives signed v1.0 JSON telemetry events pushed from Target System outbox
and provides query endpoints for live SOC threat feeds.
"""
from flask import Blueprint, request, jsonify
import hmac
import hashlib
import time
import os
import logging
from app.services.target_system_service import (
    get_target_by_key_id,
    verify_and_record_nonce,
)
from app.services.event_service import ingest_event, query_events

events_bp = Blueprint('events', __name__)
logger = logging.getLogger(__name__)

DEFAULT_SECRET = os.getenv('TARGET_SECRET', 'super-secret-key-32b')


def verify_incoming_hmac():
    """
    Verifies HMAC headers sent by target system per §10 Direction A:
    X-ECS-Key-Id, X-ECS-Timestamp, X-ECS-Nonce, X-ECS-Signature
    """
    key_id = request.headers.get('X-ECS-Key-Id')
    ts = request.headers.get('X-ECS-Timestamp')
    nonce = request.headers.get('X-ECS-Nonce')
    sig = request.headers.get('X-ECS-Signature')

    if not all([key_id, ts, nonce, sig]):
        return False, "Missing HMAC signature headers", None

    try:
        now = int(time.time())
        req_ts = int(ts)
        if abs(now - req_ts) > 300:
            return False, "Timestamp skew exceeds 300 seconds", None
    except ValueError:
        return False, "Invalid timestamp", None

    # Resolve secret from target_systems registry or default
    from app.services.crypto_service import decrypt_secret
    from app.services.tenant_service import set_current_organization_id, resolve_tenant_from_request

    target = get_target_by_key_id(key_id)
    raw_secret = target.get('secret_key') if target else DEFAULT_SECRET
    secret = decrypt_secret(raw_secret)

    if target and target.get('organization_id'):
        set_current_organization_id(target['organization_id'])
    else:
        resolve_tenant_from_request()

    raw_body = request.get_data()
    body_hash = hashlib.sha256(raw_body).hexdigest()
    canonical = f"{ts}\n{nonce}\n{request.method.upper()}\n{request.path}\n{body_hash}"
    expected = hmac.new(secret.encode(), canonical.encode(), hashlib.sha256).hexdigest()

    if not hmac.compare_digest(sig, expected):
        if os.getenv('FLASK_DEBUG') == '1' and sig == 'dev-bypass':
            pass
        else:
            return False, "Invalid signature", target

    # Database-backed anti-replay check
    nonce_ok, nonce_err = verify_and_record_nonce(key_id, nonce)
    if not nonce_ok:
        return False, nonce_err, target

    return True, None, target


@events_bp.route('', methods=['POST'])
def receive_event():
    """
    Ingests an individual security event or batch of events pushed from Target System outbox.
    Delegates to event_service.ingest_event / ingest_batch for canonical persistence & normalization.
    """
    is_valid, err, target = verify_incoming_hmac()
    if not is_valid:
        logger.warning(f"HMAC verification warning: {err}")
        # Allow dev bypass if debug
        if not (os.getenv('FLASK_DEBUG') == '1' and request.headers.get('X-ECS-Signature') == 'dev-bypass'):
            return jsonify({'error': 'Unauthorized', 'detail': err}), 401

    data = request.get_json(silent=True) or {}

    # Extract client headers if direct probe / client
    client_ua = request.headers.get('User-Agent')
    client_plat = request.headers.get('Sec-Ch-Ua-Platform')
    client_mac = request.headers.get('X-Device-Mac') or request.headers.get('X-Mac-Address')
    client_net = request.headers.get('X-Network-Type') or request.headers.get('X-Connection-Type')

    def _inject_client_meta(ev_item):
        if not isinstance(ev_item, dict):
            return
        attrs = ev_item.setdefault('attributes', {})
        if not ev_item.get('user_agent') and not attrs.get('user_agent') and client_ua:
            attrs['user_agent'] = client_ua
        if client_plat and not attrs.get('sec_ch_ua_platform'):
            attrs['sec_ch_ua_platform'] = client_plat
        if client_mac and not attrs.get('device_mac'):
            attrs['device_mac'] = client_mac
        if client_net and not attrs.get('network_type'):
            attrs['network_type'] = client_net

    try:
        from app.services.event_service import ingest_batch
        if 'events' in data and isinstance(data['events'], list):
            for e in data['events']:
                _inject_client_meta(e)
            count = ingest_batch(data['events'], target=target)
            return jsonify({'status': 'ok', 'ingested': count}), 200
        else:
            _inject_client_meta(data)
            result = ingest_event(data, target=target)
            return jsonify(result), 200
    except ValueError as val_err:
        return jsonify({'error': str(val_err)}), 400
    except Exception as e:
        logger.error(f"Failed to ingest event: {e}")
        return jsonify({'error': 'Internal ingestion error', 'detail': str(e)}), 500


@events_bp.route('/contract', methods=['GET'])
def get_contract():
    """
    Returns the canonical JSON schema and metadata for ECS Event Contract v1.1.
    """
    import json
    candidate_paths = [
        os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), '..', 'docs', 'contracts', 'ecs-event-v1.1.schema.json'),
        os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'docs', 'contracts', 'ecs-event-v1.1.schema.json'),
        os.path.join(os.getcwd(), 'docs', 'contracts', 'ecs-event-v1.1.schema.json')
    ]
    schema_dict = None
    for p in candidate_paths:
        norm_p = os.path.normpath(p)
        if os.path.exists(norm_p):
            try:
                with open(norm_p, 'r', encoding='utf-8') as f:
                    schema_dict = json.load(f)
                break
            except Exception:
                pass

    if not schema_dict:
        schema_dict = {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": "CanonicalEventV11",
            "properties": {
                "event_id": {"type": "string"},
                "event_type": {"type": "string"},
                "channel": {"type": "string"},
                "payment_rail": {"type": "string"},
                "counterparty_ref_hash": {"type": "string"},
                "msisdn_hash": {"type": "string"},
                "device_fingerprint": {"type": "string"},
                "national_id_hash": {"type": "string"},
                "locale_tz": {"type": "string"},
            }
        }

    return jsonify({
        'version': '1.1.0',
        'standard': 'ECS Event Contract v1.1',
        'schema': schema_dict
    }), 200


@events_bp.route('', methods=['GET'])
def list_events():
    """
    Query recent security events stream for live SOC ticker.
    Supports filtering by event_type, target_system_id, account, user_id, source_ip,
    channel, payment_rail, limit.
    """
    event_type = request.args.get('event_type')
    target_id = request.args.get('target_system_id')
    account = request.args.get('account')
    user_id = request.args.get('user_id')
    source_ip = request.args.get('source_ip')
    channel = request.args.get('channel')
    payment_rail = request.args.get('payment_rail')
    limit = int(request.args.get('limit', 50))

    events = query_events(
        event_type=event_type,
        target_id=target_id,
        account=account,
        user_id=user_id,
        source_ip=source_ip,
        channel=channel,
        payment_rail=payment_rail,
        limit=limit
    )

    return jsonify(events), 200
