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
    target = get_target_by_key_id(key_id)
    secret = target.get('secret_key') if target else DEFAULT_SECRET

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
    Ingests an individual security event pushed from Target System outbox.
    Delegates to event_service.ingest_event for canonical persistence & normalization.
    """
    is_valid, err, target = verify_incoming_hmac()
    if not is_valid:
        logger.warning(f"HMAC verification warning: {err}")
        # Allow dev bypass if debug
        if not (os.getenv('FLASK_DEBUG') == '1' and request.headers.get('X-ECS-Signature') == 'dev-bypass'):
            return jsonify({'error': 'Unauthorized', 'detail': err}), 401

    data = request.get_json(silent=True) or {}
    try:
        result = ingest_event(data, target=target)
        return jsonify(result), 200
    except ValueError as val_err:
        return jsonify({'error': str(val_err)}), 400
    except Exception as e:
        logger.error(f"Failed to ingest event: {e}")
        return jsonify({'error': 'Internal ingestion error', 'detail': str(e)}), 500


@events_bp.route('', methods=['GET'])
def list_events():
    """
    Query recent security events stream for live SOC ticker.
    Supports filtering by event_type, target_system_id, account, user_id, source_ip, limit.
    """
    event_type = request.args.get('event_type')
    target_id = request.args.get('target_system_id')
    account = request.args.get('account')
    user_id = request.args.get('user_id')
    source_ip = request.args.get('source_ip')
    limit = int(request.args.get('limit', 50))

    events = query_events(
        event_type=event_type,
        target_id=target_id,
        account=account,
        user_id=user_id,
        source_ip=source_ip,
        limit=limit
    )

    return jsonify(events), 200
