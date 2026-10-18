"""
Ethio-Cyber-Shield (ECS) — Canonical Python SDK Client.
Provides HMAC-SHA256 event signing, transactional outbox batching, and secure delivery.
"""
import hmac
import hashlib
import json
import time
import uuid
import requests
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class CanonicalEventBuilder:
    """Helper to build Canonical Event v1.1 telemetry objects with privacy-preserving hashing."""

    @staticmethod
    def hash_identifier(value: Optional[str], salt: str = "") -> Optional[str]:
        if value is None:
            return None
        val_str = str(value).strip()
        if not val_str:
            return None
        to_hash = f"{salt}:{val_str}" if salt else val_str
        return hashlib.sha256(to_hash.encode('utf-8')).hexdigest()

    @staticmethod
    def hash_phone(phone: str, salt: str = "") -> Optional[str]:
        """Normalizes and hashes MSISDN (e.g. +251... / 09...) to privacy-preserving SHA-256."""
        if not phone:
            return None
        import re
        digits = re.sub(r'[^0-9+]', '', str(phone).strip())
        if digits.startswith('09') and len(digits) == 10:
            digits = '+251' + digits[1:]
        elif digits.startswith('9') and len(digits) == 9:
            digits = '+251' + digits
        elif digits.startswith('251') and len(digits) == 12:
            digits = '+' + digits
        return CanonicalEventBuilder.hash_identifier(digits, salt=salt)

    @staticmethod
    def hash_national_id(national_id: str, salt: str = "") -> Optional[str]:
        """Hashes National ID / Fayda ID to SHA-256 to protect customer identity."""
        return CanonicalEventBuilder.hash_identifier(national_id, salt=salt)

    @staticmethod
    def hash_counterparty(account_ref: str, salt: str = "") -> Optional[str]:
        """Hashes destination beneficiary/counterparty account number to SHA-256."""
        return CanonicalEventBuilder.hash_identifier(account_ref, salt=salt)

    @staticmethod
    def build(event_type: str, result: str, source_system: str,
              user_id_pub: Optional[str] = None, account_id_pub: Optional[str] = None,
              session_id_pub: Optional[str] = None, device_id_pub: Optional[str] = None,
              source_ip: Optional[str] = None, endpoint: Optional[str] = None,
              amount_minor: Optional[int] = None, currency: str = "ETB",
              beneficiary_id_pub: Optional[str] = None, transaction_id_pub: Optional[str] = None,
              channel: str = "web", payment_rail: Optional[str] = None,
              counterparty_ref_hash: Optional[str] = None,
              device_fingerprint: Optional[str] = None,
              msisdn_hash: Optional[str] = None,
              agent_id: Optional[str] = None,
              national_id_hash: Optional[str] = None,
              locale_tz: str = "Africa/Addis_Ababa",
              attributes: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        return {
            "event_id": f"evt-{uuid.uuid4().hex[:12]}",
            "event_type": event_type,
            "occurred_at": datetime.now(timezone.utc).isoformat(),
            "source_system": source_system,
            "user_id_pub": user_id_pub,
            "account_id_pub": account_id_pub,
            "session_id_pub": session_id_pub,
            "device_id_pub": device_id_pub,
            "source_ip": source_ip,
            "endpoint": endpoint,
            "result": result,
            "amount_minor": amount_minor,
            "currency": currency,
            "beneficiary_id_pub": beneficiary_id_pub,
            "transaction_id_pub": transaction_id_pub,
            "channel": channel,
            "payment_rail": payment_rail,
            "counterparty_ref_hash": counterparty_ref_hash,
            "device_fingerprint": device_fingerprint,
            "msisdn_hash": msisdn_hash,
            "agent_id": agent_id,
            "national_id_hash": national_id_hash,
            "locale_tz": locale_tz,
            "attributes": attributes or {}
        }


class ECSClient:
    """Official client to ingest telemetry into Ethio-Cyber-Shield."""

    def __init__(self, ecs_url: str, key_id: str, secret_key: str, organization_id: Optional[str] = None):
        self.ecs_url = ecs_url.rstrip('/')
        self.key_id = key_id
        self.secret_key = secret_key
        self.organization_id = organization_id

    def generate_headers(self, method: str, path: str, raw_body: str = "") -> Dict[str, str]:
        timestamp = str(int(time.time()))
        nonce = str(uuid.uuid4())
        body_sha256 = hashlib.sha256(raw_body.encode('utf-8')).hexdigest()
        canonical_str = f"{timestamp}\n{nonce}\n{method.upper()}\n{path}\n{body_sha256}"
        signature = hmac.new(self.secret_key.encode('utf-8'), canonical_str.encode('utf-8'), hashlib.sha256).hexdigest()

        headers = {
            "X-ECS-Key-Id": self.key_id,
            "X-ECS-Timestamp": timestamp,
            "X-ECS-Nonce": nonce,
            "X-ECS-Signature": signature,
            "Content-Type": "application/json"
        }
        if self.organization_id:
            headers["X-ECS-Tenant"] = self.organization_id
        return headers

    def send_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Send a single telemetry event."""
        return self.send_batch([event])

    def send_batch(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Send a batch of telemetry events synchronously."""
        path = "/api/events"
        url = f"{self.ecs_url}{path}"
        payload = {"events": events}
        raw_body = json.dumps(payload)
        headers = self.generate_headers("POST", path, raw_body)

        try:
            resp = requests.post(url, headers=headers, data=raw_body, timeout=10)
            if resp.status_code in (200, 201):
                return resp.json()
            logger.error(f"ECS Ingest error HTTP {resp.status_code}: {resp.text}")
            return {"status": "error", "code": resp.status_code, "message": resp.text}
        except Exception as e:
            logger.error(f"Failed to post events to ECS: {e}")
            return {"status": "error", "message": str(e)}
