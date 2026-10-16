"""
Ethio-Cyber-Shield (ECS) — Pluggable Target Connector Base Architecture.
Enforces safe bidirectional communication, canonical signing, and rollback.
"""
from abc import ABC, abstractmethod
from enum import Enum
from typing import Dict, Any, List, Optional
from datetime import datetime, timezone
import hmac
import hashlib
import uuid


class IngestionMode(str, Enum):
    PUSH = "push"
    PULL = "pull"
    BIDIRECTIONAL = "bidirectional"


class ActionType(str, Enum):
    FREEZE_TRANSACTION = "freeze_transaction"
    REVOKE_SESSION = "revoke_session"
    BLOCK_IP = "block_ip"
    REQUIRE_STEP_UP = "require_step_up"
    DISABLE_BENEFICIARY = "disable_beneficiary"
    LOCK_ACCOUNT = "lock_account"
    REVERT = "revert"


class MitigationCommand:
    def __init__(self, action_type: str, target_entity_type: str, target_entity_id: str,
                 reason: str, alert_id: Optional[str] = None, incident_id: Optional[str] = None,
                 parameters: Optional[Dict[str, Any]] = None):
        self.action_id = str(uuid.uuid4())
        self.action_type = action_type
        self.target_entity_type = target_entity_type
        self.target_entity_id = target_entity_id
        self.reason = reason
        self.alert_id = alert_id
        self.incident_id = incident_id
        self.parameters = parameters or {}
        self.dispatched_at = datetime.now(timezone.utc)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_id": self.action_id,
            "action_type": self.action_type,
            "target_entity_type": self.target_entity_type,
            "target_entity_id": self.target_entity_id,
            "reason": self.reason,
            "alert_id": self.alert_id,
            "incident_id": self.incident_id,
            "parameters": self.parameters,
            "dispatched_at": self.dispatched_at.isoformat()
        }


class MitigationResult:
    def __init__(self, action_id: str, success: bool, message: str,
                 target_response: Optional[Dict[str, Any]] = None,
                 is_reverted: bool = False, error: Optional[str] = None):
        self.action_id = action_id
        self.success = success
        self.message = message
        self.target_response = target_response or {}
        self.is_reverted = is_reverted
        self.error = error
        self.completed_at = datetime.now(timezone.utc)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_id": self.action_id,
            "success": self.success,
            "message": self.message,
            "target_response": self.target_response,
            "is_reverted": self.is_reverted,
            "error": self.error,
            "completed_at": self.completed_at.isoformat()
        }


class BaseTargetConnector(ABC):
    """
    Abstract Base Class for all target systems connecting to ECS.
    Enforces technical independence from any single banking vendor or architecture.
    """

    def __init__(self, organization_id: str, target_id: str, name: str, base_url: str,
                 key_id: str, secret_key: str, sync_mode: IngestionMode = IngestionMode.BIDIRECTIONAL):
        self.organization_id = organization_id
        self.target_id = target_id
        self.name = name
        self.base_url = base_url.rstrip('/')
        self.key_id = key_id
        self.secret_key = secret_key
        self.sync_mode = sync_mode

    def generate_hmac_headers(self, method: str, path: str, raw_body: str = "") -> Dict[str, str]:
        """Generates canonical HMAC-SHA256 authentication headers."""
        timestamp = str(int(datetime.now(timezone.utc).timestamp()))
        nonce = str(uuid.uuid4())
        body_sha256 = hashlib.sha256(raw_body.encode('utf-8')).hexdigest()
        canonical_string = f"{timestamp}\n{nonce}\n{method.upper()}\n{path}\n{body_sha256}"
        signature = hmac.new(self.secret_key.encode('utf-8'), canonical_string.encode('utf-8'), hashlib.sha256).hexdigest()

        return {
            "X-ECS-Key-Id": self.key_id,
            "X-ECS-Timestamp": timestamp,
            "X-ECS-Nonce": nonce,
            "X-ECS-Signature": signature,
            "Content-Type": "application/json"
        }

    def verify_hmac(self, signature: str, timestamp_str: str, nonce: str,
                    method: str, path: str, raw_body: str = "") -> bool:
        """Verifies inbound HMAC-SHA256 signature."""
        try:
            now_ts = int(datetime.now(timezone.utc).timestamp())
            req_ts = int(timestamp_str)
            if abs(now_ts - req_ts) > 300:
                return False

            body_sha256 = hashlib.sha256(raw_body.encode('utf-8')).hexdigest()
            canonical_string = f"{timestamp_str}\n{nonce}\n{method.upper()}\n{path}\n{body_sha256}"
            expected_sig = hmac.new(self.secret_key.encode('utf-8'), canonical_string.encode('utf-8'), hashlib.sha256).hexdigest()
            return hmac.compare_digest(signature, expected_sig)
        except Exception:
            return False

    @abstractmethod
    def check_health(self) -> Dict[str, Any]:
        """Perform bidirectional liveness check against the target system."""
        pass

    @abstractmethod
    def poll_events(self, since_seq: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
        """Pull security events in Direction B (outbound pull)."""
        pass

    @abstractmethod
    def dispatch_mitigation(self, command: MitigationCommand) -> MitigationResult:
        """Execute a containment action on the target system."""
        pass

    @abstractmethod
    def revert_mitigation(self, action_id: str, action_type: str, target_entity_id: str) -> MitigationResult:
        """Execute an idempotent rollback/revert of a previously executed action."""
        pass
