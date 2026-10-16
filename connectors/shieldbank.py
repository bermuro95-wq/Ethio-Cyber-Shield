"""
ShieldBank Target Connector for Ethio-Cyber-Shield.
Encapsulates ShieldBank synthetic testbed communication, outbox polling, and mitigation dispatch.
"""
import requests
import json
import logging
from typing import Dict, Any, List
from connectors.base import BaseTargetConnector, MitigationCommand, MitigationResult, IngestionMode

logger = logging.getLogger(__name__)


class ShieldBankConnector(BaseTargetConnector):
    """
    Dedicated connector implementation for the ShieldBank testbed.
    """

    ENDPOINT_MAP = {
        'freeze_transaction': '/api/public/security/controls/freeze-transaction',
        'revoke_session': '/api/public/security/controls/revoke-session',
        'block_ip': '/api/public/security/controls/block-ip',
        'require_step_up': '/api/public/security/controls/require-step-up',
        'disable_beneficiary': '/api/public/security/controls/disable-beneficiary',
        'lock_account': '/api/public/security/controls/lock-account',
        'revert': '/api/public/security/controls/revert'
    }

    PAYLOAD_FIELD_MAP = {
        'freeze_transaction': 'transaction_id',
        'revoke_session': 'session_id',
        'block_ip': 'ip',
        'require_step_up': 'user_id',
        'disable_beneficiary': 'beneficiary_id',
        'lock_account': 'account_id'
    }

    def check_health(self) -> Dict[str, Any]:
        url = f"{self.base_url}/api/public/security/health"
        headers = self.generate_hmac_headers("GET", "/api/public/security/health")
        try:
            resp = requests.get(url, headers=headers, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                return {"status": "healthy", "details": data}
            return {"status": "degraded", "error": f"HTTP {resp.status_code}: {resp.text}"}
        except Exception as e:
            return {"status": "offline", "error": str(e)}

    def poll_events(self, since_seq: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
        path = f"/api/public/security/events?since_seq={since_seq}&limit={limit}"
        url = f"{self.base_url}{path}"
        headers = self.generate_hmac_headers("GET", path)
        try:
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                return data.get('events', []) if isinstance(data, dict) else (data if isinstance(data, list) else [])
            logger.warning(f"ShieldBank polling returned HTTP {resp.status_code}: {resp.text}")
            return []
        except Exception as e:
            logger.error(f"Error polling ShieldBank at {url}: {e}")
            return []

    def dispatch_mitigation(self, command: MitigationCommand) -> MitigationResult:
        endpoint = self.ENDPOINT_MAP.get(command.action_type)
        if not endpoint:
            return MitigationResult(
                action_id=command.action_id,
                success=False,
                message=f"Unsupported action type: {command.action_type}",
                error="InvalidActionType"
            )

        field_name = self.PAYLOAD_FIELD_MAP.get(command.action_type, 'target_entity_id')
        payload = {
            field_name: command.target_entity_id,
            "reason": command.reason,
            "action_id": command.action_id,
            "parameters": command.parameters
        }
        raw_body = json.dumps(payload)
        url = f"{self.base_url}{endpoint}"
        headers = self.generate_hmac_headers("POST", endpoint, raw_body)

        try:
            resp = requests.post(url, headers=headers, data=raw_body, timeout=8)
            if resp.status_code == 200:
                resp_data = resp.json() if resp.text else {}
                return MitigationResult(
                    action_id=command.action_id,
                    success=True,
                    message=f"Action {command.action_type} confirmed by ShieldBank",
                    target_response=resp_data
                )
            return MitigationResult(
                action_id=command.action_id,
                success=False,
                message=f"Target rejected action with HTTP {resp.status_code}",
                error=resp.text
            )
        except Exception as e:
            return MitigationResult(
                action_id=command.action_id,
                success=False,
                message=f"Failed to communicate with ShieldBank: {str(e)}",
                error=str(e)
            )

    def revert_mitigation(self, action_id: str, action_type: str, target_entity_id: str) -> MitigationResult:
        endpoint = self.ENDPOINT_MAP['revert']
        payload = {
            "action_id": action_id,
            "action_type": action_type,
            "target_entity_id": target_entity_id,
            "reason": "Analyst manual rollback / automated false-positive reversal"
        }
        raw_body = json.dumps(payload)
        url = f"{self.base_url}{endpoint}"
        headers = self.generate_hmac_headers("POST", endpoint, raw_body)

        try:
            resp = requests.post(url, headers=headers, data=raw_body, timeout=8)
            if resp.status_code == 200:
                return MitigationResult(
                    action_id=action_id,
                    success=True,
                    message=f"Rollback of {action_type} succeeded",
                    is_reverted=True,
                    target_response=resp.json() if resp.text else {}
                )
            return MitigationResult(
                action_id=action_id,
                success=False,
                message=f"Target failed rollback with HTTP {resp.status_code}",
                error=resp.text
            )
        except Exception as e:
            return MitigationResult(
                action_id=action_id,
                success=False,
                message=f"Rollback error: {str(e)}",
                error=str(e)
            )
