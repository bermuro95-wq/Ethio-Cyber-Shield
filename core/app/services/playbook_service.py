"""
Ethio-Cyber-Shield (ECS) — Playbook & Response Connectors Engine (Phase 4.3).

Implements:
1. Declarative Playbook execution and dry-run simulation engine.
2. Standard response connectors control contracts with reversibility & rollback capabilities.
3. Two-person / dual-custody approval workflows for high-impact/irreversible actions.
4. Idempotent action rollbacks (revert).
Multi-tenant partitioned strictly by organization_id UUID NOT NULL.
"""
import os
import glob
import yaml
import uuid
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple

from app.services.db import get_service_supabase
from app.services.response_modes_service import ResponseModesService
from app.services.guardrails_service import GuardrailsService
from app.services import target_system_service

logger = logging.getLogger(__name__)

# Standard Response Connectors Control Contract
RESPONSE_CONNECTORS: Dict[str, Dict[str, Any]] = {
    'freeze_transaction': {
        'name': 'freeze_transaction',
        'display_name': 'Freeze Transaction',
        'description': 'Idempotently freezes a suspicious payment transaction from clearing',
        'supported_entities': ['transaction'],
        'is_reversible': True,
        'rollback_connector': 'revert',
        'requires_approval_if_irreversible': False,
        'risk_level': 'medium'
    },
    'revoke_session': {
        'name': 'revoke_session',
        'display_name': 'Revoke Active Session',
        'description': 'Terminates an authenticated user or attacker web/mobile session',
        'supported_entities': ['session'],
        'is_reversible': False,
        'rollback_connector': None,
        'requires_approval_if_irreversible': False,
        'risk_level': 'low'
    },
    'block_ip': {
        'name': 'block_ip',
        'display_name': 'Block Source IP',
        'description': 'Applies a temporary network firewall drop on an attacking IP address',
        'supported_entities': ['ip'],
        'is_reversible': True,
        'rollback_connector': 'revert',
        'requires_approval_if_irreversible': False,
        'default_ttl_minutes': 60,
        'risk_level': 'medium'
    },
    'require_step_up': {
        'name': 'require_step_up',
        'display_name': 'Require Step-Up Authentication',
        'description': 'Prompts client for out-of-band MFA or biometric step-up before proceeding',
        'supported_entities': ['user'],
        'is_reversible': False,
        'rollback_connector': None,
        'requires_approval_if_irreversible': False,
        'risk_level': 'low'
    },
    'disable_beneficiary': {
        'name': 'disable_beneficiary',
        'display_name': 'Disable Beneficiary',
        'description': 'Deactivates an unverified or mule beneficiary account from receiving funds',
        'supported_entities': ['beneficiary'],
        'is_reversible': True,
        'rollback_connector': 'revert',
        'requires_approval_if_irreversible': False,
        'risk_level': 'medium'
    },
    'lock_account': {
        'name': 'lock_account',
        'display_name': 'Lock User Account',
        'description': 'Temporarily disables login access to a compromised customer or staff account',
        'supported_entities': ['account'],
        'is_reversible': True,
        'rollback_connector': 'revert',
        'requires_approval_if_irreversible': True,
        'risk_level': 'high'
    },
    'revert': {
        'name': 'revert',
        'display_name': 'Revert Prior Action',
        'description': 'Rolls back a previously dispatched reversible containment action',
        'supported_entities': ['action'],
        'is_reversible': False,
        'rollback_connector': None,
        'requires_approval_if_irreversible': False,
        'risk_level': 'medium'
    }
}

# In-memory stores
_PLAYBOOK_CATALOG: Dict[str, Dict[str, Any]] = {}
_TENANT_PLAYBOOKS: Dict[Tuple[str, str], Dict[str, Any]] = {}
_ACTION_APPROVALS: Dict[str, Dict[str, Any]] = {}


def clear_playbook_caches():
    """Resets in-memory approvals and cached tenant playbooks for testing."""
    _TENANT_PLAYBOOKS.clear()
    _ACTION_APPROVALS.clear()


def load_declarative_playbooks():
    """Loads YAML playbook definitions from core/app/playbooks/definitions."""
    current_dir = os.path.dirname(os.path.abspath(__file__))
    pb_dir = os.path.abspath(os.path.join(current_dir, '..', 'playbooks', 'definitions'))
    if not os.path.exists(pb_dir):
        return

    yaml_files = glob.glob(os.path.join(pb_dir, '*.yaml'))
    for f in yaml_files:
        try:
            with open(f, 'r', encoding='utf-8') as handle:
                data = yaml.safe_load(handle)
                if data and isinstance(data, dict) and 'id' in data:
                    _PLAYBOOK_CATALOG[data['id']] = data
        except Exception as e:
            logger.error(f"Failed to load declarative playbook from {f}: {e}")


# Initialize catalog on import
load_declarative_playbooks()


class PlaybookService:
    """
    Service for managing and executing declarative containment playbooks and response connectors.
    """

    @classmethod
    def list_connectors(cls) -> List[Dict[str, Any]]:
        """Returns the specifications and control contracts for all response connectors."""
        return list(RESPONSE_CONNECTORS.values())

    @classmethod
    def list_playbooks(cls, org_id: str) -> List[Dict[str, Any]]:
        """Lists declarative playbooks available for a tenant."""
        oid = str(org_id).strip()
        if not _PLAYBOOK_CATALOG:
            load_declarative_playbooks()

        playbooks = {k: dict(v) for k, v in _PLAYBOOK_CATALOG.items()}

        # Tenant overrides and custom playbooks from memory
        for (k_org, p_id), pb in _TENANT_PLAYBOOKS.items():
            if k_org == oid:
                playbooks[p_id] = dict(pb)

        # Tenant overrides from database
        try:
            sb = get_service_supabase()
            res = sb.table('playbooks').select('*').eq('organization_id', oid).execute()
            if res.data:
                for row in res.data:
                    playbooks[row['id']] = dict(row)
        except Exception as e:
            logger.debug(f"Playbooks db list fallback: {e}")

        return list(playbooks.values())

    @classmethod
    def get_playbook(cls, org_id: str, playbook_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a single playbook definition."""
        oid = str(org_id).strip()
        pid = str(playbook_id).strip()
        if not _PLAYBOOK_CATALOG:
            load_declarative_playbooks()

        # Check tenant memory
        if (oid, pid) in _TENANT_PLAYBOOKS:
            return dict(_TENANT_PLAYBOOKS[(oid, pid)])

        # Check catalog
        if pid in _PLAYBOOK_CATALOG:
            return dict(_PLAYBOOK_CATALOG[pid])

        # Check database
        try:
            sb = get_service_supabase()
            res = sb.table('playbooks').select('*').eq('organization_id', oid).eq('id', pid).limit(1).execute()
            if res.data and len(res.data) > 0:
                _TENANT_PLAYBOOKS[(oid, pid)] = res.data[0]
                return dict(res.data[0])
        except Exception as e:
            logger.debug(f"Playbook lookup db fallback: {e}")

        return None

    # =========================================================================
    # DRY-RUN SIMULATION ENGINE
    # =========================================================================

    @classmethod
    def dry_run_playbook(
        cls,
        org_id: str,
        playbook_id: str,
        incident_context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Executes a dry-run simulation of a playbook against an incident context without
        calling target systems or mutating the database.
        Returns a step-by-step trace showing trigger match, guardrails, and action simulations.
        """
        oid = str(org_id).strip()
        pb = cls.get_playbook(oid, playbook_id)
        if not pb:
            raise ValueError(f"Playbook '{playbook_id}' not found")

        trigger = pb.get('trigger', {})
        sev_in = trigger.get('severity_in', [])
        min_risk = trigger.get('min_risk_score', 0)
        rules_any = trigger.get('rules_any', [])

        ctx_sev = incident_context.get('severity', 'low')
        ctx_score = int(incident_context.get('risk_score', 0))
        ctx_rules = incident_context.get('rules_fired', [])

        # Evaluate Trigger Conditions
        sev_match = not sev_in or ctx_sev in sev_in
        score_match = ctx_score >= min_risk
        rules_match = not rules_any or any(r in ctx_rules for r in rules_any)
        trigger_matched = sev_match and score_match and rules_match

        action_traces = []
        if trigger_matched:
            for act_def in pb.get('actions', []):
                connector_name = act_def.get('connector')
                target_field = act_def.get('target_entity')
                entity_val = incident_context.get(target_field) or incident_context.get('entity_id') or "N/A"

                connector_spec = RESPONSE_CONNECTORS.get(connector_name, {})
                entity_type = connector_spec.get('supported_entities', ['unknown'])[0]

                # Evaluate Guardrails in dry-run
                gr_eval = GuardrailsService.evaluate_guardrails(
                    org_id=oid,
                    action_type=connector_name,
                    entity_type=entity_type,
                    entity_id=str(entity_val),
                    confidence=incident_context.get('confidence', 'high')
                )

                # Evaluate Response Mode
                eff_mode = ResponseModesService.get_effective_mode(oid, connector_name)

                action_traces.append({
                    'name': act_def.get('name'),
                    'connector': connector_name,
                    'target_entity_type': entity_type,
                    'target_entity_id': entity_val,
                    'reason': act_def.get('reason'),
                    'is_reversible': connector_spec.get('is_reversible', False),
                    'rollback_connector': connector_spec.get('rollback_connector'),
                    'requires_approval_if_irreversible': connector_spec.get('requires_approval_if_irreversible', False),
                    'guardrails_passed': gr_eval.get('passed'),
                    'guardrails_reason': gr_eval.get('reason'),
                    'effective_mode': eff_mode,
                    'status': 'simulated',
                    'would_execute': gr_eval.get('passed') and eff_mode in ('auto', 'observe')
                })

        return {
            'playbook_id': playbook_id,
            'playbook_name': pb.get('name'),
            'trigger_matched': trigger_matched,
            'trigger_evaluation': {
                'severity_match': sev_match,
                'score_match': score_match,
                'rules_match': rules_match
            },
            'actions_evaluated_count': len(action_traces),
            'actions': action_traces,
            'dry_run': True,
            'timestamp': datetime.now(timezone.utc).isoformat()
        }

    # =========================================================================
    # APPROVALS & DUAL CUSTODY WORKFLOW
    # =========================================================================

    @classmethod
    def create_approval_request(
        cls,
        org_id: str,
        action_type: str,
        entity_type: str,
        entity_id: str,
        reason: str,
        requires_two_person: bool = False,
        requested_by: Optional[str] = None,
        duration_minutes: int = 1440
    ) -> Dict[str, Any]:
        """Creates a pending action approval request."""
        oid = str(org_id).strip()
        req_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(minutes=duration_minutes)

        record = {
            'id': req_id,
            'organization_id': oid,
            'action_type': str(action_type).strip(),
            'target_entity_type': str(entity_type).strip(),
            'target_entity_id': str(entity_id).strip(),
            'reason': reason,
            'requires_two_person': bool(requires_two_person),
            'status': 'pending',
            'requested_by': requested_by or "system",
            'approvers': [],
            'created_at': now.isoformat(),
            'expires_at': expires_at.isoformat()
        }

        _ACTION_APPROVALS[req_id] = record

        try:
            sb = get_service_supabase()
            sb.table('action_approvals').insert(record).execute()
        except Exception as e:
            logger.debug(f"Action approval db insertion fallback: {e}")

        return dict(record)

    @classmethod
    def submit_approval(cls, org_id: str, request_id: str, approver_id: str) -> Dict[str, Any]:
        """
        Submits an approval sign-off.
        Enforces that the two approvers in a two-person approval workflow must be distinct.
        """
        oid = str(org_id).strip()
        rid = str(request_id).strip()
        aid = str(approver_id).strip()

        req = _ACTION_APPROVALS.get(rid)
        if not req or req.get('organization_id') != oid:
            raise ValueError(f"Approval request '{request_id}' not found")

        if req.get('status') != 'pending':
            raise ValueError(f"Approval request '{request_id}' is already {req.get('status')}")

        approvers = req.get('approvers', [])
        if aid in approvers:
            raise ValueError(f"Approver '{aid}' has already signed off on this request.")

        approvers.append(aid)
        req['approvers'] = approvers

        # Determine final status
        if req.get('requires_two_person'):
            if len(approvers) >= 2:
                req['status'] = 'approved'
            else:
                req['status'] = 'pending'
        else:
            req['status'] = 'approved'

        req['updated_at'] = datetime.now(timezone.utc).isoformat()

        # Update in DB
        try:
            sb = get_service_supabase()
            sb.table('action_approvals').update({
                'status': req['status'],
                'approvers': approvers,
                'updated_at': req['updated_at']
            }).eq('id', rid).eq('organization_id', oid).execute()
        except Exception as e:
            logger.debug(f"Action approval db update fallback: {e}")

        return {
            'id': rid,
            'status': req['status'],
            'approvals_count': len(approvers),
            'requires_two_person': req.get('requires_two_person'),
            'approvers': list(approvers)
        }

    @classmethod
    def reject_approval(cls, org_id: str, request_id: str, approver_id: str, reason: str = "Rejected by analyst") -> Dict[str, Any]:
        """Rejects a staged action approval request."""
        oid = str(org_id).strip()
        rid = str(request_id).strip()

        req = _ACTION_APPROVALS.get(rid)
        if not req or req.get('organization_id') != oid:
            raise ValueError(f"Approval request '{request_id}' not found")

        req['status'] = 'rejected'
        req['rejection_reason'] = reason
        req['rejected_by'] = approver_id
        req['updated_at'] = datetime.now(timezone.utc).isoformat()

        try:
            sb = get_service_supabase()
            sb.table('action_approvals').update({
                'status': 'rejected',
                'reason': reason,
                'updated_at': req['updated_at']
            }).eq('id', rid).eq('organization_id', oid).execute()
        except Exception as e:
            logger.debug(f"Action rejection db update fallback: {e}")

        return dict(req)

    @classmethod
    def list_approvals(cls, org_id: str, status: Optional[str] = None) -> List[Dict[str, Any]]:
        """Lists pending or past approval requests for a tenant."""
        oid = str(org_id).strip()
        items = [dict(r) for r in _ACTION_APPROVALS.values() if r.get('organization_id') == oid]

        try:
            sb = get_service_supabase()
            q = sb.table('action_approvals').select('*').eq('organization_id', oid)
            if status:
                q = q.eq('status', status)
            res = q.execute()
            if res.data:
                existing_ids = {i['id'] for i in items}
                for row in res.data:
                    if row['id'] not in existing_ids:
                        items.append(dict(row))
        except Exception as e:
            logger.debug(f"Action approvals db list fallback: {e}")

        if status:
            items = [i for i in items if i.get('status') == status]

        return items

    # =========================================================================
    # ACTION ROLLBACK / REVERT
    # =========================================================================

    @classmethod
    def rollback_action(
        cls,
        org_id: str,
        action_id: str,
        reason: str = "Analyst Rollback",
        user_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Reverts a previously dispatched reversible mitigation action via target POST /controls/revert.
        """
        oid = str(org_id).strip()
        aid = str(action_id).strip()

        # Call target system rollback via revert_target_action
        result = target_system_service.revert_target_action(aid, reason=reason, requested_by=user_id)

        try:
            sb = get_service_supabase()
            sb.table('response_actions').update({
                'status': 'reverted',
                'is_reverted': True,
                'reverted_at': datetime.now(timezone.utc).isoformat()
            }).eq('id', aid).eq('organization_id', oid).execute()
        except Exception as e:
            logger.debug(f"Response action rollback db fallback: {e}")

        return result
