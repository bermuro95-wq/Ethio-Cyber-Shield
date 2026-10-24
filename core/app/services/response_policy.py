"""
Closed-Loop Controlled Response & Mitigation Policy Engine for ECS.
Safely executes target containment commands against high-confidence threats,
enforces auto-containment policies, and verifies target enforcement.
Conforms to SRS §10, §21, and §22.
"""
import os
import logging
from datetime import datetime, timezone
from app.services.db import get_service_supabase
from app.services.audit_service import log_action
from app.services.target_system_service import (
    freeze_target_transaction,
    revoke_target_session,
    block_target_ip,
    require_step_up,
    disable_beneficiary,
    lock_account,
    revert_target_action,
)

logger = logging.getLogger(__name__)


def is_auto_containment_enabled() -> bool:
    """
    Checks if autonomous containment execution is enabled in system settings.
    Defaults to True for automated competition demonstration.
    """
    env_setting = os.getenv("AUTO_CONTAINMENT_ENABLED")
    if env_setting is not None:
        return env_setting.lower() in ("true", "1", "yes")

    try:
        sb = get_service_supabase()
        res = sb.table('system_settings').select('value').eq('key', 'auto_containment').execute()
        if res.data and isinstance(res.data[0].get('value'), dict):
            return bool(res.data[0]['value'].get('enabled', True))
    except Exception as e:
        logger.debug(f"Could not load auto_containment setting from DB: {e}")

    return True


def set_auto_containment_enabled(enabled: bool, user_id: str = None) -> bool:
    """Updates the auto-containment setting in system_settings."""
    sb = get_service_supabase()
    payload = {
        'key': 'auto_containment',
        'value': {'enabled': bool(enabled), 'updated_at': datetime.now(timezone.utc).isoformat()},
    }
    if user_id:
        payload['updated_by'] = user_id

    try:
        sb.table('system_settings').upsert(payload, on_conflict='key').execute()
        try:
            log_action(user_id, 'auto_containment_toggled', 'system_setting', None, {'enabled': enabled})
        except Exception:
            pass
        return True
    except Exception as e:
        logger.error(f"Failed to update auto_containment setting: {e}")
        return False


def evaluate_and_execute_containment(event: dict, alert: dict = None, incident: dict = None, detection_result: dict = None) -> dict:
    """
    Evaluates threat evidence and executes target containment controls.
    When auto-containment is disabled, registers recommended actions instead.
    """
    event = event or {}
    detection_result = detection_result or {}
    if not detection_result and incident:
        detection_result = {
            'risk_score': incident.get('risk_score', 100),
            'rules_fired': incident.get('rules_fired') or ['ATO-001'],
            'is_attack_chain': incident.get('incident_type') == 'account_takeover' or any('ATO' in str(r) for r in incident.get('risk_reasons', []))
        }

    rules_fired = detection_result.get('rules_fired', [])
    risk_score = detection_result.get('risk_score', 0)
    is_attack_chain = detection_result.get('is_attack_chain', False) or 'ATO-001' in rules_fired

    # Only act on threats with score >= 50 or attack chains
    if risk_score < 50 and not is_attack_chain:
        return {'auto_contained': False, 'reason': 'Risk below containment threshold', 'actions': []}

    target_id = event.get('target_system_id') or (incident.get('target_system_id') if incident else None)
    alert_id = alert.get('id') if isinstance(alert, dict) else None
    incident_id = incident.get('id') if isinstance(incident, dict) else None
    account_id = event.get('account_id_pub') or event.get('account_id')
    user_id = event.get('user_id_pub') or event.get('user_id')
    session_id = event.get('session_id_pub') or event.get('session_id')
    source_ip = event.get('source_ip')
    transaction_id = event.get('transaction_id_pub') or event.get('transaction_id') or event.get('raw_event_id')

    # Look in attributes if not at top-level
    attributes = event.get('attributes') or {}
    if not transaction_id and isinstance(attributes, dict):
        transaction_id = attributes.get('transaction_id')
    if not session_id and isinstance(attributes, dict):
        session_id = attributes.get('session_id')

    # Determine recommended mitigations
    planned_actions = []

    # 1. ATO-001 (Account Takeover): Freeze held transfer + revoke attacker session + block IP
    if is_attack_chain or 'ATO-001' in rules_fired:
        if transaction_id or event.get('event_type') in ('TRANSFER_CREATED', 'TRANSFER_INITIATED'):
            tx_ref = transaction_id or f"TX-{event.get('event_id')}"
            planned_actions.append({
                'action_type': 'freeze_transaction',
                'entity_id': tx_ref,
                'reason': f"CRITICAL ATO: Prevent fraudulent settlement on account {account_id or 'unknown'}",
            })
        if session_id:
            planned_actions.append({
                'action_type': 'revoke_session',
                'entity_id': session_id,
                'reason': f"CRITICAL ATO: Terminate rogue attacker session",
            })
        if source_ip:
            planned_actions.append({
                'action_type': 'block_ip',
                'entity_id': source_ip,
                'reason': f"CRITICAL ATO: Block syndicate attacker IP",
            })

    # 2. Credential Stuffing / Auth Denial Burst / Malicious IP: Block IP
    elif any(r in rules_fired for r in ('AUTH-002', 'API-001', 'IOC-001')):
        if source_ip:
            planned_actions.append({
                'action_type': 'block_ip',
                'entity_id': source_ip,
                'reason': f"Automated IP containment: {', '.join(rules_fired)}",
            })

    # 3. Fraudulent Transfer (TX-001, TX-003, TX-004): Freeze held transfer
    elif any('TX' in r for r in rules_fired):
        if transaction_id or event.get('event_type') in ('TRANSFER_CREATED', 'TRANSFER_INITIATED'):
            tx_ref = transaction_id or f"TX-{event.get('event_id')}"
            planned_actions.append({
                'action_type': 'freeze_transaction',
                'entity_id': tx_ref,
                'reason': f"Suspicious transaction anomaly: {', '.join(rules_fired)}",
            })

    # 4. Privilege Abuse (PRIV-001): Revoke session or Require Step-Up
    elif 'PRIV-001' in rules_fired:
        if session_id:
            planned_actions.append({
                'action_type': 'revoke_session',
                'entity_id': session_id,
                'reason': f"Privilege abuse attempt on {event.get('endpoint') or '/admin'}",
            })
        elif user_id:
            planned_actions.append({
                'action_type': 'require_step_up',
                'entity_id': user_id,
                'reason': "Require step-up verification after unauthorized privilege attempt",
            })

    if not planned_actions:
        return {'auto_contained': False, 'reason': 'No target entities matched containment actions', 'actions': []}

    auto_enabled = is_auto_containment_enabled()

    # If auto-containment is disabled, record recommendations
    if not auto_enabled:
        return {
            'auto_contained': False,
            'recommended_only': True,
            'actions': planned_actions,
            'message': 'Auto-containment disabled; actions queued as recommendations.'
        }

    # Execute planned mitigations
    executed_results = []
    any_success = False
    org_id = event.get('organization_id') or (incident.get('organization_id') if incident else None) or (alert.get('organization_id') if alert else None)

    for act in planned_actions:
        act_type = act['action_type']
        entity_id = act['entity_id']
        reason = act['reason']

        # Determine entity type
        if act_type == 'block_ip':
            entity_type = 'ip'
        elif act_type == 'freeze_transaction':
            entity_type = 'transaction'
        elif act_type == 'revoke_session':
            entity_type = 'session'
        elif act_type == 'require_step_up':
            entity_type = 'user'
        elif act_type == 'disable_beneficiary':
            entity_type = 'beneficiary'
        elif act_type == 'lock_account':
            entity_type = 'account'
        else:
            entity_type = 'target'

        if org_id:
            from app.services.guardrails_service import GuardrailsService
            from app.services.response_modes_service import ResponseModesService

            # 1. Guardrail evaluation
            gr_eval = GuardrailsService.evaluate_guardrails(
                org_id=org_id,
                action_type=act_type,
                entity_type=entity_type,
                entity_id=entity_id,
                confidence=detection_result.get('confidence', 'high')
            )
            if not gr_eval.get('passed'):
                executed_results.append({
                    'action_type': act_type,
                    'target_entity': entity_id,
                    'status': 'blocked_by_guardrail',
                    'blocked_by': gr_eval.get('blocked_by'),
                    'reason': gr_eval.get('reason'),
                })
                continue

            # 2. Response Mode evaluation
            eff_mode = ResponseModesService.get_effective_mode(org_id, act_type)
            if eff_mode == 'observe':
                sim = ResponseModesService.process_action_request(org_id, {
                    'action_type': act_type,
                    'entity_type': entity_type,
                    'entity_id': entity_id,
                    'reason': reason,
                    'confidence': detection_result.get('confidence', 'high'),
                    'alert_id': alert_id,
                    'incident_id': incident_id
                })
                executed_results.append({
                    'action_type': act_type,
                    'target_entity': entity_id,
                    'status': 'simulated',
                    'mode': 'observe',
                    'simulated_action_id': sim.get('simulated_action_id'),
                    'would_have_executed': True
                })
                continue
            elif eff_mode == 'recommend':
                executed_results.append({
                    'action_type': act_type,
                    'target_entity': entity_id,
                    'status': 'recommended',
                    'mode': 'recommend',
                    'reason': reason
                })
                continue
            elif eff_mode == 'approve':
                cfg = ResponseModesService.get_mode_config(org_id, act_type)
                from app.services.playbook_service import PlaybookService
                appr = PlaybookService.create_approval_request(
                    org_id=org_id,
                    action_type=act_type,
                    entity_type=entity_type,
                    entity_id=entity_id,
                    reason=reason,
                    requires_two_person=cfg.get('requires_two_person_approval', False)
                )
                executed_results.append({
                    'action_type': act_type,
                    'target_entity': entity_id,
                    'status': 'pending_approval',
                    'mode': 'approve',
                    'approval_request_id': appr.get('id')
                })
                continue

        res = None
        if act_type == 'freeze_transaction':
            res = freeze_target_transaction(entity_id, reason, alert_id=alert_id, target_id=target_id)
        elif act_type == 'revoke_session':
            res = revoke_target_session(entity_id, reason, alert_id=alert_id, target_id=target_id)
        elif act_type == 'block_ip':
            res = block_target_ip(entity_id, reason, alert_id=alert_id, target_id=target_id)
        elif act_type == 'require_step_up':
            res = require_step_up(entity_id, reason, alert_id=alert_id, target_id=target_id)
        elif act_type == 'disable_beneficiary':
            res = disable_beneficiary(entity_id, reason, alert_id=alert_id, target_id=target_id)
        elif act_type == 'lock_account':
            res = lock_account(entity_id, reason, alert_id=alert_id, target_id=target_id)

        if res:
            is_confirmed = res.get('status') == 'confirmed'
            if is_confirmed:
                any_success = True
                if org_id:
                    from app.services.guardrails_service import GuardrailsService
                    GuardrailsService.record_action_execution(org_id, act_type, entity_type, entity_id)
            executed_results.append({
                'action_type': act_type,
                'target_entity': entity_id,
                'status': res.get('status'),
                'action_id': res.get('action_id'),
                'response': res.get('response'),
            })

    # If containment succeeded, transition incident status to 'contained'
    incident_final_status = None
    if any_success and incident_id:
        try:
            sb = get_service_supabase()
            sb.table('incidents').update({
                'status': 'contained',
                'updated_at': datetime.now(timezone.utc).isoformat(),
            }).eq('id', incident_id).execute()
            incident_final_status = 'contained'
            logger.info(f"Transitioned incident {incident_id} to status 'contained'")
        except Exception as e:
            logger.warning(f"Could not update incident status to contained: {e}")

    return {
        'auto_contained': any_success,
        'incident_status': incident_final_status or (incident.get('status') if incident else 'open'),
        'actions_dispatched_count': len(executed_results),
        'actions': executed_results,
    }


def revert_containment(action_id: str, reason: str = "Analyst Rollback", user_id: str = None) -> dict:
    """
    Reverts a previously confirmed mitigation action via target POST /controls/revert.
    """
    sb = get_service_supabase()
    # Fetch action
    try:
        a_res = sb.table('response_actions').select('*').eq('id', action_id).execute()
        if not a_res.data:
            return {'error': 'Action not found', 'status': 'failed'}
        action_row = a_res.data[0]
    except Exception as e:
        return {'error': str(e), 'status': 'failed'}

    target_id = action_row.get('target_system_id')
    target_resp = action_row.get('target_response') or {}
    control_action_id = target_resp.get('action_id') or action_id

    result = revert_target_action(str(control_action_id), reason=reason, target_id=target_id, requested_by=user_id)

    # Update response_action status to reverted
    if result.get('status') == 'confirmed':
        try:
            sb.table('response_actions').update({
                'status': 'reverted',
            }).eq('id', action_id).execute()
        except Exception:
            pass

    return result


def evaluate_incident_containment(incident: dict = None, alert: dict = None, event: dict = None, target_id: str = None, detection_result: dict = None) -> dict:
    """
    Evaluates incident and dispatches automated target containment.
    Convenience wrapper around evaluate_and_execute_containment with status and actions_dispatched keys.
    """
    event = event or {}
    if target_id and not event.get('target_system_id'):
        event = {**event, 'target_system_id': target_id}
    res = evaluate_and_execute_containment(event=event, alert=alert, incident=incident, detection_result=detection_result)
    res['status'] = 'contained' if (res.get('auto_contained') or res.get('incident_status') == 'contained') else 'pending'
    res['actions_dispatched'] = res.get('actions', [])
    return res

