"""
Case Management Service for Ethio-Cyber-Shield (ECS) v3.0 (Phase 4.4).
Provides end-to-end incident case management:
1. Status transitions with automatic SLA milestone tracking (TTA, TTC, TTR).
2. Dynamic SLA health evaluation (on_track, at_risk, breached).
3. Case assignment and reassignment with tamper-evident audit logging.
4. Case notes and collaborative analyst comments.
5. Hash-sealed evidence attachments with SHA-256 verification.
6. Unified cross-time entity timelines (events, alerts, cases, response actions).
7. Related-alert correlation graph.
8. Saved searches and cross-time telemetry query engine.
Strictly partitioned by organization_id UUID NOT NULL.
"""
import uuid
import hashlib
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional, Tuple

from app.services.db import get_service_supabase
from app.services.tenant_service import get_current_organization_id
from app.services.audit_service import log_action

logger = logging.getLogger(__name__)

# Default SLA targets by incident severity (in minutes)
# Conforms to INSA Proclamation No. 1426/2026 and standard critical infrastructure benchmarks
SLA_TARGETS: Dict[str, Dict[str, int]] = {
    'critical': {
        'response_mins': 15,       # 15 minutes to acknowledge (TTA)
        'containment_mins': 60,    # 1 hour to contain (TTC)
        'resolution_mins': 240,    # 4 hours to resolve (TTR)
    },
    'high': {
        'response_mins': 30,       # 30 minutes to acknowledge
        'containment_mins': 240,   # 4 hours to contain
        'resolution_mins': 720,    # 12 hours to resolve
    },
    'medium': {
        'response_mins': 120,      # 2 hours to acknowledge
        'containment_mins': 720,   # 12 hours to contain
        'resolution_mins': 1440,   # 24 hours to resolve
    },
    'low': {
        'response_mins': 480,      # 8 hours to acknowledge
        'containment_mins': 1440,  # 24 hours to contain
        'resolution_mins': 2880,   # 48 hours to resolve
    }
}

VALID_STATUSES = ['open', 'investigating', 'contained', 'resolved', 'closed']

# In-memory stores for ultra-fast unit testing and fallback
_LOCAL_INCIDENTS: Dict[str, Dict[str, Any]] = {}
_LOCAL_CASE_NOTES: Dict[str, List[Dict[str, Any]]] = {}      # incident_id -> list of notes
_LOCAL_ATTACHMENTS: Dict[str, Dict[str, Any]] = {}           # attachment_id -> attachment dict
_LOCAL_SAVED_SEARCHES: Dict[str, Dict[str, Any]] = {}        # search_id -> search dict


def clear_case_caches() -> None:
    """Resets in-memory stores for unit testing."""
    _LOCAL_INCIDENTS.clear()
    _LOCAL_CASE_NOTES.clear()
    _LOCAL_ATTACHMENTS.clear()
    _LOCAL_SAVED_SEARCHES.clear()


def _parse_iso(val: Any) -> Optional[datetime]:
    if not val:
        return None
    if isinstance(val, datetime):
        return val if val.tzinfo else val.replace(tzinfo=timezone.utc)
    try:
        from dateutil import parser
        dt = parser.isoparse(str(val))
        return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
    except Exception:
        return None


class CaseService:
    """Autonomous Case Management & SLA Engine for ECS."""

    # =========================================================================
    # 1. SLA CALCULATION & MILESTONES
    # =========================================================================

    @classmethod
    def calculate_sla_status(cls, incident: Dict[str, Any], now: Optional[datetime] = None) -> Dict[str, Any]:
        """
        Dynamically computes SLA progress, milestones, and breach statuses.
        Stages:
          - Acknowledgment (TTA): target response_mins
          - Containment (TTC): target containment_mins
          - Resolution (TTR): target resolution_mins
        Status grades:
          - 'met': milestone achieved before target
          - 'on_track': < 75% of target time elapsed
          - 'at_risk': >= 75% and <= 100% of target time elapsed
          - 'breached': > 100% of target time elapsed without completion
        """
        now_dt = now or datetime.now(timezone.utc)
        sev = (incident.get('severity') or 'medium').lower()
        sla_cfg = SLA_TARGETS.get(sev, SLA_TARGETS['medium'])

        # Start time is detection_date or incident_date or created_at
        start_dt = (
            _parse_iso(incident.get('detection_date'))
            or _parse_iso(incident.get('incident_date'))
            or _parse_iso(incident.get('created_at'))
            or now_dt
        )

        ack_dt = _parse_iso(incident.get('acknowledged_at'))
        cont_dt = _parse_iso(incident.get('contained_at'))
        res_dt = _parse_iso(incident.get('resolved_at'))
        status = incident.get('status', 'open').lower()

        # Target minutes
        tgt_resp = int(incident.get('sla_target_response_mins') or sla_cfg['response_mins'])
        tgt_cont = int(incident.get('sla_target_containment_mins') or sla_cfg['containment_mins'])
        tgt_resol = int(incident.get('sla_target_resolution_mins') or sla_cfg['resolution_mins'])

        # 1. Response / Acknowledgment milestone
        if ack_dt:
            resp_elapsed = max(0.0, (ack_dt - start_dt).total_seconds() / 60.0)
            resp_status = 'met' if resp_elapsed <= tgt_resp else 'breached'
            resp_remaining = max(0.0, tgt_resp - resp_elapsed)
        else:
            resp_elapsed = max(0.0, (now_dt - start_dt).total_seconds() / 60.0)
            resp_remaining = max(0.0, tgt_resp - resp_elapsed)
            if resp_elapsed > tgt_resp:
                resp_status = 'breached'
            elif resp_elapsed >= 0.75 * tgt_resp:
                resp_status = 'at_risk'
            else:
                resp_status = 'on_track'

        # 2. Containment milestone
        if cont_dt:
            cont_elapsed = max(0.0, (cont_dt - start_dt).total_seconds() / 60.0)
            cont_status = 'met' if cont_elapsed <= tgt_cont else 'breached'
            cont_remaining = max(0.0, tgt_cont - cont_elapsed)
        else:
            cont_elapsed = max(0.0, (now_dt - start_dt).total_seconds() / 60.0)
            cont_remaining = max(0.0, tgt_cont - cont_elapsed)
            if cont_elapsed > tgt_cont:
                cont_status = 'breached'
            elif cont_elapsed >= 0.75 * tgt_cont:
                cont_status = 'at_risk'
            else:
                cont_status = 'on_track'

        # 3. Resolution milestone
        if res_dt:
            resol_elapsed = max(0.0, (res_dt - start_dt).total_seconds() / 60.0)
            resol_status = 'met' if resol_elapsed <= tgt_resol else 'breached'
            resol_remaining = max(0.0, tgt_resol - resol_elapsed)
        else:
            resol_elapsed = max(0.0, (now_dt - start_dt).total_seconds() / 60.0)
            resol_remaining = max(0.0, tgt_resol - resol_elapsed)
            if resol_elapsed > tgt_resol:
                resol_status = 'breached'
            elif resol_elapsed >= 0.75 * tgt_resol:
                resol_status = 'at_risk'
            else:
                resol_status = 'on_track'

        # Overall SLA breach
        is_breached = (
            resp_status == 'breached' or
            cont_status == 'breached' or
            resol_status == 'breached'
        )

        overall_status = 'breached' if is_breached else (
            'at_risk' if (resp_status == 'at_risk' or cont_status == 'at_risk' or resol_status == 'at_risk') else 'on_track'
        )
        if status in ('resolved', 'closed') and not is_breached:
            overall_status = 'met'

        resolution_deadline = start_dt + timedelta(minutes=tgt_resol)

        return {
            'severity': sev,
            'status': status,
            'overall_sla_status': overall_status,
            'is_breached': is_breached,
            'resolution_deadline': resolution_deadline.isoformat(),
            'response': {
                'target_mins': tgt_resp,
                'elapsed_mins': round(resp_elapsed, 2),
                'remaining_mins': round(resp_remaining, 2),
                'status': resp_status,
                'acknowledged_at': ack_dt.isoformat() if ack_dt else None
            },
            'containment': {
                'target_mins': tgt_cont,
                'elapsed_mins': round(cont_elapsed, 2),
                'remaining_mins': round(cont_remaining, 2),
                'status': cont_status,
                'contained_at': cont_dt.isoformat() if cont_dt else None
            },
            'resolution': {
                'target_mins': tgt_resol,
                'elapsed_mins': round(resol_elapsed, 2),
                'remaining_mins': round(resol_remaining, 2),
                'status': resol_status,
                'resolved_at': res_dt.isoformat() if res_dt else None
            }
        }

    # =========================================================================
    # 2. CASE ASSIGNMENT & STATUS TRANSITIONS
    # =========================================================================

    @classmethod
    def assign_case(
        cls,
        org_id: str,
        incident_id: str,
        user_id: str,
        assigned_by: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Assigns an incident case to a designated analyst or responder.
        If case was 'open', transitions automatically to 'investigating' and records acknowledged_at.
        """
        oid = str(org_id).strip()
        iid = str(incident_id).strip()
        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()

        # Load existing incident
        incident = cls.get_case(oid, iid)
        if not incident:
            raise ValueError(f"Incident {iid} not found for organization {oid}")

        updates: Dict[str, Any] = {
            'assigned_to': user_id,
            'updated_at': now_iso,
        }

        # If currently open, promote to investigating
        if incident.get('status') == 'open':
            updates['status'] = 'investigating'
            if not incident.get('acknowledged_at'):
                updates['acknowledged_at'] = now_iso

        cls._persist_incident_update(oid, iid, updates)
        incident.update(updates)

        # Audit log
        try:
            log_action(assigned_by, 'case_assigned', 'incident', iid, {
                'assigned_to': user_id,
                'previous_status': incident.get('status'),
                'new_status': updates.get('status', incident.get('status'))
            })
        except Exception as e:
            logger.debug(f"Audit log skipped for case assignment: {e}")

        incident['sla'] = cls.calculate_sla_status(incident)
        return incident

    @classmethod
    def transition_status(
        cls,
        org_id: str,
        incident_id: str,
        new_status: str,
        user_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Transitions case status through standard lifecycle:
        open -> investigating -> contained -> resolved -> closed
        Records milestones (acknowledged_at, contained_at, resolved_at).
        """
        oid = str(org_id).strip()
        iid = str(incident_id).strip()
        target_status = str(new_status).lower().strip()

        if target_status not in VALID_STATUSES:
            raise ValueError(f"Invalid status '{new_status}'. Allowed: {VALID_STATUSES}")

        incident = cls.get_case(oid, iid)
        if not incident:
            raise ValueError(f"Incident {iid} not found for organization {oid}")

        now = datetime.now(timezone.utc)
        now_iso = now.isoformat()

        updates: Dict[str, Any] = {
            'status': target_status,
            'updated_at': now_iso,
        }

        if target_status == 'investigating' and not incident.get('acknowledged_at'):
            updates['acknowledged_at'] = now_iso
        elif target_status == 'contained' and not incident.get('contained_at'):
            updates['contained_at'] = now_iso
        elif target_status in ('resolved', 'closed') and not incident.get('resolved_at'):
            updates['resolved_at'] = now_iso

        cls._persist_incident_update(oid, iid, updates)
        incident.update(updates)

        try:
            log_action(user_id, 'case_status_transition', 'incident', iid, {
                'from_status': incident.get('status'),
                'to_status': target_status
            })
        except Exception as e:
            logger.debug(f"Audit log skipped for status transition: {e}")

        incident['sla'] = cls.calculate_sla_status(incident)
        return incident

    @classmethod
    def get_case(cls, org_id: str, incident_id: str) -> Optional[Dict[str, Any]]:
        """Retrieves a single incident case with tenant scoping and SLA calculation."""
        oid = str(org_id).strip()
        iid = str(incident_id).strip()

        # Check in-memory store first
        if iid in _LOCAL_INCIDENTS:
            inc = _LOCAL_INCIDENTS[iid]
            if str(inc.get('organization_id')) == oid:
                res = dict(inc)
                res['sla'] = cls.calculate_sla_status(res)
                return res

        # Check DB
        try:
            sb = get_service_supabase()
            res = sb.table('incidents').select('*').eq('id', iid).eq('organization_id', oid).execute()
            if res.data:
                inc = dict(res.data[0])
                inc['sla'] = cls.calculate_sla_status(inc)
                return inc
        except Exception as e:
            logger.debug(f"DB incident fetch note: {e}")

        return None

    @classmethod
    def _persist_incident_update(cls, org_id: str, incident_id: str, updates: Dict[str, Any]) -> None:
        """Persists updates to local cache and database."""
        iid = str(incident_id).strip()
        oid = str(org_id).strip()

        if iid in _LOCAL_INCIDENTS:
            _LOCAL_INCIDENTS[iid].update(updates)

        try:
            sb = get_service_supabase()
            sb.table('incidents').update(updates).eq('id', iid).eq('organization_id', oid).execute()
        except Exception as e:
            logger.debug(f"DB incident update note: {e}")

    # =========================================================================
    # 3. CASE NOTES
    # =========================================================================

    @classmethod
    def add_note(
        cls,
        org_id: str,
        incident_id: str,
        note: str,
        author_id: Optional[str] = None,
        author_name: Optional[str] = None,
        is_internal: bool = True
    ) -> Dict[str, Any]:
        """Adds an analyst note to the case comments log."""
        oid = str(org_id).strip()
        iid = str(incident_id).strip()
        text = str(note or '').strip()

        if not text:
            raise ValueError("Note text cannot be empty")

        incident = cls.get_case(oid, iid)
        if not incident:
            raise ValueError(f"Incident {iid} not found for organization {oid}")

        note_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        record = {
            'id': note_id,
            'organization_id': oid,
            'incident_id': iid,
            'author_id': author_id,
            'author_name': author_name or 'SOC Analyst',
            'note': text,
            'is_internal': is_internal,
            'created_at': now
        }

        if iid not in _LOCAL_CASE_NOTES:
            _LOCAL_CASE_NOTES[iid] = []
        _LOCAL_CASE_NOTES[iid].append(record)

        try:
            sb = get_service_supabase()
            sb.table('case_notes').insert(record).execute()
        except Exception as e:
            logger.debug(f"DB case_notes insert note: {e}")

        try:
            log_action(author_id, 'case_note_added', 'incident', iid, {'note_id': note_id})
        except Exception as e:
            logger.debug(f"Audit log skipped for case note: {e}")

        return record

    @classmethod
    def list_notes(cls, org_id: str, incident_id: str) -> List[Dict[str, Any]]:
        """Lists notes for a given incident scoped by organization_id."""
        oid = str(org_id).strip()
        iid = str(incident_id).strip()

        local_notes = [
            dict(n) for n in _LOCAL_CASE_NOTES.get(iid, [])
            if str(n.get('organization_id')) == oid
        ]

        try:
            sb = get_service_supabase()
            res = sb.table('case_notes').select('*').eq('incident_id', iid).eq('organization_id', oid).order('created_at', desc=False).execute()
            if res.data:
                seen_ids = {n['id'] for n in local_notes}
                for row in res.data:
                    if row['id'] not in seen_ids:
                        local_notes.append(dict(row))
        except Exception as e:
            logger.debug(f"DB case_notes fetch note: {e}")

        return sorted(local_notes, key=lambda x: str(x.get('created_at')))

    # =========================================================================
    # 4. CASE ATTACHMENTS & EVIDENCE ARTIFACTS
    # =========================================================================

    @classmethod
    def add_attachment(
        cls,
        org_id: str,
        incident_id: str,
        filename: str,
        content_bytes: bytes,
        content_type: str = 'application/octet-stream',
        uploaded_by: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Attaches an evidence file or report artifact to the case.
        Calculates SHA-256 seal over the raw bytes.
        """
        oid = str(org_id).strip()
        iid = str(incident_id).strip()
        name = str(filename or 'evidence.bin').strip()

        if not content_bytes:
            raise ValueError("Attachment content cannot be empty")

        incident = cls.get_case(oid, iid)
        if not incident:
            raise ValueError(f"Incident {iid} not found for organization {oid}")

        sha256_hash = hashlib.sha256(content_bytes).hexdigest()
        att_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        record = {
            'id': att_id,
            'organization_id': oid,
            'incident_id': iid,
            'filename': name,
            'file_size': len(content_bytes),
            'content_type': content_type,
            'sha256': sha256_hash,
            'storage_path': f"evidence/{oid}/{iid}/{att_id}_{name}",
            'uploaded_by': uploaded_by,
            'created_at': now
        }

        _LOCAL_ATTACHMENTS[att_id] = {**record, '_bytes': content_bytes}

        try:
            sb = get_service_supabase()
            sb.table('case_attachments').insert(record).execute()
        except Exception as e:
            logger.debug(f"DB case_attachments insert note: {e}")

        try:
            log_action(uploaded_by, 'case_attachment_added', 'incident', iid, {
                'attachment_id': att_id,
                'filename': name,
                'sha256': sha256_hash,
                'file_size': len(content_bytes)
            })
        except Exception as e:
            logger.debug(f"Audit log skipped for case attachment: {e}")

        return record

    @classmethod
    def list_attachments(cls, org_id: str, incident_id: str) -> List[Dict[str, Any]]:
        """Lists attached evidence artifacts for an incident."""
        oid = str(org_id).strip()
        iid = str(incident_id).strip()

        local_atts = [
            {k: v for k, v in a.items() if k != '_bytes'}
            for a in _LOCAL_ATTACHMENTS.values()
            if str(a.get('organization_id')) == oid and str(a.get('incident_id')) == iid
        ]

        try:
            sb = get_service_supabase()
            res = sb.table('case_attachments').select('*').eq('incident_id', iid).eq('organization_id', oid).execute()
            if res.data:
                seen_ids = {a['id'] for a in local_atts}
                for row in res.data:
                    if row['id'] not in seen_ids:
                        local_atts.append(dict(row))
        except Exception as e:
            logger.debug(f"DB case_attachments fetch note: {e}")

        return local_atts

    @classmethod
    def verify_attachment(cls, org_id: str, attachment_id: str, content_bytes: bytes) -> Dict[str, Any]:
        """Verifies integrity of an attachment against its recorded SHA-256 seal."""
        oid = str(org_id).strip()
        aid = str(attachment_id).strip()

        # Find attachment
        att = None
        if aid in _LOCAL_ATTACHMENTS:
            candidate = _LOCAL_ATTACHMENTS[aid]
            if str(candidate.get('organization_id')) == oid:
                att = candidate

        if not att:
            try:
                sb = get_service_supabase()
                res = sb.table('case_attachments').select('*').eq('id', aid).eq('organization_id', oid).execute()
                if res.data:
                    att = res.data[0]
            except Exception as e:
                logger.debug(f"DB verify attachment note: {e}")

        if not att:
            return {'verified': False, 'error': 'Attachment not found'}

        calc_hash = hashlib.sha256(content_bytes).hexdigest()
        is_valid = (calc_hash.lower() == att['sha256'].lower())

        return {
            'attachment_id': aid,
            'filename': att.get('filename'),
            'expected_sha256': att.get('sha256'),
            'computed_sha256': calc_hash,
            'verified': is_valid
        }

    # =========================================================================
    # 5. CROSS-TIME ENTITY TIMELINE
    # =========================================================================

    @classmethod
    def get_entity_timeline(
        cls,
        org_id: str,
        entity_type: str,
        entity_value: str,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Gathers a cross-time chronological timeline for an entity (account, ip, device, user).
        Aggregates:
          - Security Events
          - Alerts
          - Incidents
          - Response Actions (blocks, freezes, step-ups)
        """
        oid = str(org_id).strip()
        etype = str(entity_type).lower().strip()
        eval_ = str(entity_value).strip()

        timeline_items: List[Dict[str, Any]] = []

        # 1. Fetch relevant security events
        try:
            sb = get_service_supabase()
            col_map = {
                'account': 'account_id_pub',
                'ip': 'source_ip',
                'device': 'device_id_pub',
                'user': 'user_id_pub'
            }
            col = col_map.get(etype, 'account_id_pub')

            q = sb.table('security_events').select('*').eq('organization_id', oid).eq(col, eval_)
            if start_time:
                q = q.gte('occurred_at', start_time)
            if end_time:
                q = q.lte('occurred_at', end_time)
            ev_res = q.order('occurred_at', desc=True).limit(50).execute()

            for ev in (ev_res.data or []):
                timeline_items.append({
                    'item_type': 'event',
                    'timestamp': ev.get('occurred_at') or ev.get('created_at'),
                    'title': f"Event: {ev.get('event_type')}",
                    'description': f"Channel {ev.get('channel') or 'Web'}, amount: {ev.get('amount') or 0} ETB",
                    'risk_score': ev.get('risk_score', 0),
                    'metadata': ev
                })
        except Exception as e:
            logger.debug(f"Timeline events lookup note: {e}")

        # 2. Fetch relevant alerts
        try:
            sb = get_service_supabase()
            a_res = sb.table('alerts').select('*').eq('organization_id', oid).order('created_at', desc=True).limit(50).execute()
            for al in (a_res.data or []):
                ev_data = al.get('evidence') or {}
                # Match entity in alert
                match = False
                if etype == 'ip' and (ev_data.get('source_ip') == eval_ or eval_ in str(al.get('title'))):
                    match = True
                elif etype == 'account' and (ev_data.get('account') == eval_ or eval_ in str(al.get('title'))):
                    match = True
                elif etype == 'device' and ev_data.get('device_id') == eval_:
                    match = True
                elif etype == 'user' and (ev_data.get('user_id') == eval_ or str(al.get('user_id')) == eval_):
                    match = True

                if match:
                    timeline_items.append({
                        'item_type': 'alert',
                        'timestamp': al.get('created_at'),
                        'title': f"Alert: {al.get('title')}",
                        'description': al.get('description'),
                        'severity': al.get('severity'),
                        'risk_score': al.get('risk_score', 0),
                        'metadata': al
                    })
        except Exception as e:
            logger.debug(f"Timeline alerts lookup note: {e}")

        # 3. Fetch response actions
        try:
            sb = get_service_supabase()
            ra_res = sb.table('response_actions').select('*').eq('organization_id', oid).eq('target_entity_id', eval_).order('created_at', desc=True).limit(50).execute()
            for ra in (ra_res.data or []):
                timeline_items.append({
                    'item_type': 'response_action',
                    'timestamp': ra.get('executed_at') or ra.get('created_at'),
                    'title': f"Mitigation: {ra.get('action_type')}",
                    'description': f"Status: {ra.get('status')}. Reason: {ra.get('reason')}",
                    'metadata': ra
                })
        except Exception as e:
            logger.debug(f"Timeline response actions lookup note: {e}")

        # Sort timeline chronologically (most recent first)
        timeline_items.sort(key=lambda x: str(x.get('timestamp') or ''), reverse=True)

        return {
            'organization_id': oid,
            'entity_type': etype,
            'entity_value': eval_,
            'total_items': len(timeline_items),
            'timeline': timeline_items
        }

    # =========================================================================
    # 6. RELATED ALERT & CASE GRAPH
    # =========================================================================

    @classmethod
    def get_case_graph(cls, org_id: str, incident_id: str) -> Dict[str, Any]:
        """
        Builds graph representation linking the case to correlated alerts, indicators, entities,
        and response actions for SOC visualization.
        """
        oid = str(org_id).strip()
        iid = str(incident_id).strip()

        incident = cls.get_case(oid, iid)
        if not incident:
            return {'error': 'Case not found', 'nodes': [], 'edges': []}

        # Build graph nodes and edges
        nodes = [{
            'id': f"inc_{iid}",
            'label': incident.get('title'),
            'type': 'case',
            'severity': incident.get('severity'),
            'status': incident.get('status')
        }]
        edges = []

        # Correlated alerts
        try:
            sb = get_service_supabase()
            al_res = sb.table('alerts').select('*').eq('organization_id', oid).eq('related_incident_id', iid).execute()
            alerts = al_res.data or []
            for al in alerts:
                node_id = f"alert_{al['id']}"
                nodes.append({
                    'id': node_id,
                    'label': al.get('title'),
                    'type': 'alert',
                    'severity': al.get('severity'),
                    'risk_score': al.get('risk_score', 0)
                })
                edges.append({
                    'from': f"inc_{iid}",
                    'to': node_id,
                    'relation': 'contains_alert'
                })
        except Exception as e:
            logger.debug(f"Case graph alerts lookup note: {e}")

        # Linked indicators
        try:
            sb = get_service_supabase()
            ind_res = sb.table('incident_indicators').select('*, indicator:indicators(*)').eq('incident_id', iid).execute()
            for row in (ind_res.data or []):
                ind = row.get('indicator')
                if ind:
                    node_id = f"ind_{ind['id']}"
                    nodes.append({
                        'id': node_id,
                        'label': f"{ind.get('indicator_type', '').upper()}: {ind.get('value')}",
                        'type': 'indicator',
                        'status': ind.get('status')
                    })
                    edges.append({
                        'from': f"inc_{iid}",
                        'to': node_id,
                        'relation': 'linked_indicator'
                    })
        except Exception as e:
            logger.debug(f"Case graph indicators lookup note: {e}")

        return {
            'organization_id': oid,
            'incident_id': iid,
            'nodes': nodes,
            'edges': edges,
            'total_nodes': len(nodes),
            'total_edges': len(edges)
        }

    # =========================================================================
    # 7. SAVED SEARCHES & CROSS-TIME EVENT SEARCH
    # =========================================================================

    @classmethod
    def create_saved_search(
        cls,
        org_id: str,
        user_id: str,
        name: str,
        query_params: Dict[str, Any],
        description: Optional[str] = None,
        is_shared: bool = False
    ) -> Dict[str, Any]:
        """Creates a saved search query configuration."""
        oid = str(org_id).strip()
        uid = str(user_id).strip()
        sname = str(name or '').strip()

        if not sname:
            raise ValueError("Search name is required")

        search_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        record = {
            'id': search_id,
            'organization_id': oid,
            'user_id': uid,
            'name': sname,
            'description': description or '',
            'query_params': query_params or {},
            'is_shared': bool(is_shared),
            'created_at': now,
            'updated_at': now
        }

        _LOCAL_SAVED_SEARCHES[search_id] = record

        try:
            sb = get_service_supabase()
            sb.table('saved_searches').insert(record).execute()
        except Exception as e:
            logger.debug(f"DB saved_searches insert note: {e}")

        return record

    @classmethod
    def list_saved_searches(cls, org_id: str, user_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Lists saved searches for a tenant, including personal and shared queries."""
        oid = str(org_id).strip()
        uid = str(user_id).strip() if user_id else None

        results: List[Dict[str, Any]] = []

        # Local cache
        for s in _LOCAL_SAVED_SEARCHES.values():
            if str(s.get('organization_id')) != oid:
                continue
            if s.get('is_shared') or (uid and str(s.get('user_id')) == uid):
                results.append(dict(s))

        # DB
        try:
            sb = get_service_supabase()
            q = sb.table('saved_searches').select('*').eq('organization_id', oid)
            res = q.execute()
            if res.data:
                seen_ids = {r['id'] for r in results}
                for row in res.data:
                    if row['id'] not in seen_ids:
                        if row.get('is_shared') or (uid and str(row.get('user_id')) == uid):
                            results.append(dict(row))
        except Exception as e:
            logger.debug(f"DB saved_searches fetch note: {e}")

        return sorted(results, key=lambda x: str(x.get('name', '')))

    @classmethod
    def delete_saved_search(cls, org_id: str, search_id: str, user_id: Optional[str] = None) -> bool:
        """Deletes a saved search scoped by tenant and ownership."""
        oid = str(org_id).strip()
        sid = str(search_id).strip()

        if sid in _LOCAL_SAVED_SEARCHES:
            s = _LOCAL_SAVED_SEARCHES[sid]
            if str(s.get('organization_id')) == oid:
                del _LOCAL_SAVED_SEARCHES[sid]

        try:
            sb = get_service_supabase()
            sb.table('saved_searches').delete().eq('id', sid).eq('organization_id', oid).execute()
        except Exception as e:
            logger.debug(f"DB saved_searches delete note: {e}")

        return True

    @classmethod
    def search_events_cross_time(
        cls,
        org_id: str,
        query_params: Dict[str, Any],
        limit: int = 100,
        offset: int = 0
    ) -> Dict[str, Any]:
        """
        Cross-time query engine searching security_events with multi-parameter filtering.
        Supported filters:
          - start_time, end_time (ISO timestamps)
          - event_type (e.g. transfer, auth, api_call)
          - channel (e.g. mobile_app, ussd, web)
          - account (account_id_pub)
          - source_ip
          - search (keyword in payload)
          - min_amount, max_amount
        """
        oid = str(org_id).strip()
        params = query_params or {}

        try:
            sb = get_service_supabase()
            q = sb.table('security_events').select('*').eq('organization_id', oid)

            if params.get('event_type'):
                q = q.eq('event_type', str(params['event_type']).strip())
            if params.get('channel'):
                q = q.eq('channel', str(params['channel']).strip())
            if params.get('account'):
                q = q.eq('account_id_pub', str(params['account']).strip())
            if params.get('source_ip'):
                q = q.eq('source_ip', str(params['source_ip']).strip())
            if params.get('start_time'):
                q = q.gte('occurred_at', str(params['start_time']).strip())
            if params.get('end_time'):
                q = q.lte('occurred_at', str(params['end_time']).strip())

            res = q.order('occurred_at', desc=True).limit(min(limit, 500)).execute()
            events = res.data or []

            # In-memory post filtering if search text or amount range provided
            search_text = str(params.get('search') or '').lower()
            min_amt = float(params['min_amount']) if 'min_amount' in params and params['min_amount'] is not None else None
            max_amt = float(params['max_amount']) if 'max_amount' in params and params['max_amount'] is not None else None

            filtered = []
            for ev in events:
                if search_text:
                    ev_str = str(ev).lower()
                    if search_text not in ev_str:
                        continue
                if min_amt is not None:
                    if float(ev.get('amount') or 0) < min_amt:
                        continue
                if max_amt is not None:
                    if float(ev.get('amount') or 0) > max_amt:
                        continue
                filtered.append(ev)

            return {
                'organization_id': oid,
                'total_results': len(filtered),
                'limit': limit,
                'offset': offset,
                'events': filtered[offset:offset + limit]
            }
        except Exception as e:
            logger.warning(f"Cross-time event search failed: {e}")
            return {
                'organization_id': oid,
                'total_results': 0,
                'events': [],
                'error': str(e)
            }
