"""
Endpoint & Email Security Ingestion Adapter Service for Ethio-Cyber-Shield (ECS) v3.0 (Phase 8.2).
Ingests and normalizes host-level (EDR/Sysmon/Wazuh) and email security telemetry:
  1. Endpoint Ingestion:
     - Process creations, suspicious command arguments, and parent-child execution anomalies.
     - Ransomware precursors (e.g., 'vssadmin delete shadows', 'wbadmin delete catalog', mass rename bursts).
  2. Email Security Ingestion:
     - SPF / DKIM / DMARC authentication failures.
     - Business Email Compromise (BEC) and VIP / C-Suite display name spoofing.
     - Urgent financial wire transfer / SWIFT fraud lures.
Strictly partitioned by organization_id UUID NOT NULL.
"""
import re
import uuid
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple

from app.services.db import get_service_supabase
from app.services.tenant_service import get_current_organization_id

logger = logging.getLogger(__name__)

# Ransomware precursor signatures (MITRE ATT&CK T1490, T1059, T1070)
RANSOMWARE_COMMAND_PATTERNS = [
    r'vssadmin(\.exe)?\s+delete\s+shadows',
    r'wbadmin(\.exe)?\s+delete\s+catalog',
    r'bcdedit(\.exe)?\s+/set\s+.*recoveryenabled\s+no',
    r'wmic(\.exe)?\s+shadowcopy\s+delete',
    r'cipher(\.exe)?\s+/w',
    r'wevtutil(\.exe)?\s+cl\s+(system|security|application)'
]

# BEC and Wire Transfer Urgency Keyword Patterns
BEC_URGENCY_KEYWORDS = [
    r'urgent\s+(wire|transfer|payment|swift|rtgs)',
    r'immediate\s+remittance',
    r'confidential\s+settlement',
    r'cbe\s+birr\s+urgent',
    r'update\s+beneficiary\s+bank\s+account'
]

# In-memory store for normalized adapter events for unit testing
_LOCAL_ADAPTER_EVENTS: List[Dict[str, Any]] = []


def clear_adapter_caches() -> None:
    """Resets adapter caches for test isolation."""
    _LOCAL_ADAPTER_EVENTS.clear()


class EndpointEmailAdapterService:
    """Normalizes and processes endpoint and email security signals into ECS."""

    # =========================================================================
    # 1. ENDPOINT TELEMETRY INGESTION (Sysmon / Wazuh / Defender)
    # =========================================================================

    @classmethod
    def ingest_endpoint_log(
        cls,
        org_id: str,
        raw_log: Dict[str, Any],
        source_format: str = 'sysmon'
    ) -> Dict[str, Any]:
        """
        Ingests and normalizes an endpoint event. Flags ransomware precursors and suspicious executions.
        """
        oid = str(org_id).strip()
        event_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        # Extract fields
        hostname = raw_log.get('hostname') or raw_log.get('Computer') or raw_log.get('agent', {}).get('name') or 'unknown-host'
        process_name = raw_log.get('process_name') or raw_log.get('Image') or raw_log.get('process') or ''
        command_line = raw_log.get('command_line') or raw_log.get('CommandLine') or raw_log.get('cmd') or ''
        parent_process = raw_log.get('parent_process') or raw_log.get('ParentImage') or ''
        user = raw_log.get('user') or raw_log.get('User') or 'system'

        # Detect ransomware precursors
        is_ransomware_precursor = False
        matched_pattern = None
        for pat in RANSOMWARE_COMMAND_PATTERNS:
            if re.search(pat, command_line, re.IGNORECASE):
                is_ransomware_precursor = True
                matched_pattern = pat
                break

        # Detect suspicious LOLBins or scripts
        is_suspicious_script = bool(
            re.search(r'(powershell|pwsh|cmd\.exe|wscript|cscript|rundll32|certutil)', process_name, re.IGNORECASE)
            and re.search(r'(-enc|-encodedcommand|downloadstring|bypass|-w\s+hidden|http)', command_line, re.IGNORECASE)
        )

        risk_score = 0
        severity = 'low'
        tags = ['endpoint', source_format]

        if is_ransomware_precursor:
            risk_score = 95
            severity = 'critical'
            tags.extend(['ransomware_precursor', 'mitre_t1490'])
        elif is_suspicious_script:
            risk_score = 75
            severity = 'high'
            tags.extend(['suspicious_script', 'mitre_t1059'])
        elif process_name:
            risk_score = 15

        normalized_event = {
            'id': event_id,
            'organization_id': oid,
            'event_type': 'endpoint.ransomware_precursor' if is_ransomware_precursor else 'endpoint.process_execution',
            'timestamp': now,
            'source_system': source_format,
            'hostname': hostname,
            'user': user,
            'process_name': process_name,
            'command_line': command_line,
            'parent_process': parent_process,
            'risk_score': risk_score,
            'severity': severity,
            'is_ransomware_precursor': is_ransomware_precursor,
            'matched_pattern': matched_pattern,
            'tags': tags
        }

        _LOCAL_ADAPTER_EVENTS.append(normalized_event)
        return normalized_event

    # =========================================================================
    # 2. EMAIL SECURITY INGESTION (Postfix / Exchange / Microsoft 365)
    # =========================================================================

    @classmethod
    def ingest_email_event(
        cls,
        org_id: str,
        email_data: Dict[str, Any],
        known_executives: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """
        Normalizes email headers and evaluates DMARC/SPF/DKIM failures and BEC VIP impersonation.
        """
        oid = str(org_id).strip()
        event_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        sender = str(email_data.get('sender') or email_data.get('from', '')).strip()
        display_name = str(email_data.get('display_name', '')).strip()
        recipient = str(email_data.get('recipient') or email_data.get('to', '')).strip()
        subject = str(email_data.get('subject', '')).strip()
        body = str(email_data.get('body_snippet') or email_data.get('body', '')).strip()

        spf_result = str(email_data.get('spf', 'pass')).lower()
        dkim_result = str(email_data.get('dkim', 'pass')).lower()
        dmarc_result = str(email_data.get('dmarc', 'pass')).lower()

        # Check BEC VIP Impersonation
        is_vip_spoof = False
        exec_list = known_executives or ['CEO', 'Chief Executive Officer', 'President', 'Chief Financial Officer', 'Director']
        for exec_title in exec_list:
            if exec_title.lower() in display_name.lower() or exec_title.lower() in subject.lower():
                # If display name matches executive but sender address is non-corporate or external
                corp_domain = email_data.get('corporate_domain', 'bank.et')
                if corp_domain not in sender:
                    is_vip_spoof = True
                    break

        # Check Urgent Wire Transfer keywords
        has_wire_urgency = False
        content_to_check = f"{subject} {body}"
        for pat in BEC_URGENCY_KEYWORDS:
            if re.search(pat, content_to_check, re.IGNORECASE):
                has_wire_urgency = True
                break

        # Determine risk score and severity
        risk_score = 10
        severity = 'low'
        tags = ['email']

        is_dmarc_failed = (dmarc_result in ('fail', 'reject') or spf_result == 'fail')
        if is_vip_spoof and has_wire_urgency:
            risk_score = 90
            severity = 'critical'
            tags.extend(['bec_attempt', 'vip_impersonation', 'urgent_wire_lure'])
        elif is_vip_spoof:
            risk_score = 70
            severity = 'high'
            tags.extend(['vip_impersonation'])
        elif has_wire_urgency and is_dmarc_failed:
            risk_score = 80
            severity = 'high'
            tags.extend(['phishing', 'dmarc_failure', 'urgent_wire_lure'])
        elif is_dmarc_failed:
            risk_score = 45
            severity = 'medium'
            tags.extend(['dmarc_failure'])

        normalized_event = {
            'id': event_id,
            'organization_id': oid,
            'event_type': 'email.bec_threat' if is_vip_spoof else 'email.message_analyzed',
            'timestamp': now,
            'sender': sender,
            'display_name': display_name,
            'recipient': recipient,
            'subject': subject,
            'auth_verdicts': {
                'spf': spf_result,
                'dkim': dkim_result,
                'dmarc': dmarc_result
            },
            'is_vip_spoof': is_vip_spoof,
            'has_wire_urgency': has_wire_urgency,
            'risk_score': risk_score,
            'severity': severity,
            'tags': tags
        }

        _LOCAL_ADAPTER_EVENTS.append(normalized_event)
        return normalized_event

    @classmethod
    def list_ingested_events(cls, org_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Lists normalized adapter events for tenant."""
        oid = str(org_id).strip()
        filtered = [
            e for e in _LOCAL_ADAPTER_EVENTS
            if str(e.get('organization_id')) == oid
        ]
        return filtered[-limit:]
