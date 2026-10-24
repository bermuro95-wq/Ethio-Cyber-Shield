"""
National Identity Assurance (Fayda Digital ID) Adapter for Ethio-Cyber-Shield (ECS) v3.0 (Phase 8.4).
Fulfills identity-assurance integration under Ethiopian Digital ID Proclamation No. 1284/2023:
  1. Ingests Fayda authentication and e-KYC verification events (biometric, OTP, demographic).
  2. Protects customer privacy via keyed hashing of Fayda FIN (no raw National ID numbers stored).
  3. Evaluates Identity Assurance Level (IAL):
     - Biometric face/fingerprint verified -> High Identity Assurance (reduces transaction fraud score).
     - Biometric mismatch or token locked -> Critical Impersonation Warning (+50 risk).
     - Biometric spoof / presentation attack detected -> P0 Identity Theft Alert (+90 risk).
  4. Provides real-time identity context to ECS detection rules and Risk Model v2.
Strictly partitioned by organization_id UUID NOT NULL.
"""
import uuid
import hmac
import hashlib
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from app.services.signal_exchange_service import HUB_PEPPER

logger = logging.getLogger(__name__)

# In-memory store for Fayda verification telemetry
_LOCAL_FAYDA_EVENTS: Dict[str, Dict[str, Any]] = {}  # event_id -> event_dict


def clear_fayda_caches() -> None:
    """Resets Fayda caches for test isolation."""
    _LOCAL_FAYDA_EVENTS.clear()


class FaydaIdService:
    """Processes Fayda National Digital ID verification telemetry and risk weighting."""

    @classmethod
    def hash_fayda_fin(cls, raw_fin: str) -> str:
        """
        Derives privacy-preserving keyed hash of Fayda Identification Number (FIN).
        Protects citizen privacy conforming to PDPP Proclamation No. 1321/2024.
        """
        clean_fin = str(raw_fin).replace('-', '').replace(' ', '').strip()
        h = hmac.new(HUB_PEPPER.encode('utf-8'), clean_fin.encode('utf-8'), hashlib.sha256)
        return f"fayda_fin_h_{h.hexdigest()[:24]}"

    @classmethod
    def ingest_verification_event(
        cls,
        org_id: str,
        fayda_fin: str,
        account_number: str,
        auth_mode: str,          # 'biometric_face', 'biometric_fingerprint', 'otp_sms', 'demographic'
        auth_status: str,        # 'verified', 'failed_mismatch', 'locked', 'spoof_detected'
        kyc_tier: str = 'tier_3', # 'tier_1', 'tier_2', 'tier_3'
        ip_address: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Ingests a national digital identity verification event and calculates identity assurance level.
        """
        oid = str(org_id).strip()
        event_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        fin_hash = cls.hash_fayda_fin(fayda_fin)
        mode = auth_mode.lower().strip()
        status = auth_status.lower().strip()

        # Evaluate Identity Assurance Level (IAL) & Risk Adjustment
        risk_adjustment = 0
        assurance_level = 'medium'
        flagged_reason = None

        if status == 'spoof_detected':
            risk_adjustment = +90
            assurance_level = 'compromised_spoof'
            flagged_reason = 'Biometric presentation attack / deepfake spoof detected against Fayda identity rail.'
        elif status in ('failed_mismatch', 'locked'):
            risk_adjustment = +55
            assurance_level = 'identity_mismatch'
            flagged_reason = 'Fayda biometric mismatch or credential lock during transaction authorization.'
        elif status == 'verified':
            if mode in ('biometric_face', 'biometric_fingerprint'):
                risk_adjustment = -25  # High assurance reduces fraud risk
                assurance_level = 'high_biometric'
            elif mode == 'otp_sms':
                risk_adjustment = -10
                assurance_level = 'medium_otp'
            else:
                risk_adjustment = 0
                assurance_level = 'standard_demographic'
        else:
            risk_adjustment = +20
            assurance_level = 'unverified'

        event_record = {
            'id': event_id,
            'organization_id': oid,
            'fayda_fin_hash': fin_hash,
            'account_number': account_number.strip(),
            'auth_mode': mode,
            'auth_status': status,
            'kyc_tier': kyc_tier,
            'ip_address': ip_address,
            'assurance_level': assurance_level,
            'risk_adjustment': risk_adjustment,
            'flagged_reason': flagged_reason,
            'timestamp': now
        }

        _LOCAL_FAYDA_EVENTS[event_id] = event_record
        return event_record

    @classmethod
    def get_account_identity_assurance(cls, org_id: str, account_number: str) -> Dict[str, Any]:
        """
        Retrieves the latest identity assurance status for a given bank account.
        """
        oid = str(org_id).strip()
        acc = str(account_number).strip()

        matching = [
            e for e in _LOCAL_FAYDA_EVENTS.values()
            if str(e.get('organization_id')) == oid and str(e.get('account_number')) == acc
        ]

        if not matching:
            return {
                'account_number': acc,
                'assurance_level': 'no_fayda_record',
                'risk_adjustment': 0,
                'is_verified': False
            }

        # Return latest event
        latest = matching[-1]
        return {
            'account_number': acc,
            'fayda_fin_hash': latest['fayda_fin_hash'],
            'assurance_level': latest['assurance_level'],
            'auth_status': latest['auth_status'],
            'risk_adjustment': latest['risk_adjustment'],
            'flagged_reason': latest.get('flagged_reason'),
            'is_verified': latest['auth_status'] == 'verified'
        }
