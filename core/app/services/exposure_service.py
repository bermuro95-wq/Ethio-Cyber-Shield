"""
Exposure Management & Attack Surface Context Service for Ethio-Cyber-Shield (ECS) v3.0 (Phase 8.3).
Integrates attack surface management concepts (LocalShield architecture):
  1. External Asset Inventory (domains, FQDNs, public IPs, web endpoints).
  2. TLS/SSL Certificate Auditing (expiration within 14 days, untrusted CA, weak ciphers).
  3. Security Header Verification (HSTS, CSP, X-Frame-Options, X-Content-Type-Options).
  4. Exposed Port Anomaly Checks (public SSH, RDP, DB ports).
  5. Feeds asset exposure severity directly into the ECS Risk Model context.
Strictly partitioned by organization_id UUID NOT NULL.
"""
import uuid
import logging
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

# Risky ports exposed on public network
DANGEROUS_PUBLIC_PORTS = [22, 3389, 5432, 3306, 6379, 27017, 8080, 9200]

# In-memory store for asset inventory and exposure scans
_LOCAL_EXPOSURE_ASSETS: Dict[str, Dict[str, Any]] = {}  # asset_id -> asset_dict


def clear_exposure_caches() -> None:
    """Resets exposure cache for test isolation."""
    _LOCAL_EXPOSURE_ASSETS.clear()


class ExposureService:
    """Audits external assets, TLS posture, and feeds exposure risk into ECS."""

    @classmethod
    def register_asset(
        cls,
        org_id: str,
        asset_type: str,
        identifier: str,
        environment: str = 'production',
        tags: Optional[List[str]] = None
    ) -> Dict[str, Any]:
        """Registers a domain, FQDN, or IP into tenant attack surface inventory."""
        oid = str(org_id).strip()
        asset_id = str(uuid.uuid4())
        now = datetime.now(timezone.utc).isoformat()

        record = {
            'id': asset_id,
            'organization_id': oid,
            'asset_type': asset_type.lower().strip(),  # 'domain', 'ip', 'endpoint'
            'identifier': identifier.strip(),
            'environment': environment.lower(),
            'tags': tags or [],
            'created_at': now,
            'last_scanned_at': None,
            'exposure_grade': 'unscanned',
            'exposure_score': 0,
            'vulnerabilities': []
        }

        _LOCAL_EXPOSURE_ASSETS[asset_id] = record
        return record

    @classmethod
    def scan_asset_exposure(
        cls,
        org_id: str,
        asset_id: str,
        scan_data: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Evaluates TLS certificates, security headers, and exposed ports for an asset.
        """
        oid = str(org_id).strip()
        asset = _LOCAL_EXPOSURE_ASSETS.get(asset_id)
        if not asset or str(asset.get('organization_id')) != oid:
            raise ValueError(f"Asset {asset_id} not found for organization {oid}")

        now = datetime.now(timezone.utc)
        data = scan_data or {}
        vulnerabilities: List[Dict[str, Any]] = []
        score = 0

        # 1. TLS Certificate Checks
        tls_info = data.get('tls', {})
        if tls_info:
            is_valid = tls_info.get('is_valid', True)
            days_to_expire = tls_info.get('days_to_expire', 90)
            is_self_signed = tls_info.get('is_self_signed', False)
            tls_version = tls_info.get('tls_version', 'TLSv1.3')

            if not is_valid:
                vulnerabilities.append({
                    'code': 'EXP-TLS-001',
                    'title': 'Invalid / Untrusted SSL Certificate',
                    'severity': 'critical',
                    'impact': 'Customer transactions susceptible to Man-In-The-Middle attacks.'
                })
                score += 50
            elif days_to_expire <= 14:
                vulnerabilities.append({
                    'code': 'EXP-TLS-002',
                    'title': f'SSL Certificate Expiring in {days_to_expire} Days',
                    'severity': 'high',
                    'impact': 'Imminent service interruption and browser security warnings.'
                })
                score += 30

            if is_self_signed:
                vulnerabilities.append({
                    'code': 'EXP-TLS-003',
                    'title': 'Self-Signed Certificate in Production',
                    'severity': 'high',
                    'impact': 'Lack of public CA root validation.'
                })
                score += 25

            if tls_version in ('TLSv1.0', 'TLSv1.1'):
                vulnerabilities.append({
                    'code': 'EXP-TLS-004',
                    'title': f'Deprecated Protocol Version: {tls_version}',
                    'severity': 'medium',
                    'impact': 'Susceptible to POODLE / BEAST cryptographic attacks.'
                })
                score += 20

        # 2. HTTP Security Headers Checks
        headers = data.get('headers', {})
        if headers:
            required_headers = [
                ('Strict-Transport-Security', 'HSTS Missing', 'high', 20),
                ('Content-Security-Policy', 'CSP Missing', 'medium', 15),
                ('X-Frame-Options', 'Clickjacking Protection Missing', 'medium', 15),
                ('X-Content-Type-Options', 'MIME Sniffing Protection Missing', 'low', 10)
            ]
            for hdr_name, title, sev, penalty in required_headers:
                if hdr_name.lower() not in [k.lower() for k in headers.keys()]:
                    vulnerabilities.append({
                        'code': f"EXP-HDR-{hdr_name[:3].upper()}",
                        'title': title,
                        'severity': sev,
                        'impact': f"Missing {hdr_name} header reduces client-side defense in depth."
                    })
                    score += penalty

        # 3. Exposed Open Ports Checks
        open_ports = data.get('open_ports', [])
        for p in open_ports:
            if int(p) in DANGEROUS_PUBLIC_PORTS:
                vulnerabilities.append({
                    'code': f'EXP-PORT-{p}',
                    'title': f'Insecure Public Port {p} Exposed',
                    'severity': 'critical' if p in (22, 3389, 5432, 6379) else 'high',
                    'impact': f"Direct public access to service port {p} exposes backend to brute-force."
                })
                score += 40

        # Determine overall grade
        if score >= 70:
            grade = 'critical'
        elif score >= 40:
            grade = 'high'
        elif score >= 20:
            grade = 'medium'
        elif score > 0:
            grade = 'low'
        else:
            grade = 'secure'

        # Update asset record
        asset['last_scanned_at'] = now.isoformat()
        asset['exposure_grade'] = grade
        asset['exposure_score'] = min(100, score)
        asset['vulnerabilities'] = vulnerabilities

        return asset

    @classmethod
    def list_assets(cls, org_id: str) -> List[Dict[str, Any]]:
        """Lists all registered attack surface assets for tenant."""
        oid = str(org_id).strip()
        return [
            dict(a) for a in _LOCAL_EXPOSURE_ASSETS.values()
            if str(a.get('organization_id')) == oid
        ]

    @classmethod
    def get_asset_exposure_context(cls, org_id: str, identifier: str) -> Optional[Dict[str, Any]]:
        """
        Feeds external attack surface risk directly into ECS detection/risk calculation.
        """
        oid = str(org_id).strip()
        for a in _LOCAL_EXPOSURE_ASSETS.values():
            if str(a.get('organization_id')) == oid and str(a.get('identifier')).lower() == identifier.lower().strip():
                return {
                    'asset_id': a['id'],
                    'identifier': a['identifier'],
                    'exposure_score': a.get('exposure_score', 0),
                    'exposure_grade': a.get('exposure_grade', 'secure'),
                    'vulnerability_count': len(a.get('vulnerabilities', []))
                }
        return None
