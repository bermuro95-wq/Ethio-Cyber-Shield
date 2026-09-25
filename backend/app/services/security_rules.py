"""
Simple rule-based security analysis for Ethio-Cyber Shield.
NO AI / ML — pure deterministic rules.
"""
from datetime import datetime, timedelta, timezone
from app.services.db import get_service_supabase
from app.services.audit_service import log_action
import logging

logger = logging.getLogger(__name__)

# Severity weights for risk scoring
SEVERITY_WEIGHTS = {
    'low': 10,
    'medium': 25,
    'high': 50,
    'critical': 80
}

INDICATOR_WEIGHTS = {
    'benign': 0,
    'unknown': 5,
    'suspicious': 20,
    'malicious': 40
}

def calculate_incident_risk(incident_id: str) -> dict:
    """
    Calculate risk score and level for an incident based on simple rules.
    Returns: {risk_score, risk_level, reasons}
    """
    sb = get_service_supabase()
    reasons = []
    score = 0

    # Fetch incident
    inc_res = sb.table('incidents').select('*').eq('id', incident_id).execute()
    if not inc_res.data:
        return {'risk_score': 0, 'risk_level': 'low', 'reasons': ['Incident not found']}
    
    incident = inc_res.data[0]
    
    # Rule 1: Base severity
    sev = incident.get('severity', 'low')
    score += SEVERITY_WEIGHTS.get(sev, 10)
    reasons.append(f"Base severity '{sev}' contributes {SEVERITY_WEIGHTS.get(sev, 10)} points")

    # Rule 2: Linked indicators
    link_res = sb.table('incident_indicators').select('indicator_id').eq('incident_id', incident_id).execute()
    indicator_ids = [r['indicator_id'] for r in (link_res.data or [])]
    
    if indicator_ids:
        ind_res = sb.table('indicators').select('*').in_('id', indicator_ids).execute()
        indicators = ind_res.data or []
        
        for ind in indicators:
            status = ind.get('status', 'unknown')
            weight = INDICATOR_WEIGHTS.get(status, 5)
            score += weight
            if status == 'malicious':
                reasons.append(f"Malicious indicator ({ind['indicator_type']}: {ind['value']}) adds {weight} points")
            elif status == 'suspicious':
                reasons.append(f"Suspicious indicator ({ind['indicator_type']}: {ind['value']}) adds {weight} points")
            else:
                reasons.append(f"Indicator ({ind['indicator_type']}: {ind['value']}) status '{status}' adds {weight} points")

        # Rule 3: Multiple indicators increase risk
        if len(indicators) >= 3:
            score += 15
            reasons.append(f"Multiple indicators linked ({len(indicators)}) adds 15 points")

    # Rule 4: Incident type specific
    itype = incident.get('incident_type', '')
    if itype in ('account_takeover', 'phishing'):
        score += 15
        reasons.append(f"High-risk incident type '{itype}' adds 15 points")
    elif itype == 'fraud':
        score += 20
        reasons.append("Fraud type incident adds 20 points")

    # Rule 5: Related transactions (same account or device correlation)
    related_tx = find_related_transactions(incident)
    if related_tx:
        suspicious_count = sum(1 for t in related_tx if t.get('is_suspicious'))
        if suspicious_count > 0:
            score += 25
            reasons.append(f"{suspicious_count} related suspicious transaction(s) add 25 points")
        elif len(related_tx) > 0:
            score += 10
            reasons.append(f"{len(related_tx)} related transaction(s) add 10 points")

    # Rule 6: Status still open/investigating
    if incident.get('status') in ('open', 'investigating'):
        score += 5
        reasons.append("Incident still open/investigating adds 5 points")

    # Cap score
    score = min(score, 100)

    # Map to level
    if score >= 80:
        level = 'critical'
    elif score >= 55:
        level = 'high'
    elif score >= 30:
        level = 'medium'
    else:
        level = 'low'

    # Persist
    sb.table('incidents').update({
        'risk_score': score,
        'risk_level': level,
        'risk_reasons': reasons
    }).eq('id', incident_id).execute()

    return {
        'risk_score': score,
        'risk_level': level,
        'reasons': reasons
    }


def find_related_transactions(incident: dict) -> list:
    """Simple correlation: look for transactions close in time or sharing attributes."""
    sb = get_service_supabase()
    # We look at description or related fields; for MVP we search by time window
    # and any explicit related_incident_id
    try:
        # Direct links
        direct = sb.table('transactions').select('*').eq('related_incident_id', incident['id']).execute()
        results = direct.data or []

        # Time-window correlation (±24h of incident_date) for high-severity
        if incident.get('severity') in ('high', 'critical'):
            inc_time = incident.get('incident_date')
            if inc_time:
                # Parse and expand window
                from dateutil import parser
                t = parser.isoparse(inc_time)
                start = (t - timedelta(hours=24)).isoformat()
                end = (t + timedelta(hours=24)).isoformat()
                # Only if we have device or IP in description (simple keyword match for MVP)
                # For real systems we'd extract entities; here we keep simple
                near = sb.table('transactions').select('*').gte('transaction_time', start).lte('transaction_time', end).limit(20).execute()
                for tx in (near.data or []):
                    if tx['id'] not in [r['id'] for r in results]:
                        results.append(tx)
        return results
    except Exception as e:
        logger.error(f"Related tx lookup error: {e}")
        return []



def get_fraud_thresholds() -> dict:
    """Load configurable fraud thresholds from system_settings (with defaults)."""
    defaults = {
        'high_amount': 500000,
        'critical_amount': 1500000,
        'night_amount': 200000,
        'burst_count': 4,
        'burst_window_minutes': 30,
        'velocity_amount': 800000,
        'new_device_amount': 200000,
        'multi_account_device': 3,
        'shared_ip_accounts': 4,
        'large_withdrawal': 300000,
        'rapid_transfer_amount': 150000,
        'rapid_window_minutes': 10,
    }
    try:
        sb = get_service_supabase()
        res = sb.table('system_settings').select('value').eq('key', 'fraud_rules').limit(1).execute()
        if res.data and res.data[0].get('value'):
            val = res.data[0]['value']
            if isinstance(val, dict):
                defaults.update({k: val[k] for k in defaults if k in val})
    except Exception as e:
        logger.warning(f"Could not load fraud thresholds: {e}")
    return defaults


def check_watchlist_matches(tx: dict) -> list:
    """Return list of watchlist hits for a transaction."""
    hits = []
    try:
        sb = get_service_supabase()
        res = sb.table('watchlists').select('*').eq('is_active', True).limit(500).execute()
        rows = res.data or []
        account = (tx.get('account_number') or '').strip()
        device = (tx.get('device_id') or '').strip()
        ip = (tx.get('ip_address') or '').strip()
        for w in rows:
            et = w.get('entity_type')
            val = (w.get('value') or '').strip()
            if not val:
                continue
            matched = False
            if et == 'account' and account and val.lower() == account.lower():
                matched = True
            elif et == 'device' and device and val.lower() == device.lower():
                matched = True
            elif et == 'ip' and ip and val == ip:
                matched = True
            if matched:
                hits.append(w)
    except Exception as e:
        logger.warning(f"Watchlist check failed: {e}")
    return hits


def analyze_transaction(transaction_id: str) -> dict:
    """
    CBE-style rule-based fraud detection for a transaction.
    Runs immediately when a transaction is created (real-time detection).
    Returns: {is_suspicious, reasons, risk_score, risk_level, severity}
    NO AI / ML — pure deterministic rules for Ethiopian banking context.
    """
    sb = get_service_supabase()
    reasons = []
    score = 0

    res = sb.table('transactions').select('*').eq('id', transaction_id).execute()
    if not res.data:
        return {
            'is_suspicious': False,
            'reasons': ['Transaction not found'],
            'risk_score': 0,
            'risk_level': 'low',
            'severity': 'low'
        }

    tx = res.data[0]
    amount = float(tx.get('amount', 0) or 0)
    account = tx.get('account_number')
    device = tx.get('device_id')
    ip_address = tx.get('ip_address')
    tx_type = tx.get('transaction_type', 'other')
    tx_time = tx.get('transaction_time')
    location = (tx.get('location') or '').lower()

    thr = get_fraud_thresholds()
    HIGH_AMOUNT = float(thr.get('high_amount', 500000))
    CRITICAL_AMOUNT = float(thr.get('critical_amount', 1500000))
    NIGHT_AMOUNT = float(thr.get('night_amount', 200000))
    BURST_COUNT = int(thr.get('burst_count', 4))
    BURST_WINDOW = int(thr.get('burst_window_minutes', 30))
    VELOCITY_AMOUNT = float(thr.get('velocity_amount', 800000))
    NEW_DEVICE_AMOUNT = float(thr.get('new_device_amount', 200000))
    MULTI_ACCT = int(thr.get('multi_account_device', 3))
    SHARED_IP = int(thr.get('shared_ip_accounts', 4))
    LARGE_WD = float(thr.get('large_withdrawal', 300000))
    RAPID_AMT = float(thr.get('rapid_transfer_amount', 150000))
    RAPID_WIN = int(thr.get('rapid_window_minutes', 10))

    from dateutil import parser
    try:
        t = parser.isoparse(tx_time) if tx_time else datetime.now(timezone.utc)
        if t.tzinfo is None:
            t = t.replace(tzinfo=timezone.utc)
    except Exception:
        t = datetime.now(timezone.utc)

    # Convert to Africa/Addis_Ababa (UTC+3) for night-window rules
    addis_hour = (t.hour + 3) % 24

    # ---------- Rule 0: Watchlist match (highest priority signal) ----------
    for hit in check_watchlist_matches(tx):
        score += 50
        reasons.append(
            f"Watchlist hit: {hit.get('entity_type')} '{hit.get('value')}'"
            + (f" ({hit.get('label')})" if hit.get('label') else "")
        )

    # ---------- Rule 1: High amount (Ethiopian retail banking context) ----------
    if amount >= CRITICAL_AMOUNT:
        score += 45
        reasons.append(f"Critical amount: {amount:,.0f} ETB exceeds {CRITICAL_AMOUNT:,.0f} ETB")
    elif amount >= HIGH_AMOUNT:
        score += 30
        reasons.append(f"High amount: {amount:,.0f} ETB exceeds {HIGH_AMOUNT:,.0f} ETB")

    # ---------- Rule 2: Night-time high-value transfer (00:00–05:00 Addis) ----------
    if addis_hour < 5 and amount >= NIGHT_AMOUNT and tx_type in ('transfer', 'withdrawal', 'payment'):
        score += 25
        reasons.append(
            f"Night-time high-value {tx_type}: {amount:,.0f} ETB at {addis_hour:02d}:xx Addis time"
        )

    # ---------- Rule 3: Burst / velocity on same account (30 min window) ----------
    if account:
        window_start = (t - timedelta(minutes=BURST_WINDOW)).isoformat()
        window_end = (t + timedelta(minutes=1)).isoformat()
        nearby = sb.table('transactions').select('id, amount, transaction_time')\
            .eq('account_number', account)\
            .gte('transaction_time', window_start)\
            .lte('transaction_time', window_end).execute()
        nearby_rows = nearby.data or []
        count = len(nearby_rows)
        total_nearby = sum(float(r.get('amount') or 0) for r in nearby_rows)

        if count >= BURST_COUNT:
            score += 35
            reasons.append(f"Burst activity: {count} transactions on account within {BURST_WINDOW} minutes")
        elif count >= max(2, BURST_COUNT - 1) and amount > 100_000:
            score += 20
            reasons.append(f"Multiple high-value transactions ({count}) within {BURST_WINDOW} minutes")

        if total_nearby >= VELOCITY_AMOUNT:
            score += 25
            reasons.append(f"High velocity: {total_nearby:,.0f} ETB moved on account in {BURST_WINDOW} minutes")

    # ---------- Rule 4: Same device used across many accounts (ATO signal) ----------
    if device:
        day_start = (t - timedelta(hours=48)).isoformat()
        other = sb.table('transactions').select('account_number')\
            .eq('device_id', device)\
            .gte('transaction_time', day_start).execute()
        accounts = set(r['account_number'] for r in (other.data or []) if r.get('account_number'))
        if len(accounts) >= MULTI_ACCT + 1:
            score += 40
            reasons.append(f"Device {device} used across {len(accounts)} different accounts in 48h (ATO risk)")
        elif len(accounts) >= MULTI_ACCT:
            score += 25
            reasons.append(f"Device {device} used across {len(accounts)} different accounts in 48h")

    # ---------- Rule 5: First-time device + high amount ----------
    if device and account and amount > NEW_DEVICE_AMOUNT:
        hist = sb.table('transactions').select('id')\
            .eq('account_number', account).eq('device_id', device)\
            .neq('id', transaction_id).limit(1).execute()
        if not hist.data:
            score += 30
            reasons.append(f"First-time device {device} used for high-value transaction ({amount:,.0f} ETB)")

    # ---------- Rule 6: Same IP across multiple accounts (shared / compromised) ----------
    if ip_address:
        day_start = (t - timedelta(hours=24)).isoformat()
        ip_rows = sb.table('transactions').select('account_number')\
            .eq('ip_address', ip_address)\
            .gte('transaction_time', day_start).execute()
        ip_accounts = set(r['account_number'] for r in (ip_rows.data or []) if r.get('account_number'))
        if len(ip_accounts) >= SHARED_IP:
            score += 30
            reasons.append(f"IP {ip_address} used by {len(ip_accounts)} accounts in 24h")

    # ---------- Rule 7: Large withdrawal (cash-out pattern) ----------
    if tx_type == 'withdrawal' and amount >= LARGE_WD:
        score += 20
        reasons.append(f"Large withdrawal: {amount:,.0f} ETB")

    # ---------- Rule 8: Rapid successive large transfers (possible mule / rapid drain) ----------
    if account and amount >= RAPID_AMT:
        rapid_start = (t - timedelta(minutes=RAPID_WIN)).isoformat()
        rapid = sb.table('transactions').select('id, amount')\
            .eq('account_number', account)\
            .gte('transaction_time', rapid_start)\
            .lte('transaction_time', t.isoformat())\
            .neq('id', transaction_id).execute()
        rapid_count = len(rapid.data or [])
        if rapid_count >= 2:
            score += 25
            reasons.append(f"Rapid successive large transfers: {rapid_count + 1} in {RAPID_WIN} minutes")

    # Risk level from score
    if score >= 70:
        risk_level = 'critical'
        severity = 'critical'
    elif score >= 45:
        risk_level = 'high'
        severity = 'high'
    elif score >= 25:
        risk_level = 'medium'
        severity = 'medium'
    else:
        risk_level = 'low'
        severity = 'low'

    is_suspicious = score >= 25

    # Persist
    sb.table('transactions').update({
        'is_suspicious': is_suspicious,
        'suspicion_reasons': reasons,
        'status': 'flagged' if is_suspicious else tx.get('status', 'completed')
    }).eq('id', transaction_id).execute()

    return {
        'is_suspicious': is_suspicious,
        'reasons': reasons,
        'risk_score': score,
        'risk_level': risk_level,
        'severity': severity
    }


def correlate_cyber_fraud(incident_id: str = None, transaction_id: str = None) -> list:
    """
    Find correlations between incidents and transactions using simple matching.
    Returns list of correlation findings.
    """
    sb = get_service_supabase()
    findings = []

    if incident_id:
        # Get indicators linked to incident
        links = sb.table('incident_indicators').select('indicator_id').eq('incident_id', incident_id).execute()
        ind_ids = [l['indicator_id'] for l in (links.data or [])]
        if ind_ids:
            inds = sb.table('indicators').select('*').in_('id', ind_ids).execute()
            for ind in (inds.data or []):
                val = ind.get('value', '')
                itype = ind.get('indicator_type')
                # Match against transaction IP or device if applicable
                if itype == 'ip':
                    matches = sb.table('transactions').select('*').eq('ip_address', val).limit(10).execute()
                    for m in (matches.data or []):
                        findings.append({
                            'type': 'ip_match',
                            'incident_id': incident_id,
                            'transaction_id': m['id'],
                            'indicator': val,
                            'reason': f"Transaction IP matches malicious/suspicious indicator {val}"
                        })
                # For domain/url/email we can note potential phishing link usage but keep simple

    if transaction_id:
        tx_res = sb.table('transactions').select('*').eq('id', transaction_id).execute()
        if tx_res.data:
            tx = tx_res.data[0]
            # Look for incidents of type phishing / account_takeover close in time
            if tx.get('transaction_time'):
                from dateutil import parser
                t = parser.isoparse(tx['transaction_time'])
                start = (t - timedelta(days=3)).isoformat()
                end = (t + timedelta(hours=12)).isoformat()
                incs = sb.table('incidents').select('*')\
                    .in_('incident_type', ['phishing', 'account_takeover', 'suspicious_login'])\
                    .gte('incident_date', start).lte('incident_date', end).limit(10).execute()
                for inc in (incs.data or []):
                    findings.append({
                        'type': 'time_proximity',
                        'incident_id': inc['id'],
                        'transaction_id': transaction_id,
                        'reason': f"Incident '{inc['title']}' ({inc['incident_type']}) occurred near suspicious transaction time"
                    })

    return findings


def create_alert_from_event(alert_type: str, title: str, description: str, severity: str,
                            related_incident_id: str = None, related_transaction_id: str = None,
                            related_indicator_id: str = None, user_id: str = None) -> dict | None:
    """Create an alert record and audit it."""
    sb = get_service_supabase()
    data = {
        'title': title,
        'description': description,
        'alert_type': alert_type,
        'severity': severity,
        'status': 'open',
        'related_incident_id': related_incident_id,
        'related_transaction_id': related_transaction_id,
        'related_indicator_id': related_indicator_id
    }
    try:
        res = sb.table('alerts').insert(data).execute()
        if res.data:
            alert = res.data[0]
            log_action(user_id, 'alert_created', 'alert', alert['id'], {
                'title': title, 'severity': severity, 'type': alert_type
            })
            return alert
    except Exception as e:
        logger.error(f"Create alert error: {e}")
    return None


def run_full_analysis_on_incident(incident_id: str, user_id: str = None) -> dict:
    """Orchestrate risk calc + correlation + auto-alerts."""
    risk = calculate_incident_risk(incident_id)
    
    # Auto-alert on high/critical
    if risk['risk_level'] in ('high', 'critical'):
        create_alert_from_event(
            alert_type='high_risk',
            title=f"High Risk Incident Detected",
            description=f"Incident {incident_id} scored {risk['risk_score']} ({risk['risk_level']}). Reasons: {'; '.join(risk['reasons'][:3])}",
            severity=risk['risk_level'],
            related_incident_id=incident_id,
            user_id=user_id
        )

    # Correlation
    correlations = correlate_cyber_fraud(incident_id=incident_id)
    for corr in correlations:
        if corr.get('type') == 'ip_match':
            create_alert_from_event(
                alert_type='correlation',
                title="Cyber-Fraud Correlation Found",
                description=corr['reason'],
                severity='high',
                related_incident_id=incident_id,
                related_transaction_id=corr.get('transaction_id'),
                user_id=user_id
            )

    log_action(user_id, 'analysis_run', 'incident', incident_id, risk)
    return {
        'risk': risk,
        'correlations': correlations
    }
