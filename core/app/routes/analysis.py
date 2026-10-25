from flask import Blueprint, request, jsonify, g
import logging
from typing import Dict, Any, List
from collections import defaultdict
from datetime import datetime, timezone

from app.services.auth_service import role_required
from app.services.tenant_mgmt_service import is_superadmin
from app.services.tenant_service import DEFAULT_ORGANIZATION_ID
from app.services.db import get_service_supabase
from app.services.enrichment_service import (
    get_alert_dossier, synthesize_attack_dossier, parse_client_device_details, parse_network_details
)
from app.services.security_rules import (
    run_full_analysis_on_incident, analyze_transaction, correlate_cyber_fraud
)

logger = logging.getLogger(__name__)

analysis_bp = Blueprint('analysis', __name__)


@analysis_bp.route('/incident/<incident_id>', methods=['POST'])
@role_required('admin', 'analyst')
def analyze_incident(incident_id):
    result = run_full_analysis_on_incident(incident_id, g.user['id'])
    return jsonify(result)


@analysis_bp.route('/transaction/<tx_id>', methods=['POST'])
@role_required('admin', 'analyst')
def analyze_tx(tx_id):
    result = analyze_transaction(tx_id)
    return jsonify(result)


@analysis_bp.route('/correlate', methods=['POST'])
@role_required('admin', 'analyst')
def correlate():
    data = request.get_json() or {}
    findings = correlate_cyber_fraud(
        incident_id=data.get('incident_id'),
        transaction_id=data.get('transaction_id')
    )
    return jsonify({'findings': findings})


@analysis_bp.route('/correlations', methods=['GET'])
@role_required('admin', 'analyst', 'viewer', 'responder', 'auditor', 'operator', 'superadmin')
def get_attack_correlations():
    """
    Computes multi-dimensional entity correlation graph:
    1. By Attacker IP: Geolocation, ASN, ISP, Network Rail (Wi-Fi vs Cellular), OS, Client Tools, Timeline.
    2. By Device Hardware MAC / Fingerprint: Cross-Account Pivots, Credential Stuffing, OS, Tooling.
    3. By Position / Geographic Hotspot: Ethiopian Cities (Addis Ababa, Hawassa, Adama, Bahir Dar, etc.).
    Supports SaaS multi-tenant isolation and Superadmin cross-tenant view.
    """
    user = getattr(g, 'user', None) or {}
    is_sup = is_superadmin(user)

    target_tenant = request.args.get('tenant_id') or request.args.get('organization_id')
    if is_sup and target_tenant and target_tenant.lower() != 'all':
        filter_org = target_tenant
    elif not is_sup:
        filter_org = user.get('organization_id') or DEFAULT_ORGANIZATION_ID
    else:
        filter_org = None

    sb = get_service_supabase()

    # 1. Fetch alerts
    alerts: List[Dict[str, Any]] = []
    try:
        res = sb.table('alerts').select('*').order('created_at', desc=True).limit(300).execute()
        alerts = res.data or []
    except Exception as e:
        logger.warning(f"Analysis alerts query error: {e}")

    # Strict isolation filter if filtering by tenant
    if filter_org:
        from app.routes.alerts import _get_alert_org
        alerts = [
            a for a in alerts
            if not _get_alert_org(a.get('id'), a) or _get_alert_org(a.get('id'), a) == str(filter_org)
        ]

    # Fallback to local store or recent events if empty
    if not alerts:
        try:
            from app.services.event_service import get_recent_in_memory_events
            in_mem = get_recent_in_memory_events()
            for ev in in_mem:
                if not filter_org or str(ev.get('organization_id')) == str(filter_org):
                    # Synthesize synthetic candidate for analysis
                    alerts.append({
                        'id': f"alt-{ev.get('event_id', 'sim')}",
                        'title': f"Detected Suspicious Telemetry: {ev.get('event_type')}",
                        'severity': 'high' if 'FAIL' in str(ev.get('event_type')) else 'medium',
                        'risk_score': 65,
                        'primary_rule_id': 'AUTH-001',
                        'source_ip': ev.get('source_ip', '127.0.0.1'),
                        'device_id': ev.get('device_id') or ev.get('device_id_pub'),
                        'account': ev.get('account_id') or ev.get('user_id'),
                        'created_at': ev.get('occurred_at') or datetime.now(timezone.utc).isoformat(),
                        'organization_id': ev.get('organization_id') or DEFAULT_ORGANIZATION_ID,
                        'evidence': ev.get('attributes') or {}
                    })
        except Exception:
            pass

    # 2. Fetch known blocked IPs
    blocked_ips = set()
    try:
        blk_res = sb.table('ip_blocklist').select('ip').eq('status', 'ACTIVE').execute()
        for b in (blk_res.data or []):
            if b.get('ip'):
                blocked_ips.add(b['ip'].strip())
    except Exception:
        pass

    # 3. Correlation Aggregators
    ip_agg = {}
    device_agg = {}
    location_agg = {}

    total_wifi_count = 0
    total_cellular_count = 0
    total_ethernet_count = 0

    for a in alerts:
        aid = a.get('id')
        d = get_alert_dossier(aid) or synthesize_attack_dossier(a)
        geo = d.get('geo', {})
        dev = d.get('device', {})
        net = d.get('network', {})
        tgt = d.get('target', {})
        atk = d.get('attack', {})

        src_ip = geo.get('ip') or a.get('source_ip') or '127.0.0.1'
        dev_id = dev.get('device_id') or a.get('device_id') or 'DEV-UNKNOWN'
        dev_mac = dev.get('device_mac') or '00:00:00:00:00:00'
        city = geo.get('city') or 'Addis Ababa'
        region = geo.get('region') or 'Central Addis Ababa'
        country_name = geo.get('country_name') or 'Ethiopia'
        flag = geo.get('flag') or '🇪🇹'
        loc_key = f"{city}, {country_name}"

        is_wifi = bool(net.get('is_wifi'))
        is_cellular = bool(net.get('is_cellular'))
        is_ethernet = bool(net.get('is_ethernet'))

        if is_wifi:
            total_wifi_count += 1
        elif is_cellular:
            total_cellular_count += 1
        elif is_ethernet:
            total_ethernet_count += 1

        rule_id = atk.get('rule_id') or a.get('primary_rule_id') or 'AUTH-001'
        rule_name = atk.get('rule_name') or 'Deterministic Security Rule'
        acc = tgt.get('account') or a.get('account') or 'unknown-account'
        score = int(d.get('risk_score') or a.get('risk_score') or 0)
        sev = (a.get('severity') or d.get('severity') or 'medium').lower()
        ts = a.get('created_at') or d.get('created_at') or datetime.now(timezone.utc).isoformat()

        # -------------------------------------------------------------
        # Aggregate 1: IP Entity Correlations
        # -------------------------------------------------------------
        if src_ip not in ip_agg:
            ip_agg[src_ip] = {
                'ip': src_ip,
                'city': city,
                'region': region,
                'country': geo.get('country', 'ET'),
                'country_name': country_name,
                'flag': flag,
                'asn': geo.get('asn', 'AS24757'),
                'isp': geo.get('isp') or geo.get('as_org', 'Ethio Telecom'),
                'latitude': geo.get('latitude', 9.0320),
                'longitude': geo.get('longitude', 38.7468),
                'connection_type': net.get('connection_type', 'Wi-Fi (Wireless LAN)'),
                'network_label': net.get('network_label', 'Wi-Fi (802.11ax)'),
                'is_wifi': is_wifi,
                'is_cellular': is_cellular,
                'operating_systems': set(),
                'client_tools': set(),
                'targeted_accounts': set(),
                'associated_devices': set(),
                'associated_macs': set(),
                'rules_fired': {},
                'attack_count': 0,
                'max_risk_score': 0,
                'severities': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0},
                'first_seen': ts,
                'last_seen': ts,
                'sample_alert_id': aid,
                'is_blocked': src_ip in blocked_ips,
            }

        rec_ip = ip_agg[src_ip]
        rec_ip['attack_count'] += 1
        rec_ip['max_risk_score'] = max(rec_ip['max_risk_score'], score)
        if sev in rec_ip['severities']:
            rec_ip['severities'][sev] += 1
        rec_ip['operating_systems'].add(dev.get('os', 'Linux x86_64'))
        rec_ip['client_tools'].add(dev.get('client_software', 'Standard Client'))
        if acc and acc != 'unknown-account':
            rec_ip['targeted_accounts'].add(acc)
        rec_ip['associated_devices'].add(dev_id)
        rec_ip['associated_macs'].add(dev_mac)
        rec_ip['rules_fired'][rule_id] = rec_ip['rules_fired'].get(rule_id, 0) + 1
        if ts < rec_ip['first_seen']: rec_ip['first_seen'] = ts
        if ts > rec_ip['last_seen']: rec_ip['last_seen'] = ts

        # -------------------------------------------------------------
        # Aggregate 2: Device Hardware MAC Correlations (Pivot Hunter)
        # -------------------------------------------------------------
        device_key = dev_mac if dev_mac and dev_mac != '00:00:00:00:00:00' else dev_id
        if device_key not in device_agg:
            device_agg[device_key] = {
                'device_key': device_key,
                'device_mac': dev_mac,
                'device_id': dev_id,
                'os': dev.get('os', 'Linux x86_64'),
                'client_software': dev.get('client_software', 'Standard Client'),
                'connection_type': net.get('connection_type', 'Wi-Fi (Wireless LAN)'),
                'network_label': net.get('network_label', 'Wi-Fi (802.11ax)'),
                'is_wifi': is_wifi,
                'is_cellular': is_cellular,
                'ips_used': set(),
                'targeted_accounts': set(),
                'rules_fired': {},
                'attack_count': 0,
                'max_risk_score': 0,
                'first_seen': ts,
                'last_seen': ts,
                'sample_alert_id': aid,
            }

        rec_dev = device_agg[device_key]
        rec_dev['attack_count'] += 1
        rec_dev['max_risk_score'] = max(rec_dev['max_risk_score'], score)
        rec_dev['ips_used'].add(src_ip)
        if acc and acc != 'unknown-account':
            rec_dev['targeted_accounts'].add(acc)
        rec_dev['rules_fired'][rule_id] = rec_dev['rules_fired'].get(rule_id, 0) + 1
        if ts < rec_dev['first_seen']: rec_dev['first_seen'] = ts
        if ts > rec_dev['last_seen']: rec_dev['last_seen'] = ts

        # -------------------------------------------------------------
        # Aggregate 3: Position / Geographic Hotspots
        # -------------------------------------------------------------
        if loc_key not in location_agg:
            location_agg[loc_key] = {
                'location_key': loc_key,
                'city': city,
                'region': region,
                'country_name': country_name,
                'flag': flag,
                'latitude': geo.get('latitude', 9.0320),
                'longitude': geo.get('longitude', 38.7468),
                'attack_count': 0,
                'unique_ips': set(),
                'unique_devices': set(),
                'targeted_accounts': set(),
                'wifi_count': 0,
                'cellular_count': 0,
                'ethernet_count': 0,
                'rules_fired': {},
                'top_ips': [],
            }

        rec_loc = location_agg[loc_key]
        rec_loc['attack_count'] += 1
        rec_loc['unique_ips'].add(src_ip)
        rec_loc['unique_devices'].add(dev_id)
        if acc and acc != 'unknown-account':
            rec_loc['targeted_accounts'].add(acc)
        if is_wifi:
            rec_loc['wifi_count'] += 1
        elif is_cellular:
            rec_loc['cellular_count'] += 1
        else:
            rec_loc['ethernet_count'] += 1
        rec_loc['rules_fired'][rule_id] = rec_loc['rules_fired'].get(rule_id, 0) + 1

    # Format IP Correlations list
    ip_list = []
    for ip, data in ip_agg.items():
        primary_os = next(iter(data['operating_systems'])) if data['operating_systems'] else 'Linux x86_64'
        primary_tool = next(iter(data['client_tools'])) if data['client_tools'] else 'Standard Web Client'
        ip_list.append({
            'ip': data['ip'],
            'city': data['city'],
            'region': data['region'],
            'country': data['country'],
            'country_name': data['country_name'],
            'flag': data['flag'],
            'asn': data['asn'],
            'isp': data['isp'],
            'latitude': data['latitude'],
            'longitude': data['longitude'],
            'connection_type': data['connection_type'],
            'network_label': data['network_label'],
            'is_wifi': data['is_wifi'],
            'is_cellular': data['is_cellular'],
            'os': primary_os,
            'operating_systems': sorted(list(data['operating_systems'])),
            'client_software': primary_tool,
            'client_tools': sorted(list(data['client_tools'])),
            'targeted_accounts': sorted(list(data['targeted_accounts'])),
            'accounts_count': len(data['targeted_accounts']),
            'associated_devices': sorted(list(data['associated_devices'])),
            'associated_macs': sorted(list(data['associated_macs'])),
            'rules_fired': [{'rule_id': r, 'count': c} for r, c in data['rules_fired'].items()],
            'attack_count': data['attack_count'],
            'max_risk_score': data['max_risk_score'],
            'severities': data['severities'],
            'first_seen': data['first_seen'],
            'last_seen': data['last_seen'],
            'sample_alert_id': data['sample_alert_id'],
            'is_blocked': data['is_blocked'],
        })
    ip_list.sort(key=lambda x: (x['attack_count'], x['max_risk_score']), reverse=True)

    # Format Device Correlations list
    device_list = []
    pivot_devices_count = 0
    for dev_k, data in device_agg.items():
        acc_list = sorted(list(data['targeted_accounts']))
        acc_count = len(acc_list)
        is_pivot = acc_count > 1
        if is_pivot:
            pivot_devices_count += 1

        rep_status = 'high_risk' if data['max_risk_score'] >= 70 else ('suspicious' if data['max_risk_score'] >= 35 else 'trusted')

        device_list.append({
            'device_key': data['device_key'],
            'device_mac': data['device_mac'],
            'device_id': data['device_id'],
            'os': data['os'],
            'client_software': data['client_software'],
            'connection_type': data['connection_type'],
            'network_label': data['network_label'],
            'is_wifi': data['is_wifi'],
            'is_cellular': data['is_cellular'],
            'ips_used': sorted(list(data['ips_used'])),
            'ips_count': len(data['ips_used']),
            'targeted_accounts': acc_list,
            'accounts_count': acc_count,
            'is_cross_account_pivot': is_pivot,
            'rules_fired': [{'rule_id': r, 'count': c} for r, c in data['rules_fired'].items()],
            'attack_count': data['attack_count'],
            'max_risk_score': data['max_risk_score'],
            'reputation_status': rep_status,
            'first_seen': data['first_seen'],
            'last_seen': data['last_seen'],
            'sample_alert_id': data['sample_alert_id'],
        })
    device_list.sort(key=lambda x: (x['accounts_count'], x['attack_count']), reverse=True)

    # Format Location Correlations list
    location_list = []
    for loc_k, data in location_agg.items():
        dominant = 'Wi-Fi (Wireless LAN)' if data['wifi_count'] >= data['cellular_count'] else 'Cellular Mobile (4G/5G LTE)'
        location_list.append({
            'location_key': data['location_key'],
            'city': data['city'],
            'region': data['region'],
            'country_name': data['country_name'],
            'flag': data['flag'],
            'latitude': data['latitude'],
            'longitude': data['longitude'],
            'attack_count': data['attack_count'],
            'unique_ips_count': len(data['unique_ips']),
            'unique_devices_count': len(data['unique_devices']),
            'targeted_accounts_count': len(data['targeted_accounts']),
            'wifi_count': data['wifi_count'],
            'cellular_count': data['cellular_count'],
            'ethernet_count': data['ethernet_count'],
            'dominant_rail': dominant,
            'rules_fired': [{'rule_id': r, 'count': c} for r, c in data['rules_fired'].items()],
            'top_ips': sorted(list(data['unique_ips']))[:5],
        })
    location_list.sort(key=lambda x: x['attack_count'], reverse=True)

    total_attacks = len(alerts)
    wifi_pct = round((total_wifi_count / total_attacks) * 100) if total_attacks else 0
    cellular_pct = round((total_cellular_count / total_attacks) * 100) if total_attacks else 0

    return jsonify({
        'status': 'ok',
        'tenant_filter': filter_org or 'all',
        'summary': {
            'total_correlated_ips': len(ip_list),
            'total_correlated_devices': len(device_list),
            'total_hotspots': len(location_list),
            'total_attacks_analyzed': total_attacks,
            'wifi_attacks': total_wifi_count,
            'cellular_attacks': total_cellular_count,
            'ethernet_attacks': total_ethernet_count,
            'wifi_percentage': wifi_pct,
            'cellular_percentage': cellular_pct,
            'cross_account_pivot_devices_count': pivot_devices_count,
        },
        'ip_correlations': ip_list,
        'device_correlations': device_list,
        'location_correlations': location_list,
    }), 200
