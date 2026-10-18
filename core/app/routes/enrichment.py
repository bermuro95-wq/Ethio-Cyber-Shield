"""
Enrichment & Context API for Ethio-Cyber-Shield (ECS).
Provides endpoints to query offline GeoIP/ASN, Threat Intelligence,
and internal device reputation scores.
"""
from flask import Blueprint, request, jsonify, g
from app.services.auth_service import login_required
from app.services.enrichment_service import (
    lookup_ip_enrichment,
    calculate_device_reputation,
    enrich_canonical_event
)

enrichment_bp = Blueprint('enrichment', __name__)


@enrichment_bp.route('/ip/<ip>', methods=['GET'])
@login_required
def enrich_ip_endpoint(ip):
    """
    Returns offline GeoIP, ASN, carrier, and threat flags for an IP address.
    Zero external network egress.
    """
    data = lookup_ip_enrichment(ip)
    return jsonify(data), 200


@enrichment_bp.route('/device/<device_id>', methods=['GET'])
@login_required
def enrich_device_endpoint(device_id):
    """
    Returns explainable device reputation score and behavioral metrics
    based on historical organization telemetry.
    """
    data = calculate_device_reputation(device_id, organization_id=g.organization_id)
    return jsonify(data), 200


@enrichment_bp.route('/event', methods=['POST'])
@login_required
def enrich_event_endpoint():
    """
    Dry-run event enrichment endpoint. Takes a canonical or mapped event and attaches
    geolocation, ASN, threat indicators, and device context to event attributes.
    """
    raw_event = request.get_json() or {}
    if not raw_event.get('organization_id'):
        raw_event['organization_id'] = g.organization_id

    enriched = enrich_canonical_event(raw_event)
    return jsonify(enriched), 200
