"""
Unified Entity Graph & Investigation REST API for Ethio-Cyber-Shield (ECS).
Provides endpoints for:
- Entity node inspection (/entities/<type>/<value>)
- Relationship linkage retrieval (/entities/<type>/<value>/links)
- Multi-hop graph exploration (/entities/<type>/<value>/graph)
- Shared entity & fraud ring detection (/entities/<type>/<value>/shared)
- Transitive graph risk synthesis (/entities/<type>/<value>/risk)
- Analyst tagging (/entities/<type>/<value>/tag)
"""
from flask import Blueprint, request, jsonify, g
from app.services.auth_service import login_required, role_required
from app.services.entity_graph_service import (
    get_entity,
    get_entity_links,
    get_entity_graph,
    find_shared_entities,
    calculate_graph_risk,
    tag_entity
)

entities_bp = Blueprint('entities', __name__)


@entities_bp.route('/<entity_type>/<entity_value>', methods=['GET'])
@login_required
def get_entity_detail(entity_type, entity_value):
    """Retrieves an entity node summary scoped to the authenticated organization."""
    entity = get_entity(entity_type, entity_value, org_id=g.organization_id)
    if not entity:
        return jsonify({'error': f"Entity '{entity_type}:{entity_value}' not found"}), 404

    return jsonify(entity), 200


@entities_bp.route('/<entity_type>/<entity_value>/links', methods=['GET'])
@login_required
def get_entity_relationships(entity_type, entity_value):
    """Retrieves all relationship links (inbound & outbound) for an entity."""
    link_type = request.args.get('link_type')
    links = get_entity_links(entity_type, entity_value, org_id=g.organization_id, link_type=link_type)
    return jsonify(links), 200


@entities_bp.route('/<entity_type>/<entity_value>/graph', methods=['GET'])
@login_required
def get_entity_neighborhood_graph(entity_type, entity_value):
    """
    Returns a network graph payload (nodes and edges) starting from the root entity
    up to the specified exploration depth (1 or 2). Suitable for Cytoscape / Vis.js renderers.
    """
    try:
        depth = int(request.args.get('depth', 1))
        depth = max(1, min(2, depth))  # Bound depth between 1 and 2
    except ValueError:
        depth = 1

    graph = get_entity_graph(entity_type, entity_value, org_id=g.organization_id, depth=depth)
    return jsonify(graph), 200


@entities_bp.route('/<entity_type>/<entity_value>/shared', methods=['GET'])
@login_required
def check_shared_entity(entity_type, entity_value):
    """
    Detects shared devices (credential stuffing / multiple account takeover)
    and shared beneficiary accounts (money mule aggregation rings).
    """
    analysis = find_shared_entities(entity_type, entity_value, org_id=g.organization_id)
    return jsonify(analysis), 200


@entities_bp.route('/<entity_type>/<entity_value>/risk', methods=['GET'])
@login_required
def get_entity_graph_risk(entity_type, entity_value):
    """
    Calculates transitive risk propagated across graph connections
    (e.g., connection to compromised accounts or malicious IPs).
    """
    risk_report = calculate_graph_risk(entity_type, entity_value, org_id=g.organization_id)
    return jsonify(risk_report), 200


@entities_bp.route('/<entity_type>/<entity_value>/tag', methods=['POST'])
@role_required('admin', 'analyst', 'responder')
def add_entity_tag(entity_type, entity_value):
    """Allows analysts and automated playbooks to attach investigation tags to entity nodes."""
    data = request.get_json() or {}
    tag = (data.get('tag') or '').strip()

    if not tag:
        return jsonify({'error': 'tag is required'}), 400

    updated_node = tag_entity(entity_type, entity_value, tag=tag, org_id=g.organization_id)
    return jsonify(updated_node), 200
