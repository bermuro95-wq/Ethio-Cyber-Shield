"""
Case Management REST API Routes for Ethio-Cyber-Shield (ECS) v3.0 (Phase 4.4).
Endpoints:
  GET    /api/cases                        - List cases with SLA metrics & filtering
  GET    /api/cases/<id>                   - Get case detail with SLA status
  POST   /api/cases/<id>/assign            - Assign case to responder
  POST   /api/cases/<id>/status            - Transition status with SLA milestones
  GET    /api/cases/<id>/notes             - List case notes
  POST   /api/cases/<id>/notes             - Add analyst case note
  GET    /api/cases/<id>/attachments       - List case evidence attachments
  POST   /api/cases/<id>/attachments       - Upload/attach evidence file with SHA-256 seal
  POST   /api/cases/attachments/<id>/verify- Verify SHA-256 seal integrity
  GET    /api/cases/timeline/entity        - Cross-time entity timeline (events, alerts, actions)
  GET    /api/cases/<id>/graph             - Related-alert & entity case graph
  GET    /api/cases/search/saved           - List saved queries
  POST   /api/cases/search/saved           - Create saved search
  DELETE /api/cases/search/saved/<id>      - Delete saved search
  GET    /api/cases/search/events          - Cross-time event search
"""
import io
from flask import Blueprint, request, jsonify, g
from app.services.auth_service import login_required, role_required
from app.services.case_service import CaseService
from app.services.tenant_service import get_current_organization_id
import logging

logger = logging.getLogger(__name__)
cases_bp = Blueprint('cases', __name__)


def _get_org_id() -> str:
    org_id = g.user.get('organization_id') if hasattr(g, 'user') and g.user else None
    return str(org_id or get_current_organization_id() or "00000000-0000-0000-0000-000000000001")


@cases_bp.route('', methods=['GET'])
@login_required
def list_cases():
    """Lists incident cases with SLA status for current tenant."""
    org_id = _get_org_id()
    from app.services.db import get_service_supabase
    sb = get_service_supabase()

    try:
        q = sb.table('incidents').select('*').eq('organization_id', org_id)
        status = request.args.get('status')
        severity = request.args.get('severity')
        if status:
            q = q.eq('status', status)
        if severity:
            q = q.eq('severity', severity)
        res = q.order('created_at', desc=True).limit(100).execute()
        cases = res.data or []
    except Exception as e:
        logger.debug(f"Cases list DB note: {e}")
        cases = []

    for c in cases:
        c['sla'] = CaseService.calculate_sla_status(c)

    return jsonify(cases), 200


@cases_bp.route('/<incident_id>', methods=['GET'])
@login_required
def get_case(incident_id):
    """Retrieves single case with SLA metrics."""
    org_id = _get_org_id()
    case = CaseService.get_case(org_id, incident_id)
    if not case:
        return jsonify({'error': 'Case not found'}), 404
    return jsonify(case), 200


@cases_bp.route('/<incident_id>/assign', methods=['POST'])
@role_required('admin', 'analyst', 'responder')
def assign_case(incident_id):
    """Assigns case to analyst and marks acknowledged."""
    org_id = _get_org_id()
    data = request.get_json() or {}
    user_id = data.get('user_id')
    if not user_id:
        return jsonify({'error': 'user_id is required'}), 400

    try:
        updated = CaseService.assign_case(
            org_id=org_id,
            incident_id=incident_id,
            user_id=user_id,
            assigned_by=g.user.get('id') if hasattr(g, 'user') else None
        )
        return jsonify(updated), 200
    except ValueError as e:
        return jsonify({'error': str(e)}), 404


@cases_bp.route('/<incident_id>/status', methods=['POST'])
@role_required('admin', 'analyst', 'responder')
def transition_status(incident_id):
    """Transitions case status (open -> investigating -> contained -> resolved -> closed)."""
    org_id = _get_org_id()
    data = request.get_json() or {}
    new_status = data.get('status')
    if not new_status:
        return jsonify({'error': 'status is required'}), 400

    try:
        updated = CaseService.transition_status(
            org_id=org_id,
            incident_id=incident_id,
            new_status=new_status,
            user_id=g.user.get('id') if hasattr(g, 'user') else None
        )
        return jsonify(updated), 200
    except ValueError as e:
        status_code = 404 if 'not found' in str(e).lower() else 400
        return jsonify({'error': str(e)}), status_code


@cases_bp.route('/<incident_id>/notes', methods=['GET'])
@login_required
def list_notes(incident_id):
    """Lists analyst notes for a case."""
    org_id = _get_org_id()
    notes = CaseService.list_notes(org_id, incident_id)
    return jsonify(notes), 200


@cases_bp.route('/<incident_id>/notes', methods=['POST'])
@role_required('admin', 'analyst', 'responder')
def add_note(incident_id):
    """Adds a note to a case."""
    org_id = _get_org_id()
    data = request.get_json() or {}
    note_text = data.get('note')
    if not note_text:
        return jsonify({'error': 'note is required'}), 400

    author_id = g.user.get('id') if hasattr(g, 'user') else None
    author_name = g.user.get('full_name') if hasattr(g, 'user') else 'SOC Analyst'

    try:
        note_rec = CaseService.add_note(
            org_id=org_id,
            incident_id=incident_id,
            note=note_text,
            author_id=author_id,
            author_name=author_name,
            is_internal=data.get('is_internal', True)
        )
        return jsonify(note_rec), 201
    except ValueError as e:
        status_code = 404 if 'not found' in str(e).lower() else 400
        return jsonify({'error': str(e)}), status_code


@cases_bp.route('/<incident_id>/attachments', methods=['GET'])
@login_required
def list_attachments(incident_id):
    """Lists evidence attachments for a case."""
    org_id = _get_org_id()
    attachments = CaseService.list_attachments(org_id, incident_id)
    return jsonify(attachments), 200


@cases_bp.route('/<incident_id>/attachments', methods=['POST'])
@role_required('admin', 'analyst', 'responder')
def add_attachment(incident_id):
    """Uploads or registers an evidence attachment with SHA-256 seal."""
    org_id = _get_org_id()

    # Supports multipart/form-data or JSON payload
    if 'file' in request.files:
        f = request.files['file']
        filename = f.filename
        content_bytes = f.read()
        content_type = f.content_type or 'application/octet-stream'
    else:
        data = request.get_json() or {}
        filename = data.get('filename', 'evidence.txt')
        content_str = data.get('content', '')
        content_bytes = content_str.encode('utf-8')
        content_type = data.get('content_type', 'text/plain')

    if not content_bytes:
        return jsonify({'error': 'Attachment file content is required'}), 400

    uploaded_by = g.user.get('id') if hasattr(g, 'user') else None

    try:
        att = CaseService.add_attachment(
            org_id=org_id,
            incident_id=incident_id,
            filename=filename,
            content_bytes=content_bytes,
            content_type=content_type,
            uploaded_by=uploaded_by
        )
        return jsonify(att), 201
    except ValueError as e:
        status_code = 404 if 'not found' in str(e).lower() else 400
        return jsonify({'error': str(e)}), status_code


@cases_bp.route('/attachments/<attachment_id>/verify', methods=['POST'])
@login_required
def verify_attachment(attachment_id):
    """Verifies SHA-256 seal against candidate payload or file."""
    org_id = _get_org_id()
    if 'file' in request.files:
        content_bytes = request.files['file'].read()
    else:
        data = request.get_json() or {}
        content_bytes = data.get('content', '').encode('utf-8')

    res = CaseService.verify_attachment(org_id, attachment_id, content_bytes)
    return jsonify(res), 200


@cases_bp.route('/timeline/entity', methods=['GET'])
@login_required
def get_entity_timeline():
    """Gathers cross-time chronological timeline for an entity."""
    org_id = _get_org_id()
    entity_type = request.args.get('entity_type', 'account')
    entity_value = request.args.get('entity_value')
    if not entity_value:
        return jsonify({'error': 'entity_value parameter is required'}), 400

    start_time = request.args.get('start_time')
    end_time = request.args.get('end_time')

    timeline = CaseService.get_entity_timeline(
        org_id=org_id,
        entity_type=entity_type,
        entity_value=entity_value,
        start_time=start_time,
        end_time=end_time
    )
    return jsonify(timeline), 200


@cases_bp.route('/<incident_id>/graph', methods=['GET'])
@login_required
def get_case_graph(incident_id):
    """Returns visual graph of correlated alerts, indicators, entities, and actions."""
    org_id = _get_org_id()
    graph = CaseService.get_case_graph(org_id, incident_id)
    return jsonify(graph), 200


@cases_bp.route('/search/saved', methods=['GET'])
@login_required
def list_saved_searches():
    """Lists saved search queries."""
    org_id = _get_org_id()
    user_id = g.user.get('id') if hasattr(g, 'user') else None
    searches = CaseService.list_saved_searches(org_id, user_id)
    return jsonify(searches), 200


@cases_bp.route('/search/saved', methods=['POST'])
@login_required
def create_saved_search():
    """Creates a saved search."""
    org_id = _get_org_id()
    user_id = g.user.get('id') if hasattr(g, 'user') else None
    data = request.get_json() or {}
    name = data.get('name')
    query_params = data.get('query_params', {})

    if not name:
        return jsonify({'error': 'name is required'}), 400

    search = CaseService.create_saved_search(
        org_id=org_id,
        user_id=user_id,
        name=name,
        query_params=query_params,
        description=data.get('description'),
        is_shared=data.get('is_shared', False)
    )
    return jsonify(search), 201


@cases_bp.route('/search/saved/<search_id>', methods=['DELETE'])
@login_required
def delete_saved_search(search_id):
    """Deletes a saved search."""
    org_id = _get_org_id()
    user_id = g.user.get('id') if hasattr(g, 'user') else None
    success = CaseService.delete_saved_search(org_id, search_id, user_id)
    return jsonify({'success': success}), 200


@cases_bp.route('/search/events', methods=['GET'])
@login_required
def search_events_cross_time():
    """Executes cross-time query on security events."""
    org_id = _get_org_id()
    limit = int(request.args.get('limit', 100))
    offset = int(request.args.get('offset', 0))

    params = {
        'event_type': request.args.get('event_type'),
        'channel': request.args.get('channel'),
        'account': request.args.get('account'),
        'source_ip': request.args.get('source_ip'),
        'start_time': request.args.get('start_time'),
        'end_time': request.args.get('end_time'),
        'search': request.args.get('search'),
        'min_amount': request.args.get('min_amount'),
        'max_amount': request.args.get('max_amount')
    }

    res = CaseService.search_events_cross_time(org_id, params, limit=limit, offset=offset)
    return jsonify(res), 200
