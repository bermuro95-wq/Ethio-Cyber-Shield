from flask import Blueprint, request, jsonify, g
from app.services.auth_service import role_required
from app.services.security_rules import (
    run_full_analysis_on_incident, analyze_transaction, correlate_cyber_fraud
)

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
