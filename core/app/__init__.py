import sys
import os
from flask import Flask
from flask_cors import CORS
from dotenv import load_dotenv

# Ensure repository root is in sys.path for connectors and sdk modules
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from app.config import Config

load_dotenv()

def create_app():
    app = Flask(__name__)

    raw = os.getenv('ALLOWED_ORIGINS', 'http://localhost:5500,http://127.0.0.1:5500')
    origins = [o.strip() for o in raw.split(',') if o.strip()]
    debug = os.getenv('FLASK_DEBUG', '0') == '1'

    # Local development: open CORS so login works from any localhost port
    if debug or '*' in origins:
        CORS(app, resources={r"/api/*": {
            "origins": "*",
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"],
            "supports_credentials": False
        }})
    else:
        CORS(app, resources={r"/api/*": {
            "origins": origins,
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"],
            "supports_credentials": True
        }})

    from app.routes.auth import auth_bp
    from app.routes.incidents import incidents_bp
    from app.routes.indicators import indicators_bp
    from app.routes.transactions import transactions_bp
    from app.routes.alerts import alerts_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.audit import audit_bp
    from app.routes.analysis import analysis_bp
    from app.routes.live import live_bp
    from app.routes.watchlists import watchlists_bp
    from app.routes.settings import settings_bp
    from app.routes.reports import reports_bp
    from app.routes.events import events_bp
    from app.routes.targets import targets_bp
    from app.routes.webhooks import webhooks_bp
    from app.routes.log_agent import log_agent_bp
    from app.routes.enrichment import enrichment_bp
    from app.routes.entities import entities_bp
    from app.routes.data_quality import data_quality_bp
    from app.routes.connectors import connectors_bp
    from app.routes.rules import rules_bp
    from app.routes.baselines import baselines_bp
    from app.routes.risk import risk_bp
    from app.routes.benchmark import benchmark_bp
    from app.routes.tenants import tenants_bp
    from app.routes.alert_quality import alert_quality_bp
    from app.routes.response import response_bp
    from app.routes.cases import cases_bp
    from app.routes.notifications import notifications_bp
    from app.routes.feedback import feedback_bp
    from app.routes.pir import pir_bp
    from app.routes.readiness import readiness_bp
    from app.routes.signals import signals_bp
    from app.routes.narrative import narrative_bp
    from app.routes.telemetry_adapters import adapters_bp
    from app.routes.exposure import exposure_bp
    from app.routes.fayda import fayda_bp
    from app.routes.regulator import regulator_bp

    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(incidents_bp, url_prefix='/api/incidents')
    app.register_blueprint(indicators_bp, url_prefix='/api/indicators')
    app.register_blueprint(transactions_bp, url_prefix='/api/transactions')
    app.register_blueprint(alert_quality_bp, url_prefix='/api/alerts/quality')
    app.register_blueprint(alerts_bp, url_prefix='/api/alerts')
    app.register_blueprint(response_bp, url_prefix='/api/response')
    app.register_blueprint(cases_bp, url_prefix='/api/cases')
    app.register_blueprint(notifications_bp, url_prefix='/api/notifications')
    app.register_blueprint(feedback_bp, url_prefix='/api/feedback')
    app.register_blueprint(pir_bp, url_prefix='/api/pir')
    app.register_blueprint(readiness_bp, url_prefix='/api/readiness')
    app.register_blueprint(signals_bp, url_prefix='/api/signals')
    app.register_blueprint(narrative_bp, url_prefix='/api/narrative')
    app.register_blueprint(adapters_bp, url_prefix='/api/adapters')
    app.register_blueprint(exposure_bp, url_prefix='/api/exposure')
    app.register_blueprint(fayda_bp, url_prefix='/api/fayda')
    app.register_blueprint(regulator_bp, url_prefix='/api/regulator')
    app.register_blueprint(dashboard_bp, url_prefix='/api/dashboard')
    app.register_blueprint(audit_bp, url_prefix='/api/audit')
    app.register_blueprint(analysis_bp, url_prefix='/api/analysis')
    app.register_blueprint(live_bp, url_prefix='/api/live')
    app.register_blueprint(watchlists_bp, url_prefix='/api/watchlists')
    app.register_blueprint(settings_bp, url_prefix='/api/settings')
    app.register_blueprint(reports_bp, url_prefix='/api/reports')
    app.register_blueprint(events_bp, url_prefix='/api/events')
    app.register_blueprint(targets_bp, url_prefix='/api/targets')
    app.register_blueprint(webhooks_bp, url_prefix='/api/webhooks')
    app.register_blueprint(log_agent_bp, url_prefix='/api/log-agent')
    app.register_blueprint(enrichment_bp, url_prefix='/api/enrichment')
    app.register_blueprint(entities_bp, url_prefix='/api/entities')
    app.register_blueprint(data_quality_bp, url_prefix='/api/health/quality')
    app.register_blueprint(connectors_bp, url_prefix='/api/connectors')
    app.register_blueprint(rules_bp, url_prefix='/api/rules')
    app.register_blueprint(baselines_bp, url_prefix='/api/baselines')
    app.register_blueprint(risk_bp, url_prefix='/api/risk')
    app.register_blueprint(benchmark_bp, url_prefix='/api/benchmark')
    app.register_blueprint(tenants_bp, url_prefix='/api/tenants')




    @app.route('/health')
    @app.route('/api/health')
    def health():
        from app.services.db import check_db_health
        from app.services.stream_service import get_stream_service
        from datetime import datetime, timezone

        db_health = check_db_health()
        stream_svc = get_stream_service()
        stream_stats = stream_svc.get_stream_stats("00000000-0000-0000-0000-000000000001")

        is_healthy = db_health.get('status') == 'healthy' or bool(app.config.get('TESTING'))
        status_label = 'ok' if is_healthy else 'degraded'

        return {
            'status': status_label,
            'service': 'Ethio-Cyber-Shield (ECS)',
            'version': Config.PLATFORM_VERSION,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'components': {
                'database': db_health,
                'stream_engine': {
                    'backend': stream_stats.get('backend'),
                    'stream_depth': stream_stats.get('stream_length', 0),
                    'dlq_depth': stream_stats.get('dlq_length', 0)
                }
            }
        }, 200

    # Unified static UI serving for single-service cloud deployments (Render, Railway, Fly.io, etc.)
    from flask import send_from_directory
    ui_dir = os.path.abspath(os.path.join(repo_root, 'ui'))
    if os.path.exists(ui_dir):
        @app.route('/', defaults={'path': ''})
        @app.route('/<path:path>')
        def serve_ui(path):
            if path.startswith('api/') or path == 'api' or path == 'health':
                return {'error': 'Endpoint not found'}, 404

            # Normalize path: strip optional leading 'ui/' prefix so both /ui/page.html and /page.html resolve cleanly
            clean_path = path
            if clean_path.startswith('ui/'):
                clean_path = clean_path[3:]
            elif clean_path == 'ui':
                clean_path = ''

            target_file = os.path.join(ui_dir, clean_path)
            if clean_path and os.path.isfile(target_file):
                return send_from_directory(ui_dir, clean_path)
            default_file = 'dashboard.html' if os.path.exists(os.path.join(ui_dir, 'dashboard.html')) else 'index.html'
            return send_from_directory(ui_dir, default_file)

    return app
