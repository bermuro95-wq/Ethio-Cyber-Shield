from flask import Flask
from flask_cors import CORS
from dotenv import load_dotenv
import os

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

    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(incidents_bp, url_prefix='/api/incidents')
    app.register_blueprint(indicators_bp, url_prefix='/api/indicators')
    app.register_blueprint(transactions_bp, url_prefix='/api/transactions')
    app.register_blueprint(alerts_bp, url_prefix='/api/alerts')
    app.register_blueprint(dashboard_bp, url_prefix='/api/dashboard')
    app.register_blueprint(audit_bp, url_prefix='/api/audit')
    app.register_blueprint(analysis_bp, url_prefix='/api/analysis')
    app.register_blueprint(live_bp, url_prefix='/api/live')
    app.register_blueprint(watchlists_bp, url_prefix='/api/watchlists')
    app.register_blueprint(settings_bp, url_prefix='/api/settings')
    app.register_blueprint(reports_bp, url_prefix='/api/reports')

    @app.route('/api/health')
    def health():
        return {'status': 'ok', 'service': 'Ethio-Cyber Shield API', 'version': '1.0.0'}

    return app
