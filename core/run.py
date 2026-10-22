import sys
import os

# Ensure repository root is in sys.path for connectors and sdk modules
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
if repo_root not in sys.path:
    sys.path.insert(0, repo_root)

from app import create_app

app = create_app()

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', '0') == '1'

    # Optional background synchronization daemon
    if os.getenv('ENABLE_TARGET_POLLER', '1') == '1':
        # When debug/reloader is active, run exclusively in the worker process
        if not debug or os.getenv('WERKZEUG_RUN_MAIN') == 'true':
            from app.services.poller_service import get_poller_daemon
            get_poller_daemon().start()

    app.run(host='0.0.0.0', port=port, debug=debug)
