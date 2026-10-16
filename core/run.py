from app import create_app
import os

app = create_app()

if __name__ == '__main__':
    port = int(os.getenv('PORT', 5000))
    debug = os.getenv('FLASK_DEBUG', '0') == '1'

    # Optional background synchronization daemon
    if os.getenv('ENABLE_TARGET_POLLER', '1') == '1':
        from app.services.poller_service import get_poller_daemon
        get_poller_daemon().start()

    app.run(host='0.0.0.0', port=port, debug=debug)
