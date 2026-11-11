"""
Ethio-Cyber-Shield (ECS) — Unified Command Line Interface (CLI)
Entrypoint for launching ECS defense server, log agent, and simulator.
"""
import sys
import os
import argparse

def main():
    parser = argparse.ArgumentParser(
        prog="ecs",
        description="Ethio-Cyber-Shield (ECS) Sovereign Defense Platform CLI"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # ecs server
    server_parser = subparsers.add_parser("server", help="Start the ECS Defense Gateway and SOC server")
    server_parser.add_argument("--port", type=int, default=int(os.getenv("PORT", 5000)), help="Port to bind server (default: 5000)")
    server_parser.add_argument("--host", type=str, default="0.0.0.0", help="Host interface (default: 0.0.0.0)")
    server_parser.add_argument("--debug", action="store_true", help="Enable debug mode")

    # ecs agent
    agent_parser = subparsers.add_parser("agent", help="Run the ECS Log Agent Collector daemon")
    agent_parser.add_argument("--config", type=str, help="Path to log agent configuration file")
    agent_parser.add_argument("--ecs-url", type=str, default=os.getenv("ECS_URL", "http://127.0.0.1:5000"), help="ECS Base URL")

    # ecs version
    subparsers.add_parser("version", help="Print ECS platform version")

    args = parser.parse_args()

    if args.command == "version":
        print("Ethio-Cyber-Shield (ECS) v3.0-MVP (Sovereign Critical Infrastructure Defense)")
        sys.exit(0)

    elif args.command == "server" or args.command is None:
        port = getattr(args, "port", 5000)
        host = getattr(args, "host", "0.0.0.0")
        debug = getattr(args, "debug", False)
        print(f"[*] Starting Ethio-Cyber-Shield Defense Gateway on {host}:{port}...")

        # Setup paths
        core_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
        if core_dir not in sys.path:
            sys.path.insert(0, core_dir)

        from app import create_app
        app = create_app()

        if os.getenv('ENABLE_TARGET_POLLER', '1') == '1':
            try:
                from app.services.poller_service import get_poller_daemon
                get_poller_daemon().start()
            except Exception as e:
                print(f"[!] Target poller notice: {e}")

        app.run(host=host, port=port, debug=debug)

    elif args.command == "agent":
        from connectors.log_agent.cli import main as run_agent
        run_agent()

    else:
        parser.print_help()

if __name__ == "__main__":
    main()
