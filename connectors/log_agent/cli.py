"""
Ethio-Cyber-Shield (ECS) — Standalone Log Agent Collector CLI.
Runs as a lightweight daemon or systemd service on web/proxy servers to tail
access/error logs and forward canonical events to the ECS ingestion gateway.
"""
import sys
import os
import time
import argparse
import logging
import requests
import json
import hmac
import hashlib

from connectors.log_agent.collector import LogAgentCollector

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(name)s: %(message)s')
logger = logging.getLogger("ecs-log-agent")


def send_batch_to_ecs(ecs_url: str, key_id: str, secret_key: str, events: list):
    """Dispatches a batch of events to the ECS Ingestion Gateway with HMAC authentication."""
    if not events:
        return

    endpoint = f"{ecs_url.rstrip('/')}/api/events/batch"
    raw_body = json.dumps({"events": events}).encode('utf-8')
    ts = str(int(time.time()))
    nonce = os.urandom(8).hex()

    body_hash = hashlib.sha256(raw_body).hexdigest()
    canonical = f"{ts}\n{nonce}\nPOST\n/api/events/batch\n{body_hash}"
    sig = hmac.new(secret_key.encode('utf-8'), canonical.encode('utf-8'), hashlib.sha256).hexdigest()

    headers = {
        'Content-Type': 'application/json',
        'X-ECS-Key-Id': key_id,
        'X-ECS-Timestamp': ts,
        'X-ECS-Nonce': nonce,
        'X-ECS-Signature': sig
    }

    try:
        res = requests.post(endpoint, data=raw_body, headers=headers, timeout=10)
        if res.status_code in (200, 201, 202):
            logger.info(f"Successfully shipped batch of {len(events)} events to ECS")
        else:
            logger.error(f"ECS rejected batch ({res.status_code}): {res.text}")
    except Exception as e:
        logger.error(f"Failed to transmit events to ECS: {e}")


def main():
    parser = argparse.ArgumentParser(description="Ethio-Cyber-Shield (ECS) Log Agent Collector")
    parser.add_argument("--file", required=True, help="Path to the log file to monitor")
    parser.add_argument("--format", default="auto", choices=["auto", "nginx_access", "nginx_error", "apache_access", "apache_error", "syslog", "cef"])
    parser.add_argument("--org-id", required=True, help="ECS Organization UUID")
    parser.add_argument("--source-system", default="log-agent", help="Source system identifier")
    parser.add_argument("--state-file", default="/var/run/ecs_log_agent.state", help="Path to state checkpoint file")
    parser.add_argument("--ecs-url", default="http://127.0.0.1:5000", help="ECS Core Gateway URL")
    parser.add_argument("--key-id", default="", help="Target system Key ID for HMAC authentication")
    parser.add_argument("--secret-key", default="", help="Target system Secret Key for HMAC authentication")
    parser.add_argument("--batch-size", type=int, default=100, help="Maximum events per batch")
    parser.add_argument("--poll-interval", type=float, default=1.0, help="Poll interval in seconds")

    args = parser.parse_args()

    logger.info(f"Starting ECS Log Agent for {args.file} (format: {args.format}, org: {args.org_id})")

    collector = LogAgentCollector(
        log_file=args.file,
        organization_id=args.org_id,
        log_format=args.format,
        source_system=args.source_system,
        state_file=args.state_file,
        batch_size=args.batch_size,
        poll_interval_seconds=args.poll_interval
    )

    try:
        while True:
            events = collector.poll_once()
            if events and args.key_id and args.secret_key:
                send_batch_to_ecs(args.ecs_url, args.key_id, args.secret_key, events)
            time.sleep(args.poll_interval)
    except KeyboardInterrupt:
        logger.info("Log Agent shutdown signal received. Exiting.")
        sys.exit(0)


if __name__ == "__main__":
    main()
