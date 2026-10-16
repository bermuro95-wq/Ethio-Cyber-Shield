#!/usr/bin/env python3
"""
Ethio-Cyber-Shield (ECS) — Attack Scenario Simulator.
Generates synthetic attack sequences for CI/CD benchmarks and demonstrations.
"""
import time
import argparse
import logging
from sdk.python.ecs_client import ECSClient, CanonicalEventBuilder

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')
logger = logging.getLogger("Simulator")


def run_brute_force(client: ECSClient, target_ip: str = "196.188.1.101"):
    logger.info(f"==> Launching Brute Force Credential Attack from IP: {target_ip}...")
    for i in range(1, 6):
        event = CanonicalEventBuilder.build(
            event_type="auth.login.failed",
            result="FAILURE",
            source_system="targetsys_shieldbank",
            user_id_pub=f"usr_victim_101",
            account_id_pub="100012345678",
            source_ip=target_ip,
            endpoint="/api/auth/login",
            attributes={"attempt": i, "reason": "invalid_credentials"}
        )
        client.send_event(event)
        time.sleep(0.3)
    logger.info("Brute force sequence completed.")


def run_high_value_fraud(client: ECSClient):
    logger.info("==> Launching High-Value Fraudulent Transfer...")
    event = CanonicalEventBuilder.build(
        event_type="transaction.transfer.created",
        result="SUCCESS",
        source_system="targetsys_shieldbank",
        user_id_pub="usr_victim_101",
        account_id_pub="100012345678",
        amount_minor=18000000,  # 180,000 ETB
        currency="ETB",
        beneficiary_id_pub="ben_mule_999",
        transaction_id_pub=f"tx_fraud_{int(time.time())}",
        source_ip="197.156.70.12",
        channel="mobile",
        payment_rail="p2p",
        attributes={"exceeds_daily_limit": True}
    )
    res = client.send_event(event)
    logger.info(f"High-value fraud event sent: {res}")


def run_ato_chain(client: ECSClient):
    logger.info("==> Launching Complete Account Takeover Attack Chain (ATO-001)...")
    attacker_ip = "197.156.120.44"
    attacker_dev = "dev_attacker_rogue_hw"
    acc = "100099887766"

    # Step 1: 3 Failed logins
    for i in range(3):
        client.send_event(CanonicalEventBuilder.build(
            event_type="auth.login.failed",
            result="FAILURE",
            source_system="targetsys_shieldbank",
            account_id_pub=acc,
            source_ip=attacker_ip,
            attributes={"step": "brute_force"}
        ))
        time.sleep(0.2)

    # Step 2: Successful login from new device
    client.send_event(CanonicalEventBuilder.build(
        event_type="auth.login.succeeded",
        result="SUCCESS",
        source_system="targetsys_shieldbank",
        account_id_pub=acc,
        device_id_pub=attacker_dev,
        source_ip=attacker_ip,
        attributes={"is_new_device": True}
    ))
    time.sleep(0.5)

    # Step 3: Beneficiary added
    client.send_event(CanonicalEventBuilder.build(
        event_type="beneficiary.created",
        result="SUCCESS",
        source_system="targetsys_shieldbank",
        account_id_pub=acc,
        device_id_pub=attacker_dev,
        beneficiary_id_pub="ben_mule_syndicate",
        source_ip=attacker_ip
    ))
    time.sleep(0.5)

    # Step 4: High-value transfer
    client.send_event(CanonicalEventBuilder.build(
        event_type="transaction.transfer.created",
        result="SUCCESS",
        source_system="targetsys_shieldbank",
        account_id_pub=acc,
        device_id_pub=attacker_dev,
        beneficiary_id_pub="ben_mule_syndicate",
        amount_minor=15000000,
        currency="ETB",
        source_ip=attacker_ip,
        payment_rail="p2p"
    ))
    logger.info("ATO-001 Attack chain completed.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ECS Attack Simulator")
    parser.add_argument("--url", default="http://localhost:5000", help="ECS Core URL")
    parser.add_argument("--key", default="ecs_live_prod_key_01", help="Key ID")
    parser.add_argument("--secret", default="super-secret-key-32b", help="Secret Key")
    parser.add_argument("--scenario", choices=["brute_force", "high_value", "ato"], default="ato")
    args = parser.parse_args()

    client = ECSClient(ecs_url=args.url, key_id=args.key, secret_key=args.secret)

    if args.scenario == "brute_force":
        run_brute_force(client)
    elif args.scenario == "high_value":
        run_high_value_fraud(client)
    elif args.scenario == "ato":
        run_ato_chain(client)
