# Ethio-Cyber-Shield (ECS) — Developer & Engineering Guidelines

> **System Designation**: Sovereign Cyber Defense, Threat Intelligence & 48-Hour Incident-Readiness Platform  
> **Institutional Submission**: Official Project Submission to the **Information Network Security Administration (INSA)**, Federal Democratic Republic of Ethiopia.  
> **Project Authors**: Musab Hassen Aliyi (`CTC-384-26`), Osman Mohammed Seid (`CTC-2974-26`), Kedist Eyasu Embaye (`CTC-1247-26`), Yoseph Abebe Ersedo (`CTC-430-26`), Omer Mohammed Seid (`CTC-3716-26`), Efrem Mola Genebo (`CTC-4772-26`).  
> **Official Monorepo**: [https://github.com/Rammiso/ethio-cybershield](https://github.com/Rammiso/ethio-cybershield) *(Directory: `Ethio-Cyber-Shield/`)*  
> **Production Deployment**: [https://ethio-cyber-shield.onrender.com](https://ethio-cyber-shield.onrender.com)

---

## 1. Core Architectural & Engineering Principles

1. **Explainable by Default**:  
   Every detection and alert must display the exact deterministic rules triggered, condition evaluations, feature weights, and raw event evidence. Deterministic logic drives decisions; ML/LLM algorithms are strictly advisory/explanatory.
2. **Safe & Reversible Automation**:  
   All automated response actions follow progressive risk postures: `observe` (shadow) → `recommend` → `approve` (human-in-the-loop) → `auto`. Actions enforce blast-radius limits, cooldowns, allowlists, and rollback capabilities (`revert`).
3. **Evidence First & Hash-Sealed**:  
   All incident telemetry, detections, and containment dispatches are hash-sealed using SHA-256 in an append-only audit trail and exportable for statutory INSA/NBE regulatory review.
4. **Privacy-Preserving Threat Exchange**:  
   Cross-tenant community signals exchange only keyed hashes, indicator values, confidence levels, and TLP markings. Never export or exchange raw PII, account balances, or unmasked financial details.
5. **Self-Hostable & Vendor Independent**:  
   Operates independently via standard Docker Compose (`PostgreSQL` + `Redis`) with zero mandatory proprietary cloud lock-in.
6. **Statutory Honesty & Regulatory Alignment**:  
   Technical documentation claims *"supports evidence for"* or *"incident readiness assistance"* aligned with **INSA Proclamation No. 1426/2026** and **NBE Directives**.
7. **Ethiopian Operational Context**:  
   Native Ethiopian Birr (`ETB`) currency units, Addis Ababa local timezone (`Africa/Addis_Ababa`, UTC+3), local payment rails (P2P, USSD, mobile money, EthSwitch), and Ethiopian regional IP subnet routing.

---

## 2. Engineering Standards & Test Commands

```bash
# Setup virtual environment
cd core
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Run core test suites
PYTHONPATH=. python -m unittest discover tests -v

# Run multi-tenancy isolation verification
PYTHONPATH=. python -m unittest tests/test_saas_multi_tenancy.py -v
```
