# Contributing to Ethio-Cyber-Shield (ECS)

> **Institutional Submission**: Official Project Submission to the **Information Network Security Administration (INSA)**, Federal Democratic Republic of Ethiopia.  
> **Project Research Consortium**: Musab Hassen Aliyi (`CTC-384-26`), Osman Mohammed Seid (`CTC-2974-26`), Kedist Eyasu Embaye (`CTC-1247-26`), Yoseph Abebe Ersedo (`CTC-430-26`), Omer Mohammed Seid (`CTC-3716-26`), Efrem Mola Genebo (`CTC-4772-26`).  
> **Official Monorepo**: [https://github.com/Rammiso/ethio-cybershield](https://github.com/Rammiso/ethio-cybershield)

Thank you for your interest in contributing to **Ethio-Cyber-Shield (ECS)**! ECS is an independent, explainable, self-hostable cybersecurity detection and incident-readiness platform designed for Ethiopian critical infrastructure and digital finance operators.

---

## 1. Code of Conduct

All contributors and maintainers are expected to adhere to our [Code of Conduct](CODE_OF_CONDUCT.md). We are committed to fostering an inclusive, welcoming, and harassment-free community.

---

## 2. Non-Negotiable Hard Engineering Rules

Every pull request is reviewed against our six non-negotiable architectural mandates:

1. **Tenancy Everywhere**  
   Every database table and stored entity must contain an `organization_id UUID NOT NULL` column. All queries, cache keys, background jobs, and API routes must be strictly partitioned by `organization_id`. Cross-tenant data leaks are treated as P0 security bugs.
2. **Zero Secrets in Logs or Code**  
   Never commit plaintext passwords, API keys, credentials, or customer PII. Secrets stored in database tables (e.g., connector credentials) must use envelope encryption.
3. **Rules are Data**  
   Detection rules must be defined declaratively in YAML or JSON schema with versioning and lifecycle states (`draft`, `backtest`, `shadow`, `live`). Monolithic hard-coded logic in codebase branches is strictly prohibited.
4. **Durable Event Ingestion**  
   Telemetry ingest must be decoupled from detection processing via bounded durable streams (Redis Streams / outbox) to prevent data loss on container restart.
5. **Reversible Automated Mitigations**  
   Every automated response action connector must implement an idempotent `revert` rollback method or be explicitly declared irreversible and placed behind manual dual-person approval.
6. **No Overclaiming & Regulatory Honesty**  
   Always claim *"supports evidence for"* or *"incident readiness assistance"*, never *"guarantees compliance with INSA/NBE/PDPP"*.
7. **Ethiopian Context First**  
   Default currency is Ethiopian Birr (`ETB`), default operational timezone is Addis Ababa (`Africa/Addis_Ababa`, UTC+3), and multilingual terminology supports English, Amharic (`አማርኛ`), and Afaan Oromo (`Afaan Oromoo`).

---

## 3. Development Workflow

### Prerequisites
- Python 3.10+
- PostgreSQL 15+ / Docker Compose
- Redis 7+
- Node.js 18+ (for frontend web dashboard)

### Setup
```bash
git clone https://github.com/Rammiso/ethio-cybershield.git
cd ethio-cybershield/Ethio-Cyber-Shield/core
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

### Running Tests
Every contribution must include automated unit and integration tests.
```bash
# Run all core test suites
./venv/bin/python -m unittest discover tests

# Run a specific suite
./venv/bin/python -m unittest tests/test_part30_productization_editions_and_operations.py
```

---

## 4. Pull Request Guidelines

1. **One Work Item Per PR**: Keep pull requests tightly scoped and focused on a single capability or bug fix.
2. **Test-Driven Verification**: PRs without accompanying tests in `core/tests/` will not be merged.
3. **Document Decisions**: Significant architectural choices must be documented in `docs/DECISIONS.md` following standard Architecture Decision Record (ADR) format.
4. **Conventional Commits**: Format commit messages cleanly:
   - `feat(readiness): add 48-hour statutory countdown clock`
   - `fix(guardrails): prevent uncorroborated auto-block in signal exchange`
   - `docs(runbook): add disaster recovery backup procedures`

Thank you for helping secure Ethiopia's digital sovereignty and financial infrastructure!
