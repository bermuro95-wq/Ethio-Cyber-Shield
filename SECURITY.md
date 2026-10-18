# Security Policy — Ethio-Cyber-Shield (ECS)

> **Platform**: Ethio-Cyber-Shield (ECS) Independent Defense Platform  
> **Target Audience**: Financial Institutions, Telecommunications, Critical National Infrastructure (CNI)

---

## 1. Supported Versions

Security updates and critical patches are released for the following versions:

| Version | Supported | Status |
| :--- | :--- | :--- |
| **v3.0.x (Current)** | :white_check_mark: Yes | Active Mainline Development |
| v2.0.x | :x: No | Legacy Reference Only (`ecs-v2.0` tag) |
| < v2.0 | :x: No | Deprecated |

---

## 2. Reporting a Vulnerability

We prioritize the security and confidentiality of our platform, customer systems, and threat intelligence telemetry. If you discover a security vulnerability, we ask that you responsibly disclose it to our core engineering team.

### Reporting Channels
- **Security Email**: `security@ethiocybershield.et` (or platform maintainers)
- **Emergency Incident Response**: PGP Key fingerprint available on request.
- **Do NOT file public GitHub Issues** for vulnerabilities involving remote code execution, credential exposure, cross-tenant data leaks, or authentication bypasses.

### What to Include in Your Report
1. Description of the vulnerability and attack vector.
2. Step-by-step reproduction instructions or proof-of-concept (PoC).
3. Affected components (`core/`, `connectors/`, `sdk/`, `deploy/`).
4. Potential impact (e.g., cross-tenant exposure, telemetry spoofing, denial of service).
5. Any proposed mitigations or patch diffs.

---

## 3. SLA and Response Process

1. **Initial Acknowledgment**: Within 24 hours of submission.
2. **Triage & Severity Assessment**: Within 48 hours according to CVSS v3.1.
3. **Patch Development & Testing**:
   - **Critical (CVSS 9.0–10.0)**: Fix released within 72 hours.
   - **High (CVSS 7.0–8.9)**: Fix released within 7 days.
   - **Medium / Low**: Next planned minor release.
4. **Coordinated Disclosure**: Public advisories are coordinated after impacted operators have deployed mitigations.

---

## 4. Hard Cryptographic & Security Standards

- **Envelope Encryption at Rest**: AES-256-GCM with unique 96-bit IVs and 128-bit authentication tags for connector secrets and target credentials.
- **Tamper-Evident Audit Chains**: Cryptographic SHA-256 predecessor hash chaining across all `audit_logs` entries.
- **Zero Secrets in Code/Logs**: API keys, master encryption keys, and private tokens must only be supplied via environment variables (`ECS_MASTER_ENCRYPTION_KEY`, `JWT_SECRET`) and never logged.
- **Tenant Isolation**: Every database table enforces `organization_id UUID NOT NULL` with strict PostgreSQL Row-Level Security (RLS). Cross-tenant data leaks are treated as P0 critical vulnerabilities.
