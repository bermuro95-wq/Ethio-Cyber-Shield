# Ethio-Cyber-Shield (ECS) — Support Model & Operational Boundaries

> **Institutional Submission**: Official Operational Support Framework submitted to the **Information Network Security Administration (INSA)**, Federal Democratic Republic of Ethiopia.  
> **Project Research Consortium**: Musab Hassen Aliyi (`CTC-384-26`), Osman Mohammed Seid (`CTC-2974-26`), Kedist Eyasu Embaye (`CTC-1247-26`), Yoseph Abebe Ersedo (`CTC-430-26`), Omer Mohammed Seid (`CTC-3716-26`), Efrem Mola Genebo (`CTC-4772-26`).  
> **Document Version**: 3.0  
> **Official Monorepo**: [https://github.com/Rammiso/ethio-cybershield](https://github.com/Rammiso/ethio-cybershield)  
> **Mandate**: Clearly delineate operational responsibilities, support service levels, and boundaries of assistance across platform editions.  
> **Adherence to Principle #6**: Ethio-Cyber-Shield explicitly disclaims guaranteed compliance or 24/7 outsourced SOC protection unless formally contracted under a dedicated Managed Defense SLA.

---

## 1. Support Matrix by Edition

| Tier / Attribute | Community Edition | Pro / Financial Operator | Managed Defense | Sector Hub |
| :--- | :--- | :--- | :--- | :--- |
| **Licensing** | Open-source (Apache-2.0) | Commercial Subscription | Managed Service Fee | Consortium / National Hub |
| **Hosting Model** | Self-hosted (Docker/K8s) | Self-hosted or Private Cloud | Dedicated Cloud or Hybrid | Multi-Tenant Consortium Hub |
| **Support Channel** | Community GitHub Issues | Enterprise Portal & Email | Dedicated Telegram / Phone | Dedicated Technical Lead |
| **Standard SLA Hours** | Best-effort (Community) | 8x5 East Africa Time | 24x7 Severity 1 Escalation | 24x7 Critical Infrastructure |
| **Sev 1 Response Target** | N/A (Self-managed) | $\le$ 2 Hours | $\le$ 30 Minutes | $\le$ 15 Minutes |
| **Sev 2 Response Target** | N/A (Self-managed) | $\le$ 6 Hours | $\le$ 2 Hours | $\le$ 1 Hour |
| **Rule Tuning Assistance**| Community Discussions | Quarterly Review | Monthly Dedicated SOC Review| Sector-wide Coordination |
| **Tabletop Drills** | Self-conducted | Annual Template | Bi-Annual Facilitated Drill | National Simulation Drill |

---

## 2. Severity Classification & Incident Response SLAs

Severity levels apply to software defects, platform outages, and incident response assistance:

### Severity 1 — Critical Platform Outage or Active National Breach
- **Definition**: Core detection engine stopped; durable event ingestion failure; active high-impact ransomware or massive P2P mule cascade requiring emergency intervention.
- **Pro Target Response**: $\le$ 2 hours (during business hours).
- **Managed Target Response**: $\le$ 30 minutes (24/7/365).
- **Escalation Path**: Primary Responder $\to$ Platform Operations Lead $\to$ CISO / Designated Authority.

### Severity 2 — Significant Degradation
- **Definition**: Notification channels impaired; secondary connector failures; rate-limit throttling in non-critical pipeline.
- **Pro Target Response**: $\le$ 6 hours.
- **Managed Target Response**: $\le$ 2 hours.

### Severity 3 — General Technical Query or Minor Anomaly
- **Definition**: Rule tuning guidance; false positive adjustment request; documentation clarification.
- **Pro Target Response**: Next business day.
- **Managed Target Response**: $\le$ 8 hours.

---

## 3. Explicit Boundaries & Disclaimers

### 3.1 No Automatic 24/7 SOC Coverage
Deploying Ethio-Cyber-Shield Community or Pro Edition provides the technical infrastructure, detection logic, and automation guardrails, but **does not constitute an external 24/7 outsourced Security Operations Center (SOC)**. Internal security analysts or a contracted Managed Defense team must monitor alerts, execute manual approvals, and interface with law enforcement.

### 3.2 Regulatory Compliance Disclaimers
In accordance with Rule #6 of our Core Engineering Guidelines:
> **Ethio-Cyber-Shield provides tools that *"supports evidence for"* statutory compliance and incident readiness. It does not *"guarantee"* compliance with INSA Proclamation No. 1426/2026, NBE Directives, or PDPP Proclamation No. 1321/2024.**

Final compliance determinations, regulatory filings, and legal defenses remain the sole statutory responsibility of the operator's designated Data Protection Officer (DPO) and Chief Information Security Officer (CISO).

### 3.3 Safe Automation Boundaries
In `auto` mode, Ethio-Cyber-Shield executes predefined, bounded mitigation actions (e.g., temporary account quarantine, session revocation). Operators remain responsible for maintaining allowlists, configuring emergency kill switches, and reviewing automated action logs.

---

## 4. Contact & Escalation Channels

- **Community Support**: [GitHub Issues Repository](https://github.com/your-org/Ethio-Cyber-Shield/issues)
- **Enterprise Technical Support**: `support@ethio-cybershield.org`
- **Security Vulnerability Reporting**: `security@ethio-cybershield.org` (PGP key available upon request)
- **Emergency Hotline (Managed Tier Only)**: Available in operator tenant onboarding dossier.
