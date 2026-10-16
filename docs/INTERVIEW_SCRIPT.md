# Ethio-Cyber-Shield (ECS) — Stakeholder Discovery & Validation Protocol

> **Document Type**: Stakeholder Discovery Protocol & Questionnaire  
> **Target Group**: 12–15 Ethiopian Security, Fraud, Risk & IT Leaders  
> **Applicable Phase**: Phase 0 (Validation & Design Partnerships)  

---

## 1. Interview Target Cohorts

To ensure representative validation across the Ethiopian financial and critical infrastructure ecosystem, interviews are divided into four cohorts:

1. **Cohort A: Tier-1 & Tier-2 Commercial Banks (4–5 interviews)**
   - Roles: Head of Cybersecurity / CISO, Head of Fraud Management, IT Operations Director.
2. **Cohort B: Microfinance Institutions (MFIs) & Regional Credit Unions (3–4 interviews)**
   - Roles: Chief Information Officer, Risk & Compliance Officer, Lead Systems Engineer.
3. **Cohort C: Payment System Operators (PSOs) & Fintech Startups (3–4 interviews)**
   - Roles: VP of Engineering, Lead Security Architect, Infrastructure & Compliance Lead.
4. **Cohort D: Fintech/E-Commerce Web Agencies & Sector Liaisons (2–3 interviews)**
   - Roles: Agency Managing Directors, EthioCERT liaison / Cyber Security Association members.

---

## 2. Interview Protocol & Guiding Principles

- **Confidentiality Assurance**: Inform the interviewee that all institutional details will be aggregated and anonymized. No proprietary breach details or vulnerability data will be published.
- **Listen, Don't Pitch**: Do not pitch ECS as a finished product. The goal is to uncover unvarnished operational friction, regulatory anxiety, tool shortcomings, and budget constraints.
- **Duration**: 35–45 minutes per conversation.

---

## 3. Structured Questionnaire

### Section 1: Current Threat Detection & Tooling Reality (10 mins)
1. *Current Stack*: What security and fraud monitoring tools do you currently have deployed in production? (e.g., SIEM, WAF, core banking fraud modules, in-house database scripts).
2. *Alert Fatigue*: Approximately how many alerts does your team receive daily? What percentage turns out to be false positives?
3. *Blind Spots*: Where are your biggest detection blind spots today? (e.g., USSD transactions, mobile app account takeover, mule accounts, SIM-swap cashouts, insider database modifications).
4. *Core Banking Disconnect*: How long does it take for a suspicious mobile/P2P transfer event to be correlated with branch or web activity?

### Section 2: The First 48 Hours After Incident Detection (10 mins)
1. *Chronology*: Walk me through what happens inside your organization in the first 48 hours after an active cyber attack or major fraud event is discovered.
2. *Statutory Readiness*: Under Proclamation No. 1426/2026, you are mandated to report incidents to the National CERT within 48 hours of detection under threat of ETB 2M fines. How prepared is your team to produce a complete technical report within 48 hours today?
3. *Evidence Gathering*: How do you currently collect and preserve evidence? Is it manual log extraction, database queries, or automated snapshots?
4. *Regulator Relationship*: Have you ever submitted an incident notification to INSA or EthioCERT? What was the format (email, portal, paper memo), and what challenges did you face?

### Section 3: Data Sovereignty, Cloud & Trust Boundaries (10 mins)
1. *Data Residency*: Under NBE directives and the Personal Data Protection Proclamation (1321/2024), what categories of telemetry are forbidden from leaving your physical premises or national boundary?
2. *Self-Hosting Requirement*: Would your risk and compliance committee approve an on-premise Linux/Docker deployment where customer data never leaves your infrastructure?
3. *Automated Response Hesitation*: If an automated engine detects an account takeover with 95% confidence, would you permit the system to automatically freeze the transaction, or must a human analyst click approve?
4. *Cross-Bank Threat Sharing*: Would your institution opt into an anonymous threat indicator exchange (sharing hashed IPs, device hashes, and mule account hashes with other Ethiopian banks) if it warned you minutes before a syndicate struck your accounts? What would make legal reject this?

### Section 4: Budget, Commercials & Willingness to Adopt (10 mins)
1. *Current Spend*: What does your organization typically pay annually for cybersecurity tooling or MSSP contracts?
2. *Value Anchor*: Which capability would offer the highest immediate ROI for you:
   - *Option A*: Automated 48-Hour Incident Dossier Generator for INSA/EthioCERT.
   - *Option B*: Real-time Transaction Fraud & ATO Engine (`ATO-001`).
   - *Option C*: Inter-bank Threat & Mule Account Signal Sharing.
3. *Deal Breakers*: What would make you immediately refuse to pilot or purchase a local cybersecurity platform like ECS? (e.g., vendor lock-in, fear of regulatory interference, licensing complexity, performance overhead).

---

## 4. Synthesis & Follow-up Actions
- Record verbatim pain statements in `docs/VALIDATION_REPORT.md`.
- Evaluate willingness to participate as one of the 3 design partners for Phase 1 and Phase 4 tabletop testing.
