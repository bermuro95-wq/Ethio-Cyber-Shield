# Ethio-Cyber-Shield (ECS) — Community Signal Exchange Governance Charter & Privacy Impact Assessment (PIA)

> **Institutional Submission**: Official Federated Intelligence Specification submitted to the **Information Network Security Administration (INSA)**, Federal Democratic Republic of Ethiopia.  
> **Project Research Consortium**: Musab Hassen Aliyi (`CTC-384-26`), Osman Mohammed Seid (`CTC-2974-26`), Kedist Eyasu Embaye (`CTC-1247-26`), Yoseph Abebe Ersedo (`CTC-430-26`), Omer Mohammed Seid (`CTC-3716-26`), Efrem Mola Genebo (`CTC-4772-26`).  
> **Document Version**: v1.0 (Phase 6 Deliverable)  
> **Platform Version**: ECS v3.0 Independent Defense  
> **Official Monorepo**: [https://github.com/Rammiso/ethio-cybershield](https://github.com/Rammiso/ethio-cybershield)  
> **Scope**: Cross-Tenant Federated Threat Intelligence Exchange for Ethiopian Digital Finance & Critical Infrastructure  
> **Target Audience**: CISOs, Compliance Officers, Legal Counsel, EthioCERT / INSA Observers

---

## 1. Executive Purpose & Governance Principles

The **Ethio-Cyber-Shield Community Defense Network** enables Ethiopian financial institutions, payment operators, telecommunication providers, and critical infrastructure operators to collaborate against coordinated cyber attacks (account takeover syndicates, mule networks, credential stuffing campaigns) without compromising customer privacy or competitive proprietary data.

### Core Governance Principles:
1. **Privacy-Preserving by Design**: Raw PII (customer names, plaintext account numbers, unmasked phone numbers, account balances) is **NEVER** shared across organizations. Customer identifiers are keyed-hashed using a secure hub salt (`HUB_PEPPER`) before egress.
2. **Strict Opt-In Participation**: Every institution maintains explicit granular control over whether they contribute signals and which TLP levels they participate in.
3. **Anti-Poisoning by Default**: No single community signal can automatically trigger disruptive containment actions. Containment requires corroboration ($N \ge 2$ independent institutions) or local human-in-the-loop analyst approval.
4. **Transparent Retraction & Dispute Resolution**: Any participant can retract erroneously submitted signals, with automated network-wide deprecation and reputation adjustments.

---

## 2. Traffic Light Protocol (TLP) Policy

ECS enforces the international FIRST Standards TLP v2.0 classification:

| TLP Marking | Sharing Boundary | Permitted Propagation | ECS Handling |
| :--- | :--- | :--- | :--- |
| **TLP:CLEAR / WHITE** | Public Community | Entire Ethiopian digital ecosystem & public advisories. | Freely distributed in community feed and EthioCERT STIX bundles. |
| **TLP:GREEN** | Consortium Members | Authorized ECS community participants only. | Shared with peer institutions that have opted into exchange. |
| **TLP:AMBER** | Sector-Restricted | Strictly within participant's sector (e.g., Commercial Banks only). | Filtered by tenant sector profile; excluded from other sectors. |
| **TLP:RED** | Organization Strictly Local | **STRICTLY LOCAL** to reporting organization. | **REJECTED from hub egress.** Local to reporting tenant only. |

---

## 3. Data-Handling Charter: What is Shared vs. What is Never Shared

```
┌────────────────────────────────────────────────────────┐
│                   LOCAL TENANT REPOSITORY              │
│  • Account: 100001234567       • Amount: 250,000 ETB   │
│  • Customer: Almaz Ayana       • Plaintext Logs        │
└──────────────────────────┬─────────────────────────────┘
                           │
             [Privacy-Preserving Keyed Hash]
                           │
                           ▼
┌────────────────────────────────────────────────────────┐
│             COMMUNITY SIGNAL EXCHANGE (HUB)            │
│  SHARED:                                               │
│  • IP: 196.188.10.45 (Network Observable)              │
│  • Keyed Hash: hash:v1:7a8b9c... (Mule Account Hash)   │
│  • Threat Category: mule_network                       │
│  • Confidence: 0.85                                    │
│  • TLP: GREEN                                          │
│                                                        │
│  NEVER SHARED:                                         │
│  ❌ Customer PII, Names, Passwords                     │
│  ❌ Plaintext Account Numbers                          │
│  ❌ Bank Balances or Transaction Amounts               │
└────────────────────────────────────────────────────────┘
```

---

## 4. Anti-Poisoning & Corroboration Engine

To prevent malicious actors, compromised credentials, or configuration mistakes from polluting the community feed ("signal poisoning"):

1. **Reporter Reputation Scoring**:
   - Each participating tenant starts at baseline reputation score of `0.50` (on a `0.00` to `1.00` scale).
   - Valid, corroborated signals increment score by `+0.05` (up to `1.00`).
   - Retracted false signals penalize score by `-0.20`.
2. **Corroboration Threshold ($N \ge 2$)**:
   - A signal reported by only one institution is marked **Uncorroborated Advisory** (`is_corroborated: false`).
   - A signal reported by two or more independent licensed institutions is marked **Corroborated Threat** (`is_corroborated: true`).
3. **Safe Automation Guardrail**:
   - **Uncorroborated signals produce only advisory alerts (`IOC-COMMUNITY-ADVISORY`) with reduced risk weight (15 pts). They NEVER trigger automated blocking.**
   - Only corroborated signals or locally approved policies are eligible for automated transaction freezes or IP blocks.

---

## 5. Privacy Impact Assessment (PIA)

### Assessment Findings:
1. **PII Minimization**: The platform strictly complies with Article 32 of Personal Data Protection Proclamation No. 1321/2024.
2. **Keyed Hashing Security**: Identifiers are transformed using HMAC-SHA256 with an offline hub salt. Rainbow table attacks on Ethiopian 12-digit account numbers and 10-digit MSISDNs are mathematically unfeasible without the hub key.
3. **Anonymized Egress**: Community feeds replace reporting organization IDs with randomized peer handles (`PEER-1`, `PEER-2`), preventing institutional targeting or competitive intelligence leakage.
4. **Data Retention & Expiry**: All community signals feature a strict Time-to-Live (TTL default 168 hours / 7 days). Expired indicators are purged from active matching.

---

## 6. EthioCERT & Regulatory Harmonization

ECS provides automated STIX 2.1 JSON export for national regulatory coordination:
- Complies with OASIS STIX 2.1 indicator format.
- Fully compatible with EthioCERT MISP, OpenCTI, and INSA threat repositories.
- Allows rapid bi-directional ingestion of national advisories without custom format converters.
