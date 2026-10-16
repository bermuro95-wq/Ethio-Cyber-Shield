# Ethio-Cyber-Shield (ECS) — 48-Hour Incident Report Fallback Specification

> **Document Type**: Incident Reporting Fallback Standard & Data Schema  
> **Status**: Approved Fallback Standard (Phase 0 Deliverable)  
> **Applicable Mandate**: Proclamation No. 1426/2026 (Critical Infrastructure Cybersecurity)  
> **Reporting Authority**: National Computer Emergency Response Center (EthioCERT / INSA)  

---

## 1. Scope & Objective

Proclamation No. 1426/2026 mandates that critical infrastructure operators in Ethiopia (including banking, payment systems, telecommunications, and energy) must submit a formal incident report to the National CERT within **48 hours of initial incident detection**.

Because INSA has not published a machine-readable JSON schema or public web-hook contract for automatic submissions, this document establishes the **ECS Fallback Incident Report Standard (ECS-IRS-v1.0)**. 

This standard serves three purposes:
1. Provides a rigorous, structured internal format to capture all technical evidence, chronologies, indicators, and mitigation actions during an active incident.
2. Automatically generates a formal **Bilingual (English & Amharic) PDF Dossier** suitable for physical or email submission to EthioCERT.
3. Automatically generates a **Machine-Readable JSON Package with a SHA-256 cryptographic manifest** to support independent regulatory audits.

---

## 2. Standard Schema Definition (`incident_report_v1.0.json`)

```json
{
  "$schema": "https://json-schema.org/draft/2020-12/schema",
  "title": "ECS Incident Report Package (Proclamation 1426/2026)",
  "type": "object",
  "required": [
    "report_id",
    "organization_profile",
    "statutory_timeline",
    "incident_classification",
    "technical_summary",
    "impact_assessment",
    "indicators_of_compromise",
    "containment_and_remediation",
    "evidence_manifest",
    "attestation"
  ],
  "properties": {
    "report_id": {
      "type": "string",
      "description": "Unique report reference, format: ECS-REP-YYYYMMDD-<short_id>"
    },
    "organization_profile": {
      "type": "object",
      "required": ["organization_id", "legal_name", "sector", "license_ref", "contact_ciso"],
      "properties": {
        "organization_id": { "type": "string", "format": "uuid" },
        "legal_name": { "type": "string" },
        "sector": { 
          "type": "string", 
          "enum": ["Finance - Commercial Bank", "Finance - Microfinance", "Finance - Payment System Operator", "Telecommunications", "Energy & Utilities", "Other Critical Infrastructure"] 
        },
        "license_ref": { "type": "string", "description": "NBE or regulatory license registration number" },
        "contact_ciso": {
          "type": "object",
          "properties": {
            "name": { "type": "string" },
            "title": { "type": "string" },
            "phone_et": { "type": "string", "pattern": "^\\+251[0-9]{9}$" },
            "email": { "type": "string", "format": "email" }
          }
        }
      }
    },
    "statutory_timeline": {
      "type": "object",
      "required": ["earliest_activity_at", "detection_at", "report_generation_at", "elapsed_hours_since_detection", "statutory_deadline_at", "is_within_48h_limit"],
      "properties": {
        "earliest_activity_at": { "type": "string", "format": "date-time" },
        "detection_at": { "type": "string", "format": "date-time", "description": "Timestamp when automated detection or analyst flagged incident" },
        "report_generation_at": { "type": "string", "format": "date-time" },
        "elapsed_hours_since_detection": { "type": "number" },
        "statutory_deadline_at": { "type": "string", "format": "date-time", "description": "Detection time + exactly 48 hours" },
        "is_within_48h_limit": { "type": "boolean" }
      }
    },
    "incident_classification": {
      "type": "object",
      "required": ["incident_type", "severity", "attack_vector", "mitre_attack_techniques"],
      "properties": {
        "incident_type": { 
          "type": "string", 
          "enum": ["account_takeover", "transaction_fraud", "credential_stuffing", "mule_network_transfer", "privilege_abuse", "unauthorized_api_probe", "ransomware", "ddos"] 
        },
        "severity": { "type": "string", "enum": ["low", "medium", "high", "critical"] },
        "attack_vector": { "type": "string" },
        "mitre_attack_techniques": {
          "type": "array",
          "items": { "type": "string" }
        }
      }
    },
    "technical_summary": {
      "type": "object",
      "required": ["title", "executive_summary_en", "executive_summary_am", "root_cause_analysis"],
      "properties": {
        "title": { "type": "string" },
        "executive_summary_en": { "type": "string" },
        "executive_summary_am": { "type": "string", "description": "Amharic language summary for official INSA submission" },
        "root_cause_analysis": { "type": "string" },
        "affected_systems": {
          "type": "array",
          "items": { "type": "string" }
        }
      }
    },
    "impact_assessment": {
      "type": "object",
      "required": ["customer_accounts_affected", "financial_exposure_etb", "data_breach_involved", "service_downtime_minutes"],
      "properties": {
        "customer_accounts_affected": { "type": "integer" },
        "financial_exposure_etb": { "type": "number", "description": "Total ETB volume flagged or exposed" },
        "financial_loss_prevented_etb": { "type": "number", "description": "Total ETB volume preserved through automated holds" },
        "data_breach_involved": { "type": "boolean" },
        "service_downtime_minutes": { "type": "integer" }
      }
    },
    "indicators_of_compromise": {
      "type": "array",
      "items": {
        "type": "object",
        "required": ["type", "value", "confidence", "first_seen"],
        "properties": {
          "type": { "type": "string", "enum": ["ip", "domain", "device_fingerprint", "msisdn_hash", "beneficiary_account_hash"] },
          "value": { "type": "string" },
          "confidence": { "type": "string", "enum": ["medium", "high", "confirmed"] },
          "first_seen": { "type": "string", "format": "date-time" }
        }
      }
    },
    "containment_and_remediation": {
      "type": "object",
      "required": ["containment_status", "actions_dispatched"],
      "properties": {
        "containment_status": { "type": "string", "enum": ["in_progress", "contained", "eradicated", "post_incident_monitoring"] },
        "actions_dispatched": {
          "type": "array",
          "items": {
            "type": "object",
            "properties": {
              "action_type": { "type": "string" },
              "target_entity": { "type": "string" },
              "dispatched_at": { "type": "string", "format": "date-time" },
              "status": { "type": "string" },
              "reversible": { "type": "boolean" }
            }
          }
        }
      }
    },
    "evidence_manifest": {
      "type": "object",
      "required": ["telemetry_event_count", "telemetry_sha256_digest", "audit_trail_sha256_digest", "bundle_signature"],
      "properties": {
        "telemetry_event_count": { "type": "integer" },
        "telemetry_sha256_digest": { "type": "string", "description": "Hex-encoded SHA-256 hash of ordered raw events in incident scope" },
        "audit_trail_sha256_digest": { "type": "string", "description": "Hex-encoded SHA-256 hash of associated audit log records" },
        "bundle_signature": { "type": "string", "description": "HMAC-SHA256 signature generated using tenant key" }
      }
    },
    "attestation": {
      "type": "object",
      "required": ["certifying_officer_name", "certifying_officer_role", "declaration_text", "signed_at"],
      "properties": {
        "certifying_officer_name": { "type": "string" },
        "certifying_officer_role": { "type": "string" },
        "declaration_text": { 
          "type": "string", 
          "default": "I hereby certify under penalty of administrative sanctions pursuant to Proclamation No. 1426/2026 that the technical details, telemetry digests, and containment measures detailed in this package are accurate to the best of my knowledge." 
        },
        "signed_at": { "type": "string", "format": "date-time" }
      }
    }
  }
}
```

---

## 3. Bilingual Document Presentation Standard

For official EthioCERT submission, the PDF dossier contains:
1. **Header**: State emblem placeholder, Institutional Letterhead, and Report Reference (`ECS-REP-YYYYMMDD-XXXX`).
2. **Statutory Time Box**:
   - Detection Time (`Africa/Addis_Ababa` timezone).
   - Time Elapsed: e.g., *"14 Hours 22 Minutes (Within statutory 48h requirement)"*.
   - Remaining Window Countdown.
3. **Executive Summary (English)**: Clear narrative of attack mechanics and mitigation.
4. **Executive Summary (Amharic - የአደጋው ማጠቃለያ)**:
   - Example template:
     > **የሳይበር ደህንነት ክስተት ሪፖርት (በአዋጅ ቁጥር 1426/2026 መሰረት)**  
     > ይህ ሪፖርት የተዘጋጀው በ[የተቋሙ ስም] ላይ የተከሰተውን የ[የክስተቱ አይነት] ለመግለጽ ነው። ክስተቱ በ[ቀን እና ሰዓት] በራስ-ሰር የመከላከያ ስርዓቱ የተገኘ ሲሆን፣ አጠራጣሪ እንቅስቃሴው ወዲያውኑ እንዲገታ ተደርጓል። የተጎዱ የደንበኛ ሂሳቦች ቁጥር [ቁጥር] ሲሆን፣ [የገንዘብ መጠን] የኢትዮጵያ ብር እንዳይዘረፍ በጊዜው ታግዷል።
5. **Technical Findings & IOC Table**: Listing matched indicators, source IPs, and device fingerprints.
6. **Audit & Evidence Hash Digest**: Immutable SHA-256 seal enabling EthioCERT auditors to verify that submitted evidence was not altered post-incident.
