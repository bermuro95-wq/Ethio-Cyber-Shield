"""
Explainable Narrative & Multilingual Summary Service for Ethio-Cyber-Shield (ECS) v3.0 (Phase 8.1).
Adheres strictly to Core Principle #1:
  - Explainable by default: Deterministic logic makes decisions; LLM/NLP is strictly advisory/explanatory.
  - Privacy-preserving: Sensitive customer PII is scrubbed before narrative generation.
Generates structured incident narratives, timeline chronologies, and remediation debriefs across:
  - English ('en')
  - Amharic ('am', አማርኛ)
  - Afaan Oromo ('om', Afaan Oromoo)
Strictly partitioned by organization_id UUID NOT NULL.
"""
import logging
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from app.services.db import get_service_supabase
from app.services.tenant_service import get_current_organization_id
from app.services.case_service import CaseService
from app.services.readiness_service import ReadinessService
from app.services.notification_service import redact_sensitive_payload
from app.services.i18n_service import I18nService

logger = logging.getLogger(__name__)

# In-memory store for generated narratives for unit testing & fast retrieval
_LOCAL_NARRATIVES: Dict[str, Dict[str, Any]] = {}


def clear_narrative_caches() -> None:
    """Resets narrative cache for test isolation."""
    _LOCAL_NARRATIVES.clear()


class NarrativeService:
    """Generates explainable, multilingual incident narrative reports."""

    @classmethod
    def generate_incident_narrative(
        cls,
        org_id: str,
        incident_id: str,
        lang: str = 'en',
        include_technical_details: bool = True
    ) -> Dict[str, Any]:
        """
        Generates an explainable narrative summary for a given incident.
        Uses deterministic timeline evidence, rule activations, and safe response actions.
        """
        oid = str(org_id).strip()
        iid = str(incident_id).strip()
        target_lang = str(lang).lower().strip()
        if target_lang not in ('en', 'am', 'om'):
            target_lang = 'en'

        # 1. Fetch incident case
        incident = CaseService.get_case(oid, iid)
        if not incident:
            raise ValueError(f"Incident {iid} not found for organization {oid}")

        # 2. Scrub sensitive data
        safe_incident = redact_sensitive_payload(incident)

        # 3. Gather timeline, SLA, and statutory status
        sla_status = CaseService.calculate_sla_status(incident)
        clock = ReadinessService.calculate_48h_clock(incident) if incident.get('is_reportable_48h') else None

        # Incident properties
        title = safe_incident.get('title') or safe_incident.get('description') or f"Incident {iid}"
        inc_type = safe_incident.get('incident_type', 'cyber_security_anomaly')
        severity = safe_incident.get('severity', 'medium')
        status = safe_incident.get('status', 'open')
        det_date = safe_incident.get('detection_date') or safe_incident.get('created_at') or 'Unknown'
        impact_etb = float(safe_incident.get('financial_impact_etb') or 0.0)

        # 4. Generate Localized Narrative Text
        if target_lang == 'am':
            narrative = cls._build_amharic_narrative(
                title, inc_type, severity, status, det_date, impact_etb, sla_status, clock
            )
        elif target_lang == 'om':
            narrative = cls._build_oromo_narrative(
                title, inc_type, severity, status, det_date, impact_etb, sla_status, clock
            )
        else:
            narrative = cls._build_english_narrative(
                title, inc_type, severity, status, det_date, impact_etb, sla_status, clock
            )

        narrative_record = {
            'incident_id': iid,
            'organization_id': oid,
            'language': target_lang,
            'generated_at': datetime.now(timezone.utc).isoformat(),
            'model_type': 'deterministic_explainable_narrative',
            'advisory_only': True,
            'content': narrative,
            'evidence_metrics': {
                'severity': severity,
                'status': status,
                'financial_impact_etb': impact_etb,
                'is_reportable_48h': bool(incident.get('is_reportable_48h')),
                'sla_health': sla_status.get('overall_health', 'on_track')
            }
        }

        # Cache locally
        cache_key = f"{iid}:{target_lang}"
        _LOCAL_NARRATIVES[cache_key] = narrative_record

        return narrative_record

    @classmethod
    def get_narrative(cls, org_id: str, incident_id: str, lang: str = 'en') -> Optional[Dict[str, Any]]:
        """Retrieves cached narrative if available."""
        oid = str(org_id).strip()
        iid = str(incident_id).strip()
        target_lang = str(lang).lower().strip()
        cache_key = f"{iid}:{target_lang}"

        if cache_key in _LOCAL_NARRATIVES:
            rec = _LOCAL_NARRATIVES[cache_key]
            if str(rec.get('organization_id')) == oid:
                return dict(rec)

        return None

    # =========================================================================
    # MULTILINGUAL NARRATIVE GENERATORS
    # =========================================================================

    @classmethod
    def _build_english_narrative(cls, title, inc_type, severity, status, det_date, impact_etb, sla, clock) -> Dict[str, str]:
        loc_type = I18nService.translate(inc_type, 'en', default=inc_type)
        return {
            'executive_summary': (
                f"On {det_date}, ECS detected a {severity.upper()} severity incident categorized as {loc_type}. "
                f"The incident is currently in '{status.upper()}' status. "
                f"Financial exposure of ETB {impact_etb:,.2f} was evaluated and contained under safe response guardrails."
            ),
            'root_cause_analysis': (
                f"Behavioral pattern anomalies and signature correlation matched deterministic indicators for {loc_type}. "
                "Detection rules triggered bounded automated recommendations without unverified destructive actions."
            ),
            'statutory_status': (
                f"Incident 48-Hour statutory clock status: {clock['clock_stage'].upper()} "
                f"with {clock.get('remaining_hours', 0)}h remaining before regulatory deadline."
                if clock else "Not classified as a statutory reportable incident under INSA Proclamation No. 1426/2026."
            ),
            'remediation_advice': (
                "1. Maintain analyst monitoring over flagged counterpart accounts. "
                "2. Conduct peer review before releasing temporary account or IP holds. "
                "3. Ensure Post-Incident Review (PIR) is hash-sealed upon final resolution."
            )
        }

    @classmethod
    def _build_amharic_narrative(cls, title, inc_type, severity, status, det_date, impact_etb, sla, clock) -> Dict[str, str]:
        loc_type = I18nService.translate(inc_type, 'am', default=inc_type)
        loc_sev = I18nService.translate(f"{severity}_severity", 'am', default=severity)
        loc_stat = I18nService.translate(f"status_{status}", 'am', default=status)
        return {
            'executive_summary': (
                f"በ {det_date} ላይ የኢትዮ-ሳይበር-ሺልድ መድረክ {loc_sev} የሆነ የ {loc_type} ጥቃት አግኝቷል። "
                f"የጉዳዩ ወቅታዊ ሁኔታ '{loc_stat}' ላይ ይገኛል። "
                f"በአጠቃላይ የብር {impact_etb:,.2f} ETB ተጋላጭነት በአስተማማኝ ራስ-ሰር ምላሽ ቁጥጥር ስር ውሏል።"
            ),
            'root_cause_analysis': (
                f"የስርዓቱ ክትትል የባህሪ ለውጦችን እና አጠራጣሪ እንቅስቃሴዎችን በማነፃፀር ለ {loc_type} የተመዘገቡ ህጎችን አረጋግጧል። "
                "የደህንነት ቁጥጥሮች ስጋቱን ያለተጨማሪ ጉዳት ገድበውታል።"
            ),
            'statutory_status': (
                f"በኢንፎርሜሽን መረብ ደህንነት አስተዳደር (ኢመደአ) አዋጅ ቁጥር 1426/2026 መሰረት የ 48-ሰዓት የህግ ማሳወቂያ ሰዓት: "
                f"{clock['clock_stage']} ደረጃ ላይ ሲሆን {clock.get('remaining_hours', 0)} ሰዓታት ቀርተዋል።"
                if clock else "በአዋጅ ቁጥር 1426/2026 መሰረት ሪፖርት የሚደረግበት መስፈርት አላሟላም።"
            ),
            'remediation_advice': (
                "1. አጠራጣሪ የሂሳብ ቁጥሮች እና አይፒዎችን በቅርበት ይከታተሉ። "
                "2. ጊዜያዊ እገዳዎችን ከማንሳትዎ በፊት የሁለተኛ ወገን ማረጋገጫ ያግኙ። "
                "3. ጥቃቱ እንደተፈታ የድህረ-ጥቃት ግምገማ (PIR) በምስጠራ ማህተም ያረጋግጡ።"
            )
        }

    @classmethod
    def _build_oromo_narrative(cls, title, inc_type, severity, status, det_date, impact_etb, sla, clock) -> Dict[str, str]:
        loc_type = I18nService.translate(inc_type, 'om', default=inc_type)
        loc_sev = I18nService.translate(f"{severity}_severity", 'om', default=severity)
        loc_stat = I18nService.translate(f"status_{status}", 'om', default=status)
        return {
            'executive_summary': (
                f"Guyyaa {det_date} tti sirni ECS miidhaa {loc_sev} kan ta'e {loc_type} adda baasee jira. "
                f"Haalli amma irra jiru '{loc_stat}' dha. "
                f"Qabeenyi Birrii {impact_etb:,.2f} ETB qabamee nageenyi isaa mirkanaa'eera."
            ),
            'root_cause_analysis': (
                f"Amalli sochiilee fi mallattooleen {loc_type} wajjin walsiman qorannoo sirnaatiin mirkanaa'aniiru. "
                "Tarkaanfiiwwan of-harkaa nageenyaan gargaaramuun to'atameera."
            ),
            'statutory_status': (
                f"Akka Labsii INSA Lak. 1426/2026 tti sa'aatii 48 beeksisaa: "
                f"Sadarkaa {clock['clock_stage']} irra jira; sa'aatiin hafe {clock.get('remaining_hours', 0)} dha."
                if clock else "Labsii Lak. 1426/2026 jalatti kan hin gabaafamne."
            ),
            'remediation_advice': (
                "1. Herregawwan shakkiisaa fi teessoo IP hordofaa. "
                "2. Cufaa yeroo kaasuu dura qorannoo lammaffaa gaggeessaa. "
                "3. Rakkoon erga furamee booda gamaaggama booda miidhaa (PIR) mirkaneessaa."
            )
        }
