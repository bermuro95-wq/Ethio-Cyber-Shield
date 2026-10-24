"""
Multilingual Cybersecurity Terminology Service for Ethio-Cyber-Shield (ECS) v3.0 (Phase 7.4).
Provides localized cybersecurity and financial crime defense terminology across:
  - English ('en')
  - Amharic ('am', አማርኛ)
  - Afaan Oromo ('om', Afaan Oromoo)
Strictly adheres to Ethiopian banking, telecommunications, and regulatory contexts.
"""
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

SUPPORTED_LANGUAGES = [
    {'code': 'en', 'name': 'English', 'native_name': 'English', 'is_default': True},
    {'code': 'am', 'name': 'Amharic', 'native_name': 'አማርኛ', 'is_default': False},
    {'code': 'om', 'name': 'Afaan Oromo', 'native_name': 'Afaan Oromoo', 'is_default': False},
]

# Comprehensive domain-specific cybersecurity and fintech fraud terminology glossary
GLOSSARY: Dict[str, Dict[str, str]] = {
    'account_takeover': {
        'en': 'Account Takeover',
        'am': 'የሂሳብ ቁጥጥር ስርቆት',
        'om': 'Herrega Dhuunfaa Qabachuu'
    },
    'evidence_vault': {
        'en': 'Evidence Vault',
        'am': 'የማስረጃ ማከማቻ',
        'om': 'Kuusaa Ragaa'
    },
    'statutory_48h_notification': {
        'en': 'Statutory 48-Hour Notification',
        'am': 'የህግ 48-ሰዓት ማሳወቂያ',
        'om': "Beeksisa Sa'aatii 48 Seeraa"
    },
    'incident_containment': {
        'en': 'Incident Containment',
        'am': 'የጥቃት መቆጣጠርያ',
        'om': "Miidhaa To'achuu"
    },
    'suspicious_transaction': {
        'en': 'Suspicious Transaction',
        'am': 'አጠራጣሪ የገንዘብ ዝውውር',
        'om': 'Daddabarsa Shakkiisaa'
    },
    'emergency_kill_switch': {
        'en': 'Emergency Kill Switch',
        'am': 'የአደጋ ጊዜ ድንገተኛ ማቆሚያ',
        'om': 'Cufaa Balaa Hatattamaa'
    },
    'community_signal_exchange': {
        'en': 'Community Signal Exchange',
        'am': 'የህብረተሰብ መረጃ ልውውጥ',
        'om': 'Jijjiirraa Mallattoo Hawaasaa'
    },
    'safe_automation_mode': {
        'en': 'Safe Automation Mode',
        'am': 'አስተማማኝ ራስ-ሰር ምላሽ',
        'om': 'Hojiirra Oolmaa Of-Harkaa Nageenyaa'
    },
    'false_positive_rate': {
        'en': 'False Positive Rate',
        'am': 'የስህተት ማስጠንቀቂያ መጠን',
        'om': 'Reeshioo Akeekkachiisa Dogoggoraa'
    },
    'post_incident_review': {
        'en': 'Post-Incident Review',
        'am': 'የድህረ-ጥቃት ግምገማ',
        'om': 'Gamaaggama Booda Miidhaa'
    },
    'mule_account': {
        'en': 'Mule Account',
        'am': 'የመሸጋገሪያ ሂሳብ',
        'om': 'Herrega Dabarsituu'
    },
    'structuring_burst': {
        'en': 'Structuring / Smurfing',
        'am': 'የተከፋፈለ የገንዘብ ዝውውር',
        'om': 'Daddabarsa Qoodamee Raawwatamu'
    },
    'sim_swap_fraud': {
        'en': 'SIM Swap Fraud',
        'am': 'የሲም ካርድ ቅያሪ ማጭበርበር',
        'om': 'Hanna Jijjiirraa Kaardii SIM'
    },
    'brute_force_login': {
        'en': 'Brute Force Login',
        'am': 'ተደጋጋሚ የማስገደድ ሙከራ',
        'om': 'Yaalii Seensaa Dirqisiisaa'
    },
    'denial_of_service': {
        'en': 'Denial of Service',
        'am': 'አገልግሎት የማስተጓጎል ጥቃት',
        'om': 'Tajaajila Dhowwachuu'
    },
    'critical_severity': {
        'en': 'Critical Severity',
        'am': 'እጅግ አሳሳቢ ክብደት',
        'om': 'Sadarkaa Cimaa'
    },
    'high_severity': {
        'en': 'High Severity',
        'am': 'ከፍተኛ ክብደት',
        'om': 'Sadarkaa Olaanaa'
    },
    'medium_severity': {
        'en': 'Medium Severity',
        'am': 'መካከለኛ ክብደት',
        'om': 'Sadarkaa Giddu-galeessaa'
    },
    'low_severity': {
        'en': 'Low Severity',
        'am': 'ዝቅተኛ ክብደት',
        'om': 'Sadarkaa Gadi-aanaa'
    },
    'status_open': {
        'en': 'Open',
        'am': 'ክፍት',
        'om': 'Banaa'
    },
    'status_investigating': {
        'en': 'Under Investigation',
        'am': 'በምርመራ ላይ',
        'om': 'Qorannoo Jalatti'
    },
    'status_contained': {
        'en': 'Contained',
        'am': 'ቁጥጥር ስር የዋለ',
        'om': "Kan To'annoo Jala Oole"
    },
    'status_resolved': {
        'en': 'Resolved',
        'am': 'የተፈታ',
        'om': 'Kan Furiinsa Argate'
    },
    'sla_on_track': {
        'en': 'On Track',
        'am': 'በእቅዱ መሰረት',
        'om': 'Akka Karooratti'
    },
    'sla_at_risk': {
        'en': 'At Risk',
        'am': 'ስጋት ላይ',
        'om': 'Sodaa Jalatti'
    },
    'sla_breached': {
        'en': 'Breached',
        'am': 'የተጣሰ',
        'om': 'Kan Cabee'
    },
    'regulatory_authority': {
        'en': 'Information Network Security Administration (INSA)',
        'am': 'የኢንፎርሜሽን መረብ ደህንነት አስተዳደር (ኢመደአ)',
        'om': 'Bulchiinsa Nageenya Neetwoorkii Odeeffannoo (INSA)'
    },
    'central_bank': {
        'en': 'National Bank of Ethiopia (NBE)',
        'am': 'የኢትዮጵያ ብሔራዊ ባንክ',
        'om': 'Baankii Biyyooleessaa Itoophiyaa'
    }
}


class I18nService:
    """Cybersecurity localization service for English, Amharic, and Afaan Oromo."""

    @classmethod
    def list_languages(cls) -> List[Dict[str, Any]]:
        """Returns list of supported languages with codes and native display names."""
        return list(SUPPORTED_LANGUAGES)

    @classmethod
    def get_translations(cls, lang: str = 'en') -> Dict[str, str]:
        """Returns the full translation dictionary for a specific language."""
        target_lang = str(lang).lower().strip()
        if target_lang not in ('en', 'am', 'om'):
            target_lang = 'en'

        return {k: v.get(target_lang, v['en']) for k, v in GLOSSARY.items()}

    @classmethod
    def translate(cls, term_key: str, lang: str = 'en', default: Optional[str] = None) -> str:
        """Translates a specific terminology key into the requested language."""
        target_lang = str(lang).lower().strip()
        if target_lang not in ('en', 'am', 'om'):
            target_lang = 'en'

        entry = GLOSSARY.get(term_key.lower().strip())
        if entry:
            return entry.get(target_lang, entry['en'])

        return default if default is not None else term_key

    @classmethod
    def localize_incident_summary(
        cls,
        incident_type: str,
        severity: str,
        status: str,
        lang: str = 'en'
    ) -> Dict[str, str]:
        """Provides a localized summary object for incident status cards."""
        return {
            'language': lang,
            'incident_type': cls.translate(incident_type, lang=lang, default=incident_type),
            'severity': cls.translate(f"{severity.lower()}_severity", lang=lang, default=severity),
            'status': cls.translate(f"status_{status.lower()}", lang=lang, default=status)
        }
