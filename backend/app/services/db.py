from supabase import create_client, Client
from app.config import Config
import logging

logger = logging.getLogger(__name__)

_client: Client = None
_service_client: Client = None

def get_supabase() -> Client:
    """Get the public/anon Supabase client"""
    global _client
    if _client is None:
        if not Config.SUPABASE_URL or not Config.SUPABASE_KEY:
            raise ValueError("SUPABASE_URL and SUPABASE_KEY must be set")
        _client = create_client(Config.SUPABASE_URL, Config.SUPABASE_KEY)
    return _client

def get_service_supabase() -> Client:
    """Get the service-role client for privileged operations (audit, admin)"""
    global _service_client
    if _service_client is None:
        key = Config.SUPABASE_SERVICE_KEY or Config.SUPABASE_KEY
        if not Config.SUPABASE_URL or not key:
            raise ValueError("SUPABASE_URL and key must be set")
        _service_client = create_client(Config.SUPABASE_URL, key)
    return _service_client
