import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SUPABASE_URL = os.getenv('SUPABASE_URL')
    SUPABASE_KEY = os.getenv('SUPABASE_KEY')
    SUPABASE_SERVICE_KEY = os.getenv('SUPABASE_SERVICE_KEY')
    DATABASE_URL = os.getenv('DATABASE_URL')
    REDIS_URL = os.getenv('REDIS_URL', 'redis://localhost:6379/0')
    ECS_MASTER_ENCRYPTION_KEY = os.getenv('ECS_MASTER_ENCRYPTION_KEY')
    JWT_SECRET = os.getenv('JWT_SECRET', 'dev-secret-change-me')
    JWT_EXPIRY_HOURS = 24
    BCRYPT_ROUNDS = 12
    PLATFORM_VERSION = '1.0.0'
