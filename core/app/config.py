import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SUPABASE_URL = os.getenv('SUPABASE_URL')
    SUPABASE_KEY = os.getenv('SUPABASE_KEY')
    SUPABASE_SERVICE_KEY = os.getenv('SUPABASE_SERVICE_KEY')
    JWT_SECRET = os.getenv('JWT_SECRET', 'dev-secret-change-me')
    JWT_EXPIRY_HOURS = 24
    BCRYPT_ROUNDS = 12
