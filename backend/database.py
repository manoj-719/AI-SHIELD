import os
import sys
from typing import Optional, Tuple
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

import supabase
from supabase import Client, create_client
from backend.config import Config

# Reusable client singleton
_supabase_client: Optional[Client] = None

def get_supabase_client() -> Client:
    """
    Return an initialized Supabase client singleton using the service role key.
    Raises RuntimeError if Supabase credentials are missing or unconfigured.
    """
    global _supabase_client
    if _supabase_client is not None:
        return _supabase_client

    if not Config.is_supabase_configured():
        raise RuntimeError(
            "Supabase credentials are not configured. Please set SUPABASE_URL "
            "and SUPABASE_SERVICE_ROLE_KEY in backend/.env"
        )

    _supabase_client = create_client(Config.SUPABASE_URL, Config.SUPABASE_SERVICE_ROLE_KEY)
    return _supabase_client

def set_supabase_client(client: Optional[Client]):
    """Inject a client instance (used for testing and dependency injection)."""
    global _supabase_client
    _supabase_client = client

def reset_supabase_client():
    """Reset the cached client instance."""
    global _supabase_client
    _supabase_client = None

def check_supabase_connection() -> Tuple[bool, str]:
    """
    Test actual connectivity to the Supabase PostgreSQL database.
    Performs a lightweight query to verify connectivity and schema presence.
    Returns: (is_connected: bool, message: str)
    """
    if not Config.is_supabase_configured():
        return False, "SUPABASE_CONFIG_REQUIRED: Missing or placeholder SUPABASE_URL or SUPABASE_SERVICE_ROLE_KEY in .env"

    try:
        client = get_supabase_client()
        # Verify connectivity by performing a count query on the employees table
        response = client.table("employees").select("count", count="exact").limit(0).execute()
        return True, f"Successfully connected to Supabase PostgreSQL at {Config.SUPABASE_URL}"
    except Exception as e:
        err_msg = str(e)
        if "relation \"public.employees\" does not exist" in err_msg or "PGRST204" in err_msg:
            return False, "Connected to Supabase, but schema not found. Please execute backend/migrations/001_initial_schema.sql in Supabase SQL Editor."
        return False, f"Supabase connection error: {err_msg}"
