"""
Supabase PostgreSQL Connectivity & Health Verification Script for AI Shield.
Run via: python backend/test_connection.py
"""

import sys
from pathlib import Path

# Ensure project root is in sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from backend.config import Config
from backend.database import get_supabase_client, check_supabase_connection

def test_supabase_connectivity():
    print("=" * 70)
    print("AI Shield - Supabase PostgreSQL Connectivity Diagnostic")
    print("=" * 70)

    # 1. Environment check
    print("\n1. Checking Environment Variables:")
    print(f"   SUPABASE_URL: {Config.SUPABASE_URL if Config.SUPABASE_URL else '<NOT SET>'}")
    if not Config.SUPABASE_SERVICE_ROLE_KEY:
        key_status = "<NOT SET>"
    elif not Config.is_supabase_configured():
        key_status = "<PLACEHOLDER - SECRET KEY REQUIRED>"
    else:
        key_status = "<CONFIGURED>"
    print(f"   SUPABASE_SERVICE_ROLE_KEY: {key_status}")

    if not Config.is_supabase_configured():
        print("\n[RESULT] [FAILED] SUPABASE CONFIGURATION INCOMPLETE")
        print("Please copy backend/.env.example to backend/.env and provide:")
        print("  - SUPABASE_URL")
        print("  - SUPABASE_SERVICE_ROLE_KEY")
        return False

    # 2. Connection check
    print("\n2. Testing Connection to Supabase:")
    is_connected, msg = check_supabase_connection()
    if not is_connected:
        print(f"   [RESULT] [FAILED] {msg}")
        return False
    print(f"   [RESULT] [SUCCESS] {msg}")

    # 3. Verifying Core Tables:
    print("\n3. Verifying Core Tables:")
    supabase = get_supabase_client()
    tables = ["employees", "security_events", "security_incidents", "alerts", "activity_logs"]
    all_ok = True

    for tbl in tables:
        try:
            res = supabase.table(tbl).select("count", count="exact").limit(0).execute()
            count = res.count if res.count is not None else 0
            print(f"   [OK] Table '{tbl}': Accessible (Current row count: {count})")
        except Exception as e:
            print(f"   [FAIL] Table '{tbl}': Error: {e}")
            all_ok = False

    if not all_ok:
        print("\n[RESULT] [WARNING] Some tables are missing. Please execute:")
        print("   backend/migrations/001_initial_schema.sql")
        print("in your Supabase Dashboard SQL Editor.")
        return False

    print("\n[RESULT] [SUCCESS] All checks passed! Supabase PostgreSQL is fully operational.")
    return True

if __name__ == "__main__":
    success = test_supabase_connectivity()
    sys.exit(0 if success else 1)
