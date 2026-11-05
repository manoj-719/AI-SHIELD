-- =============================================================================
-- AI Shield Platform — Supabase PostgreSQL Schema Migration
-- Migration: 001_initial_schema.sql
-- Description: Creates core tables, foreign keys, check constraints, indexes,
--              and Row Level Security (RLS) policies for PostgreSQL on Supabase.
-- =============================================================================

-- 1. EMPLOYEES TABLE
CREATE TABLE IF NOT EXISTS public.employees (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    employee_id TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    email TEXT UNIQUE NOT NULL,
    department TEXT NOT NULL,
    role TEXT NOT NULL,
    risk_score NUMERIC(5,2) DEFAULT 0.00,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'under_investigation', 'terminated')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 2. SECURITY EVENTS TABLE (strictly follows docs/api_contract.md)
CREATE TABLE IF NOT EXISTS public.security_events (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    event_id TEXT UNIQUE NOT NULL,
    event_type TEXT NOT NULL,
    actor_type TEXT NOT NULL CHECK (actor_type IN ('employee', 'agent', 'external')),
    actor_id TEXT NOT NULL,
    resource TEXT NOT NULL,
    is_sensitive BOOLEAN NOT NULL DEFAULT FALSE,
    action TEXT NOT NULL,
    destination TEXT,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    source TEXT NOT NULL,
    description TEXT,
    rule_result TEXT,
    anomaly BOOLEAN,
    risk_score NUMERIC(5,2),
    risk_level TEXT CHECK (risk_level IS NULL OR risk_level IN ('low', 'medium', 'high', 'critical')),
    recommended_action TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 3. SECURITY INCIDENTS TABLE
CREATE TABLE IF NOT EXISTS public.security_incidents (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    incident_id TEXT UNIQUE NOT NULL,
    title TEXT NOT NULL,
    description TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'investigating', 'resolved', 'closed')),
    actor_id TEXT,
    event_id TEXT REFERENCES public.security_events(event_id) ON DELETE SET NULL,
    assigned_to TEXT,
    resolved_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 4. ALERTS TABLE
CREATE TABLE IF NOT EXISTS public.alerts (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    alert_id TEXT UNIQUE NOT NULL,
    event_id TEXT REFERENCES public.security_events(event_id) ON DELETE CASCADE,
    incident_id TEXT REFERENCES public.security_incidents(incident_id) ON DELETE SET NULL,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    message TEXT NOT NULL,
    is_read BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- 5. ACTIVITY LOGS TABLE
CREATE TABLE IF NOT EXISTS public.activity_logs (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    log_id TEXT UNIQUE NOT NULL,
    action TEXT NOT NULL,
    performed_by TEXT NOT NULL,
    details TEXT,
    ip_address TEXT,
    timestamp TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- PERFORMANCE & QUERY INDEXES
-- =============================================================================
CREATE INDEX IF NOT EXISTS idx_employees_employee_id ON public.employees(employee_id);
CREATE INDEX IF NOT EXISTS idx_employees_email ON public.employees(email);
CREATE INDEX IF NOT EXISTS idx_employees_department ON public.employees(department);

CREATE INDEX IF NOT EXISTS idx_events_event_id ON public.security_events(event_id);
CREATE INDEX IF NOT EXISTS idx_events_actor_id ON public.security_events(actor_id);
CREATE INDEX IF NOT EXISTS idx_events_event_type ON public.security_events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_timestamp ON public.security_events(timestamp DESC);

CREATE INDEX IF NOT EXISTS idx_incidents_incident_id ON public.security_incidents(incident_id);
CREATE INDEX IF NOT EXISTS idx_incidents_severity ON public.security_incidents(severity);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON public.security_incidents(status);

CREATE INDEX IF NOT EXISTS idx_alerts_alert_id ON public.alerts(alert_id);
CREATE INDEX IF NOT EXISTS idx_alerts_severity ON public.alerts(severity);
CREATE INDEX IF NOT EXISTS idx_alerts_is_read ON public.alerts(is_read);

CREATE INDEX IF NOT EXISTS idx_activity_logs_timestamp ON public.activity_logs(timestamp DESC);

-- =============================================================================
-- ROW LEVEL SECURITY (RLS) POLICIES
-- =============================================================================
ALTER TABLE public.employees ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.security_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.security_incidents ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.alerts ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.activity_logs ENABLE ROW LEVEL SECURITY;

-- Service role has full unrestricted access for backend operations
CREATE POLICY "Service role full access on employees" ON public.employees
    FOR ALL TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "Service role full access on security_events" ON public.security_events
    FOR ALL TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "Service role full access on security_incidents" ON public.security_incidents
    FOR ALL TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "Service role full access on alerts" ON public.alerts
    FOR ALL TO service_role USING (true) WITH CHECK (true);

CREATE POLICY "Service role full access on activity_logs" ON public.activity_logs
    FOR ALL TO service_role USING (true) WITH CHECK (true);
