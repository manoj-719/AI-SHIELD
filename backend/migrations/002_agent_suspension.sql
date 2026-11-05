-- =============================================================================
-- AI Shield Platform — Supabase PostgreSQL Schema Migration
-- Migration: 002_agent_suspension.sql
-- Description: Creates the ai_agents table to persist AI agent status, suspension
--              records, violation counts, and security boundary policies.
-- =============================================================================

CREATE TABLE IF NOT EXISTS public.ai_agents (
    id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    agent_name TEXT UNIQUE NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'suspended', 'revoked')),
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    violation_count INTEGER NOT NULL DEFAULT 0,
    violation_history JSONB DEFAULT '[]'::jsonb,
    suspended_at TIMESTAMPTZ,
    suspension_reason TEXT,
    allowed_files JSONB DEFAULT '[]'::jsonb,
    allowed_actions JSONB DEFAULT '[]'::jsonb,
    allowed_destinations JSONB DEFAULT '[]'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- =============================================================================
-- PERFORMANCE & QUERY INDEXES
-- =============================================================================
CREATE INDEX IF NOT EXISTS idx_ai_agents_agent_name ON public.ai_agents(agent_name);
CREATE INDEX IF NOT EXISTS idx_ai_agents_status ON public.ai_agents(status);
CREATE INDEX IF NOT EXISTS idx_ai_agents_is_active ON public.ai_agents(is_active);

-- =============================================================================
-- ROW LEVEL SECURITY (RLS) POLICIES
-- =============================================================================
ALTER TABLE public.ai_agents ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS "Service role full access on ai_agents" ON public.ai_agents;
CREATE POLICY "Service role full access on ai_agents" ON public.ai_agents
    FOR ALL TO service_role USING (true) WITH CHECK (true);

-- Seed default initial agents if not already present
INSERT INTO public.ai_agents (agent_name, status, is_active, violation_count, violation_history, allowed_files, allowed_actions, allowed_destinations)
VALUES
    ('invoice_agent', 'active', true, 0, '[]'::jsonb, '["invoices.csv", "customer_orders.csv", "customer_records.csv"]'::jsonb, '["read"]'::jsonb, '["internal"]'::jsonb),
    ('hr_agent', 'active', true, 0, '[]'::jsonb, '["employee_salary.csv", "employee_records.csv"]'::jsonb, '["read"]'::jsonb, '["internal"]'::jsonb)
ON CONFLICT (agent_name) DO NOTHING;
