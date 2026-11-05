# AI Shield — Backend Service (Supabase PostgreSQL)

The backend service for AI Shield provides the central REST API, persistence layer, and event ingestion pipeline for company security monitoring and data protection, powered exclusively by **Supabase PostgreSQL**.

---

## Architecture Overview

- **Database**: Supabase PostgreSQL (PostgREST API via official `supabase` Python client).
- **Framework**: Flask (Python 3) using modular Blueprint architecture.
- **Contract Compliance**: Strictly follows `docs/api_contract.md` for event schemas.
- **Cross-Origin**: Built-in CORS support for frontend clients.

```
backend/
├── app.py                # Application factory, server entry point & CORS
├── config.py             # Environment variable loader (SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
├── database.py           # Reusable Supabase client singleton & connectivity diagnostics
├── test_connection.py    # Standalone Supabase connectivity verification tool
├── seed.py               # Development-only seed script (idempotent upserts)
├── requirements.txt      # Dependencies (Flask, supabase)
├── .env.example          # Environment variables template
├── migrations/
│   └── 001_initial_schema.sql  # PostgreSQL DDL, foreign keys, indexes, RLS policies
├── routes/
│   ├── health.py         # GET /api/health (with Supabase connectivity probe)
│   ├── employees.py      # GET /api/employees, POST /api/employees
│   ├── events.py         # GET /api/events, POST /api/events (api_contract.md)
│   ├── incidents.py      # GET /api/incidents, POST /api/incidents
│   └── alerts.py         # GET /api/alerts, POST /api/alerts
├── utils/
│   ├── response.py       # Standard JSON response formatting
│   └── validation.py     # Schema validators (email, actor types, event payload)
└── tests/
    └── test_backend.py   # Automated unit & integration tests
```

---

## Supabase PostgreSQL Setup Guide

### 1. Execute SQL Migrations in Supabase
1. Log into your [Supabase Dashboard](https://supabase.com/dashboard).
2. Open your project.
3. In the left navigation menu, click **SQL Editor**.
4. Click **New query**.
5. Copy and paste the entire contents of `backend/migrations/001_initial_schema.sql`.
6. Click **Run**.
This will create:
- `employees` table with unique constraint on `employee_id` and `email`
- `security_events` table conforming to `docs/api_contract.md`
- `security_incidents` table with foreign key to `security_events`
- `alerts` table with foreign keys to `security_events` and `security_incidents`
- `activity_logs` table
- Performance indexes and Row Level Security (RLS) policies

### 2. Configure Environment Variables
Copy `.env.example` to `.env` in the `backend/` directory:
```bash
cp backend/.env.example backend/.env
```
Populate your project credentials from **Project Settings -> API**:
```ini
SUPABASE_URL=https://<your-project-id>.supabase.co
SUPABASE_SERVICE_ROLE_KEY=<your-service-role-key>

HOST=127.0.0.1
PORT=5000
FLASK_ENV=development
FLASK_DEBUG=1
SECRET_KEY=ai-shield-dev-secret-key-2026
CORS_ORIGIN=*
```
> [!CAUTION]
> Never commit `backend/.env` or expose the `SUPABASE_SERVICE_ROLE_KEY` to frontend clients.

### 3. Verify Connection
Run the diagnostic script:
```bash
python backend/test_connection.py
```
This tests authentication, table availability, and row queries.

### 4. Seed Development Data
Populate realistic sample records without duplicates:
```bash
python backend/seed.py
```

### 5. Start the Server
```bash
python backend/app.py
```
Server runs at `http://127.0.0.1:5000`.

---

## API Endpoints

### Health Check
- `GET /api/health` — Probes Supabase database connection and returns server status.

### Employees
- `GET /api/employees` — Query employees (filters: `department`, `status`, `limit`, `offset`).
- `GET /api/employees/<employee_id>` — Retrieve employee by ID.
- `POST /api/employees` — Register a new employee with duplicate prevention.

### Security Events (`docs/api_contract.md`)
- `GET /api/events` — Query events (filters: `event_type`, `actor_type`, `actor_id`, `is_sensitive`, `risk_level`, `limit`, `offset`).
- `GET /api/events/<event_id>` — Retrieve single security event.
- `POST /api/events` — Ingest new security event conforming to the team API contract.

### Security Incidents
- `GET /api/incidents` — Query incidents (filters: `severity`, `status`, `actor_id`, `limit`, `offset`).
- `GET /api/incidents/<incident_id>` — Retrieve single incident.
- `POST /api/incidents` — Create security incident.

### Alerts
- `GET /api/alerts` — Query alerts (filters: `severity`, `is_read`, `limit`, `offset`).
- `POST /api/alerts` — Create security alert.

---

## Running Automated Tests

Run the backend test suite:
```bash
python -m unittest discover -s backend/tests -v
```
All 17 tests verify validation, HTTP response shapes, error handlers, query construction, and PostgREST interactions.
