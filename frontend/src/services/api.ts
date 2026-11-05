/**
 * AI Shield - Centralized Frontend API Service
 * Strongly typed client for communicating with the AI Shield Flask + Supabase backend.
 * Provides unified request handling, query serialization, and structured error propagation.
 */

// ============================================================================
// 1. GENERIC API ENVELOPES & ERRORS
// ============================================================================

export interface ApiResponse<T> {
  success: boolean;
  message?: string;
  data: T;
  meta?: ApiMeta;
}

export interface ApiMeta {
  total?: number;
  limit?: number;
  offset?: number;
  returned?: number;
  alert_id?: string;
  incident_id?: string;
  [key: string]: unknown;
}

export interface ApiErrorResponse {
  success: false;
  error: string;
  details?: unknown;
}

export class ApiError extends Error {
  status: number;
  details?: unknown;

  constructor(message: string, status: number, details?: unknown) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.details = details;
  }
}

// ============================================================================
// 2. DOMAIN ENTITY SCHEMAS & CONTRACTS
// ============================================================================

// --- System Health ---
export interface SystemHealth {
  status: 'healthy' | 'degraded';
  database: 'connected' | 'disconnected';
  database_type: string;
  service: string;
  version: string;
  python_version: string;
  timestamp: string;
  message?: string;
}

// --- Employees ---
export type EmployeeStatus = 'active' | 'suspended' | 'under_investigation' | 'terminated';

export interface Employee {
  id: number;
  employee_id: string;
  name: string;
  email: string;
  department: string;
  role: string;
  risk_score: number;
  status: EmployeeStatus;
  created_at: string;
  updated_at?: string;
}

export interface CreateEmployeePayload {
  employee_id: string;
  name: string;
  email: string;
  department: string;
  role: string;
  risk_score?: number;
  status?: EmployeeStatus;
}

export interface EmployeeFilterParams {
  department?: string;
  status?: EmployeeStatus | string;
  limit?: number;
  offset?: number;
}

// --- Security Events (Follows docs/api_contract.md) ---
export type ActorType = 'employee' | 'agent' | 'external';
export type RiskLevel = 'low' | 'medium' | 'high' | 'critical';

export interface SecurityEvent {
  id: number;
  event_id: string;
  event_type: string;
  actor_type: ActorType;
  actor_id: string;
  resource: string;
  is_sensitive: boolean;
  action: string;
  destination?: string | null;
  timestamp: string;
  source: string;
  description?: string | null;
  rule_result?: string | null;
  anomaly?: boolean | null;
  risk_score?: number | null;
  risk_level?: RiskLevel | null;
  recommended_action?: string | null;
  created_at?: string;
}

export interface CreateEventPayload {
  event_id?: string;
  event_type: string;
  actor_type: ActorType;
  actor_id: string;
  resource: string;
  is_sensitive?: boolean;
  action: string;
  destination?: string;
  timestamp?: string;
  source?: string;
  description?: string;
  // Optional precomputed or simulator features
  anomaly?: boolean;
  risk_score?: number;
  risk_level?: RiskLevel;
  rule_result?: string;
  recommended_action?: string;
  employee_activities_24h?: number;
  downloads_24h?: number;
  external_activities_24h?: number;
  sensitive_accesses_24h?: number;
}

export interface EventFilterParams {
  event_type?: string;
  actor_type?: ActorType | string;
  actor_id?: string;
  is_sensitive?: boolean | string;
  risk_level?: RiskLevel | string;
  limit?: number;
  offset?: number;
}

// --- Security Incidents ---
export type IncidentSeverity = 'low' | 'medium' | 'high' | 'critical';
export type IncidentStatus = 'open' | 'investigating' | 'resolved' | 'closed';

export interface SecurityIncident {
  id: number;
  incident_id: string;
  title: string;
  description: string;
  severity: IncidentSeverity;
  status: IncidentStatus;
  actor_id?: string | null;
  event_id?: string | null;
  assigned_to?: string | null;
  resolved_at?: string | null;
  created_at: string;
  updated_at: string;
}

export interface CreateIncidentPayload {
  incident_id?: string;
  title: string;
  description: string;
  severity: IncidentSeverity;
  status?: IncidentStatus;
  actor_id?: string;
  event_id?: string;
  assigned_to?: string;
}

export interface UpdateIncidentPayload {
  status?: IncidentStatus;
  assigned_to?: string | null;
}

export interface IncidentFilterParams {
  severity?: IncidentSeverity | string;
  status?: IncidentStatus | string;
  actor_id?: string;
  limit?: number;
  offset?: number;
}

// --- Alerts ---
export type AlertSeverity = 'low' | 'medium' | 'high' | 'critical';

export interface Alert {
  id: number;
  alert_id: string;
  event_id?: string | null;
  incident_id?: string | null;
  alert_type: string;
  severity: AlertSeverity;
  message: string;
  is_read: boolean;
  created_at: string;
}

export interface CreateAlertPayload {
  alert_id?: string;
  alert_type: string;
  severity: AlertSeverity;
  message: string;
  event_id?: string;
  incident_id?: string;
}

export interface UpdateAlertPayload {
  is_read: boolean;
}

export interface AlertFilterParams {
  severity?: AlertSeverity | string;
  is_read?: boolean | string;
  limit?: number;
  offset?: number;
}

// ============================================================================
// 3. CORE REQUEST DISPATCHER & SERIALIZER
// ============================================================================

const BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api';

/**
 * Serialize an object into URL query string, omitting undefined, null, or empty values.
 */
function buildQueryString(params?: Record<string, unknown>): string {
  if (!params) return '';
  const searchParams = new URLSearchParams();
  for (const [key, val] of Object.entries(params)) {
    if (val !== undefined && val !== null && val !== '') {
      searchParams.append(key, String(val));
    }
  }
  const qs = searchParams.toString();
  return qs ? `?${qs}` : '';
}

/**
 * Central HTTP fetch wrapper with standardized error and envelope extraction.
 */
async function request<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<ApiResponse<T>> {
  const url = `${BASE_URL}${endpoint}`;
  const headers = new Headers(options.headers || {});

  if (!headers.has('Content-Type') && options.body && typeof options.body === 'string') {
    headers.set('Content-Type', 'application/json');
  }
  headers.set('Accept', 'application/json');

  try {
    const res = await fetch(url, { ...options, headers });
    let json: unknown;

    try {
      json = await res.json();
    } catch {
      throw new ApiError(
        `Failed to parse server response (${res.status} ${res.statusText})`,
        res.status
      );
    }

    const payload = json as ApiResponse<T> & ApiErrorResponse;

    if (!res.ok || payload.success === false) {
      const errMsg = payload.error || payload.message || `HTTP error ${res.status}: ${res.statusText}`;
      throw new ApiError(errMsg, res.status, payload.details);
    }

    return payload as ApiResponse<T>;
  } catch (err: unknown) {
    if (err instanceof ApiError) {
      throw err;
    }
    const message = err instanceof Error ? err.message : 'Network request failed';
    throw new ApiError(message, 0);
  }
}

// ============================================================================
// 4. CENTRALIZED TYPED API SERVICE OBJECT
// ============================================================================

export const api = {
  /**
   * Health Check API
   */
  health: {
    check: () => request<SystemHealth>('/health'),
  },

  /**
   * Employees API
   */
  employees: {
    list: (params?: EmployeeFilterParams) =>
      request<Employee[]>(`/employees${buildQueryString(params as Record<string, unknown>)}`),
    get: (employeeId: string) =>
      request<Employee>(`/employees/${encodeURIComponent(employeeId)}`),
    create: (payload: CreateEmployeePayload) =>
      request<Employee>('/employees', {
        method: 'POST',
        body: JSON.stringify(payload),
      }),
  },

  /**
   * Security Events API
   */
  events: {
    list: (params?: EventFilterParams) =>
      request<SecurityEvent[]>(`/events${buildQueryString(params as Record<string, unknown>)}`),
    get: (eventId: string) =>
      request<SecurityEvent>(`/events/${encodeURIComponent(eventId)}`),
    create: (payload: CreateEventPayload) =>
      request<SecurityEvent>('/events', {
        method: 'POST',
        body: JSON.stringify(payload),
      }),
  },

  /**
   * Security Incidents API (including PATCH for status updates)
   */
  incidents: {
    list: (params?: IncidentFilterParams) =>
      request<SecurityIncident[]>(`/incidents${buildQueryString(params as Record<string, unknown>)}`),
    get: (incidentId: string) =>
      request<SecurityIncident>(`/incidents/${encodeURIComponent(incidentId)}`),
    create: (payload: CreateIncidentPayload) =>
      request<SecurityIncident>('/incidents', {
        method: 'POST',
        body: JSON.stringify(payload),
      }),
    update: (incidentId: string, payload: UpdateIncidentPayload) =>
      request<SecurityIncident>(`/incidents/${encodeURIComponent(incidentId)}`, {
        method: 'PATCH',
        body: JSON.stringify(payload),
      }),
  },

  /**
   * Alerts API (including PATCH for read status)
   */
  alerts: {
    list: (params?: AlertFilterParams) =>
      request<Alert[]>(`/alerts${buildQueryString(params as Record<string, unknown>)}`),
    create: (payload: CreateAlertPayload) =>
      request<Alert>('/alerts', {
        method: 'POST',
        body: JSON.stringify(payload),
      }),
    update: (alertId: string, payload: UpdateAlertPayload) =>
      request<Alert>(`/alerts/${encodeURIComponent(alertId)}`, {
        method: 'PATCH',
        body: JSON.stringify(payload),
      }),
  },
};

export default api;
