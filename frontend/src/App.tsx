import { useState, useEffect, useCallback, type ReactNode } from 'react'
import {
  Activity, AlertTriangle, Bot, CheckCircle2,
  Database, FileText, Filter, Gauge, Globe, LayoutDashboard,
  LockKeyhole, Menu, MoreHorizontal, Network, RefreshCw, Search, Settings,
  Shield, ShieldAlert, ShieldCheck,
  UserRound, Users, X
} from 'lucide-react'
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, ResponsiveContainer,
  Tooltip, XAxis, YAxis
} from 'recharts'
import AuthPage from './AuthPage'
import api, {
  type SystemHealth,
  type Employee,
  type SecurityEvent,
  type SecurityIncident,
  type Alert,
  ApiError
} from './services/api'

type Page =
  | 'Overview'
  | 'Incidents'
  | 'Activity'
  | 'Files & Sharing'
  | 'API Monitor'
  | 'DLP Violations'
  | 'Risk & Recommendations'

const navigation: { name: Page; icon: typeof LayoutDashboard }[] = [
  { name: 'Overview', icon: LayoutDashboard },
  { name: 'Incidents', icon: ShieldAlert },
  { name: 'Activity', icon: Activity },
  { name: 'Files & Sharing', icon: FileText },
  { name: 'API Monitor', icon: Network },
  { name: 'DLP Violations', icon: LockKeyhole },
  { name: 'Risk & Recommendations', icon: Gauge },
]

// Baseline trend distribution used when no event telemetry is available
const baselineTrendData = [
  { day: 'Mon', events: 12, threats: 2 },
  { day: 'Tue', events: 18, threats: 3 },
  { day: 'Wed', events: 15, threats: 1 },
  { day: 'Thu', events: 25, threats: 5 },
  { day: 'Fri', events: 22, threats: 4 },
  { day: 'Sat', events: 30, threats: 6 },
  { day: 'Sun', events: 20, threats: 3 },
]

/**
 * Maps a numerical risk score (0-100) to standard backend risk thresholds:
 * Critical >= 80, High >= 60, Medium >= 30, Low < 30.
 * Safely handles null, undefined, and non-numeric inputs.
 */
function getRiskLevel(score?: number | null): 'Critical' | 'High' | 'Medium' | 'Low' {
  if (score === null || score === undefined) return 'Low'
  const num = Number(score)
  if (isNaN(num)) return 'Low'
  if (num >= 80) return 'Critical'
  if (num >= 60) return 'High'
  if (num >= 30) return 'Medium'
  return 'Low'
}

/**
 * Checks if an event is an authentication-related interaction.
 */
function isAuthEvent(e: SecurityEvent): boolean {
  const type = (e.event_type || '').toLowerCase()
  const res = (e.resource || '').toLowerCase()
  const act = (e.action || '').toLowerCase()
  const src = (e.source || '').toLowerCase()
  return (
    type.includes('auth') ||
    type.includes('login') ||
    src.includes('auth') ||
    act === 'login' ||
    act === 'authenticate' ||
    res.includes('/auth') ||
    res.includes('/login') ||
    res.includes('/oauth') ||
    res.includes('/token')
  )
}

/**
 * Checks if an event is an API call, using actual API event types and fields
 * while strictly excluding authentication-related endpoints and removing
 * broad heuristics like resource.startsWith('/').
 */
function isApiEvent(e: SecurityEvent): boolean {
  if (isAuthEvent(e)) return false
  const type = (e.event_type || '').toLowerCase()
  const src = (e.source || '').toLowerCase()
  const res = (e.resource || '').toLowerCase()
  return (
    type === 'api_request' ||
    type === 'api_call' ||
    type.includes('api') ||
    src.includes('api') ||
    res.startsWith('/api/')
  )
}

/**
 * Checks if an alert is a genuine DLP violation or confirmed data exfiltration.
 * Avoids broad severity-based heuristics.
 */
function isDlpAlert(a: Alert): boolean {
  const type = (a.alert_type || '').toUpperCase()
  return type.includes('DLP') || type.includes('EXFILTRATION')
}

/**
 * Checks if an event is a genuine DLP violation or confirmed exfiltration event.
 */
function isDlpEvent(e: SecurityEvent): boolean {
  const evtType = (e.event_type || '').toLowerCase()
  const ruleRes = (e.rule_result || '').toLowerCase()
  return (
    evtType.includes('dlp') ||
    evtType.includes('exfiltration') ||
    ruleRes.includes('dlp') ||
    ruleRes.includes('exfiltration')
  )
}

/**
 * Checks if an event represents file activity, excluding API and auth traffic.
 */
function isFileEvent(e: SecurityEvent): boolean {
  if (isAuthEvent(e) || isApiEvent(e)) return false
  const type = (e.event_type || '').toLowerCase()
  const act = (e.action || '').toLowerCase()
  const res = (e.resource || '').toLowerCase()
  return (
    type.includes('file') ||
    type.includes('share') ||
    type.includes('transfer') ||
    act === 'download' ||
    act === 'share' ||
    act === 'export' ||
    act === 'upload' ||
    (act === 'read' && res.includes('.')) ||
    res.includes('.')
  )
}

function formatTimeAgo(isoString?: string | null): string {
  if (!isoString) return 'Just now'
  try {
    const date = new Date(isoString)
    const now = new Date()
    const diffSec = Math.floor((now.getTime() - date.getTime()) / 1000)
    if (diffSec < 60) return `${Math.max(1, diffSec)}s ago`
    const diffMin = Math.floor(diffSec / 60)
    if (diffMin < 60) return `${diffMin} min ago`
    const diffHour = Math.floor(diffMin / 60)
    if (diffHour < 24) return `${diffHour} hr ago`
    const diffDays = Math.floor(diffHour / 24)
    return `${diffDays}d ago`
  } catch {
    return 'Recently'
  }
}

function Severity({ value }: { value: string }) {
  const norm = value ? value.charAt(0).toUpperCase() + value.slice(1).toLowerCase() : 'Low'
  const colors: Record<string, string> = {
    Critical: 'bg-red-400/10 text-red-400 border-red-400/20',
    High: 'bg-orange-400/10 text-orange-300 border-orange-400/20',
    Medium: 'bg-yellow-400/10 text-yellow-300 border-yellow-400/20',
    Low: 'bg-slate-400/10 text-slate-300 border-slate-400/20',
  }

  return (
    <span className={`inline-flex rounded-md border px-2 py-1 text-[11px] font-semibold ${colors[norm] || colors.Low}`}>
      {norm}
    </span>
  )
}

function Status({ value }: { value: string }) {
  const norm = value ? value.charAt(0).toUpperCase() + value.slice(1).toLowerCase() : 'Open'
  const color =
    norm === 'Resolved' || norm === 'Closed'
      ? 'text-emerald-300'
      : norm === 'Investigating'
        ? 'text-blue-300'
        : 'text-orange-300'

  return <span className={`text-xs ${color}`}>● {norm}</span>
}

function Panel({
  title,
  subtitle,
  action,
  children,
  className = '',
}: {
  title: string
  subtitle?: string
  action?: ReactNode
  children: ReactNode
  className?: string
}) {
  return (
    <section className={`panel min-w-0 p-5 ${className}`}>
      <div className="mb-5 flex items-start justify-between gap-3">
        <div>
          <h3 className="text-sm font-semibold text-[#f4eff0]">{title}</h3>
          {subtitle && (
            <p className="mt-1 text-xs text-[#7f8985]">{subtitle}</p>
          )}
        </div>
        {action}
      </div>
      {children}
    </section>
  )
}

function App() {
  const [page, setPage] = useState<Page>('Overview')
  const [range, setRange] = useState('7 days')
  const [selectedIncident, setSelectedIncident] = useState<SecurityIncident | null>(null)
  const [mobileOpen, setMobileOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [notice, setNotice] = useState('')
  const [isAuthenticated, setIsAuthenticated] = useState(false)

  // Live Backend State
  const [loading, setLoading] = useState(false)
  const [isUpdating, setIsUpdating] = useState(false)
  const [loadingMoreIncidents, setLoadingMoreIncidents] = useState(false)
  const [loadingMoreEvents, setLoadingMoreEvents] = useState(false)
  const [health, setHealth] = useState<SystemHealth | null>(null)
  const [incidents, setIncidents] = useState<SecurityIncident[]>([])
  const [events, setEvents] = useState<SecurityEvent[]>([])
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [employees, setEmployees] = useState<Employee[]>([])
  const [totals, setTotals] = useState({
    events: 0,
    incidents: 0,
    alerts: 0,
    employees: 0,
  })

  const notify = (message: string) => {
    setNotice(message)
    window.setTimeout(() => setNotice(''), 3000)
  }

  // Fetch all backend entities in parallel with comprehensive Promise.allSettled inspection
  const loadData = useCallback(async (isManualRefresh = false) => {
    setLoading(true)
    try {
      const [hRes, incRes, evtRes, altRes, empRes] = await Promise.allSettled([
        api.health.check(),
        api.incidents.list({ limit: 100 }),
        api.events.list({ limit: 100 }),
        api.alerts.list({ limit: 100 }),
        api.employees.list({ limit: 100 }),
      ])

      const tracked = [
        { name: 'System Health', res: hRes },
        { name: 'Incidents', res: incRes },
        { name: 'Events', res: evtRes },
        { name: 'Alerts', res: altRes },
        { name: 'Employees', res: empRes },
      ]

      if (hRes.status === 'fulfilled') setHealth(hRes.value.data)

      if (incRes.status === 'fulfilled') {
        setIncidents(incRes.value.data)
        const total = incRes.value.meta?.total ?? incRes.value.data.length
        setTotals(prev => ({ ...prev, incidents: total }))
      }

      if (evtRes.status === 'fulfilled') {
        setEvents(evtRes.value.data)
        const total = evtRes.value.meta?.total ?? evtRes.value.data.length
        setTotals(prev => ({ ...prev, events: total }))
      }

      if (altRes.status === 'fulfilled') {
        setAlerts(altRes.value.data)
        const total = altRes.value.meta?.total ?? altRes.value.data.length
        setTotals(prev => ({ ...prev, alerts: total }))
      }

      if (empRes.status === 'fulfilled') {
        setEmployees(empRes.value.data)
        const total = empRes.value.meta?.total ?? empRes.value.data.length
        setTotals(prev => ({ ...prev, employees: total }))
      }

      const failed = tracked.filter(t => t.res.status === 'rejected')
      const succeeded = tracked.filter(t => t.res.status === 'fulfilled')

      if (failed.length === 0) {
        if (isManualRefresh) {
          notify('All data refreshed successfully from Supabase')
        }
      } else if (succeeded.length === 0) {
        notify(`Failed to refresh data: all ${failed.length} endpoints unreachable`)
      } else {
        const failedNames = failed.map(f => f.name).join(', ')
        notify(`Partial refresh: ${succeeded.length}/${tracked.length} succeeded (${failedNames} failed)`)
      }
    } catch (err: unknown) {
      const msg = err instanceof ApiError ? err.message : 'Error fetching backend data'
      notify(`Connection error: ${msg}`)
    } finally {
      setLoading(false)
    }
  }, [])

  // Safely fetch additional pages for Incidents without infinite loops
  const loadMoreIncidents = async () => {
    if (loadingMoreIncidents || incidents.length >= totals.incidents) return
    setLoadingMoreIncidents(true)
    try {
      const res = await api.incidents.list({ offset: incidents.length, limit: 50 })
      if (res.data.length > 0) {
        setIncidents(prev => [...prev, ...res.data])
        if (res.meta?.total) {
          setTotals(prev => ({ ...prev, incidents: res.meta!.total! }))
        }
      }
    } catch (err: unknown) {
      const msg = err instanceof ApiError ? err.message : 'Failed to load more incidents'
      notify(`Error: ${msg}`)
    } finally {
      setLoadingMoreIncidents(false)
    }
  }

  // Safely fetch additional pages for Activity events without infinite loops
  const loadMoreEvents = async () => {
    if (loadingMoreEvents || events.length >= totals.events) return
    setLoadingMoreEvents(true)
    try {
      const res = await api.events.list({ offset: events.length, limit: 50 })
      if (res.data.length > 0) {
        setEvents(prev => [...prev, ...res.data])
        if (res.meta?.total) {
          setTotals(prev => ({ ...prev, events: res.meta!.total! }))
        }
      }
    } catch (err: unknown) {
      const msg = err instanceof ApiError ? err.message : 'Failed to load more events'
      notify(`Error: ${msg}`)
    } finally {
      setLoadingMoreEvents(false)
    }
  }

  useEffect(() => {
    if (isAuthenticated) {
      // eslint-disable-next-line react-hooks/set-state-in-effect
      loadData()
    }
  }, [isAuthenticated, loadData])

  // Filtered incidents based on search query
  const filteredIncidents = incidents.filter(item =>
    `${item.incident_id} ${item.title} ${item.actor_id || ''} ${item.severity} ${item.status}`
      .toLowerCase()
      .includes(query.toLowerCase())
  )

  const openIncidentsCount = incidents.filter(i =>
    i.status.toLowerCase() === 'open' || i.status.toLowerCase() === 'investigating'
  ).length

  const unreadAlertsCount = alerts.filter(a => !a.is_read).length

  // Calculate distinct sensitive files accessed
  const sensitiveFilesSet = new Set(
    events.filter(e => e.is_sensitive).map(e => e.resource)
  )

  // Calculate threats/anomalies detected using exact backend thresholds (High >= 60, Critical >= 80)
  const threatsDetectedCount = events.filter(e => {
    if (e.anomaly) return true
    if (e.risk_score !== null && e.risk_score !== undefined && !isNaN(Number(e.risk_score))) {
      return Number(e.risk_score) >= 60.0
    }
    const norm = (e.risk_level || '').toLowerCase()
    return norm === 'high' || norm === 'critical'
  }).length

  // Overall risk score: average risk of all ingested events with numeric risk scores
  const eventsWithRisk = events.filter(
    e => e.risk_score !== null && e.risk_score !== undefined && !isNaN(Number(e.risk_score))
  )
  const calculatedRiskScore = eventsWithRisk.length > 0
    ? Math.round(
        eventsWithRisk.reduce((acc, e) => acc + Number(e.risk_score), 0) / eventsWithRisk.length
      )
    : 0

  // Filter specific event streams using precise criteria
  const apiEvents = events.filter(isApiEvent)
  const dlpAlerts = alerts.filter(isDlpAlert)
  const dlpEvents = events.filter(isDlpEvent)
  const fileEvents = events.filter(isFileEvent)

  // Real 7-day trend telemetry calculation
  const trendTelemetry = (() => {
    const daysOfWeek = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']
    const buckets = Array.from({ length: 7 }, (_, i) => {
      const d = new Date()
      d.setDate(d.getDate() - (6 - i))
      const dayName = daysOfWeek[d.getDay()]
      const dateStr = d.toISOString().split('T')[0]
      return { day: dayName, dateStr, events: 0, threats: 0 }
    })

    let matchedEvents = 0
    events.forEach(e => {
      if (!e.timestamp) return
      try {
        const eDate = new Date(e.timestamp)
        if (isNaN(eDate.getTime())) return
        const dateStr = eDate.toISOString().split('T')[0]
        const bucket = buckets.find(b => b.dateStr === dateStr)
        if (bucket) {
          bucket.events += 1
          matchedEvents += 1
          const isThreat =
            e.anomaly ||
            (e.risk_score !== null && e.risk_score !== undefined && Number(e.risk_score) >= 60.0) ||
            e.risk_level === 'high' ||
            e.risk_level === 'critical'
          if (isThreat) {
            bucket.threats += 1
          }
        }
      } catch {
        // ignore parse error
      }
    })

    return {
      hasRealData: matchedEvents > 0,
      data: matchedEvents > 0 ? buckets : baselineTrendData
    }
  })()

  // Real API trend telemetry calculation
  const apiTrendTelemetry = (() => {
    if (!apiEvents.length) {
      return {
        hasRealData: false,
        data: baselineTrendData,
        label: 'Demo / Baseline'
      }
    }

    const daysOfWeek = ['Sun', 'Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat']
    const buckets = Array.from({ length: 7 }, (_, i) => {
      const d = new Date()
      d.setDate(d.getDate() - (6 - i))
      const dayName = daysOfWeek[d.getDay()]
      const dateStr = d.toISOString().split('T')[0]
      return { day: dayName, dateStr, events: 0 }
    })

    let matched = 0
    apiEvents.forEach(e => {
      if (!e.timestamp) return
      try {
        const eDate = new Date(e.timestamp)
        if (isNaN(eDate.getTime())) return
        const dateStr = eDate.toISOString().split('T')[0]
        const bucket = buckets.find(b => b.dateStr === dateStr)
        if (bucket) {
          bucket.events += 1
          matched += 1
        }
      } catch {
        // ignore
      }
    })

    if (matched > 0) {
      return {
        hasRealData: true,
        data: buckets,
        label: 'Live Telemetry'
      }
    }

    // Group by endpoint if outside the 7-day window
    const endpointCounts: Record<string, number> = {}
    apiEvents.forEach(e => {
      const ep = e.resource || 'unknown'
      endpointCounts[ep] = (endpointCounts[ep] || 0) + 1
    })

    const endpointBuckets = Object.entries(endpointCounts).slice(0, 7).map(([endpoint, count]) => ({
      day: endpoint.length > 14 ? endpoint.slice(0, 12) + '...' : endpoint,
      events: count
    }))

    return {
      hasRealData: true,
      data: endpointBuckets,
      label: 'Live Endpoints'
    }
  })()

  const heading: Record<Page, string> = {
    Overview: 'Security overview',
    Incidents: 'Security incidents',
    Activity: 'Activity monitoring',
    'Files & Sharing': 'Files & sharing',
    'API Monitor': 'API monitor',
    'DLP Violations': 'DLP violations',
    'Risk & Recommendations': 'Risk & recommendations',
  }

  const subtitle: Record<Page, string> = {
    Overview: 'Monitor your organization’s security posture with live Supabase telemetry.',
    Incidents: 'Investigate, prioritize and resolve security incidents.',
    Activity: 'A unified timeline of employee and AI agent security events.',
    'Files & Sharing': 'Track sensitive files, permissions and external transfers.',
    'API Monitor': 'Monitor API traffic, external requests and suspicious patterns.',
    'DLP Violations': 'Review policy violations and data leakage prevention alerts.',
    'Risk & Recommendations': 'Understand organizational risk exposure and automated ML guidance.',
  }

  // Real-time metric cards reflecting accurate database counts
  const stats = [
    {
      label: 'Events monitored',
      value: (totals.events || events.length).toLocaleString(),
      change: totals.events > 0 ? 'Live in Supabase' : 'Awaiting events',
      icon: Activity,
      color: 'text-[#ff3545]',
      up: true
    },
    {
      label: 'Open incidents',
      value: String(openIncidentsCount).padStart(2, '0'),
      change: `${totals.incidents || incidents.length} total recorded`,
      icon: AlertTriangle,
      color: 'text-orange-300',
      up: openIncidentsCount > 0
    },
    {
      label: 'Sensitive files',
      value: String(sensitiveFilesSet.size || 0),
      change: `${totals.employees || employees.length} employees registered`,
      icon: Database,
      color: 'text-blue-300',
      up: false
    },
    {
      label: 'Threats flagged',
      value: String(threatsDetectedCount),
      change: `${totals.alerts || alerts.length} active alerts`,
      icon: ShieldCheck,
      color: 'text-emerald-300',
      up: true
    },
  ]

  // Render Incidents Table
  const renderIncidentTable = (items: SecurityIncident[]) => {
    if (!items.length) {
      return (
        <div className="py-8 text-center text-xs text-[#aaa0a2]">
          No incidents recorded in Supabase.
        </div>
      )
    }

    return (
      <div className="overflow-x-auto">
        <table className="w-full min-w-[680px] text-left">
          <thead>
            <tr className="border-b border-white/[0.07] text-[10px] uppercase tracking-wider text-[#91878a]">
              <th className="pb-3 font-medium">Incident</th>
              <th className="pb-3 font-medium">Actor</th>
              <th className="pb-3 font-medium">Event Ref</th>
              <th className="pb-3 font-medium">Severity</th>
              <th className="pb-3 font-medium">Time</th>
              <th className="pb-3 font-medium">Status</th>
            </tr>
          </thead>
          <tbody>
            {items.map(item => (
              <tr
                key={item.incident_id}
                onClick={() => setSelectedIncident(item)}
                className="cursor-pointer border-b border-white/[0.045] transition hover:bg-white/[0.025]"
              >
                <td className="py-4 pr-4">
                  <p className="text-xs font-medium text-[#f0e9ea]">{item.title}</p>
                  <p className="mt-1 text-[10px] text-[#91878a]">{item.incident_id}</p>
                </td>
                <td className="py-4 pr-4 text-xs text-[#d5ccce]">
                  {item.actor_id || 'System'}
                  <p className="mt-1 text-[10px] text-[#91878a]">
                    {item.assigned_to ? `Assigned: ${item.assigned_to}` : 'Unassigned'}
                  </p>
                </td>
                <td className="py-4 pr-4 font-mono text-[11px] text-[#c4babc]">
                  {item.event_id || '—'}
                </td>
                <td className="py-4 pr-4">
                  <Severity value={item.severity} />
                </td>
                <td className="py-4 pr-4 text-xs text-[#87928c]">
                  {formatTimeAgo(item.created_at)}
                </td>
                <td className="py-4">
                  <Status value={item.status} />
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    )
  }

  // Render Activity List
  const renderActivityList = (items: SecurityEvent[]) => {
    if (!items.length) {
      return (
        <div className="py-8 text-center text-xs text-[#aaa0a2]">
          No activity logs recorded in Supabase.
        </div>
      )
    }

    return (
      <div className="space-y-4">
        {items.map((item) => (
          <div key={item.event_id} className="flex items-start gap-3">
            <div className={`mt-1 h-2 w-2 shrink-0 rounded-full ${item.anomaly ? 'bg-[#ff3545]' : 'bg-emerald-400'}`} />
            <div className="min-w-0 flex-1">
              <p className="text-xs text-[#e8dfe1]">
                <span className="font-semibold">{item.actor_id}</span>{' '}
                <span className="text-[#aaa0a2]">[{item.action}]</span>
              </p>
              <p className="mt-1 truncate font-mono text-[11px] text-[#aaa0a2]">
                {item.resource}
                {item.destination ? ` → ${item.destination}` : ''}
              </p>
              <p className="mt-1 text-[10px] text-[#82777a]">
                {formatTimeAgo(item.timestamp)} · {item.source}
              </p>
            </div>
            <Severity value={item.risk_level || (item.anomaly ? 'High' : 'Low')} />
          </div>
        ))}
      </div>
    )
  }

  // Mark Incident as Investigating via PATCH endpoint
  const handleUpdateIncidentStatus = async () => {
    if (!selectedIncident) return
    setIsUpdating(true)
    try {
      const nextStatus = selectedIncident.status === 'investigating' ? 'resolved' : 'investigating'
      const res = await api.incidents.update(selectedIncident.incident_id, { status: nextStatus })
      notify(`Incident ${selectedIncident.incident_id} updated to '${nextStatus}' in Supabase`)
      setSelectedIncident(res.data)
      await loadData()
    } catch (err: unknown) {
      const msg = err instanceof ApiError ? err.message : 'Failed to update incident'
      notify(`Error: ${msg}`)
    } finally {
      setIsUpdating(false)
    }
  }

  // Mark Alert as Read via PATCH endpoint
  const handleMarkAlertRead = async (alertId: string) => {
    try {
      await api.alerts.update(alertId, { is_read: true })
      notify(`Alert ${alertId} marked as read in Supabase`)
      await loadData()
    } catch (err: unknown) {
      const msg = err instanceof ApiError ? err.message : 'Failed to update alert'
      notify(`Error: ${msg}`)
    }
  }

  // ==========================================================================
  // VIEW RENDERERS
  // ==========================================================================

  const overview = (
    <>
      {/* 4 Top Metric Cards */}
      <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">
        {stats.map((stat, i) => {
          const Icon = stat.icon
          return (
            <div key={i} className="panel p-4 sm:p-5">
              <div className="flex items-center justify-between">
                <span className="text-xs text-[#aaa0a2]">{stat.label}</span>
                <Icon size={17} className={stat.color} />
              </div>
              <div className="mt-4 flex items-end justify-between gap-2">
                <span className="text-2xl font-semibold tracking-tight text-[#ffffff] tabular-nums">
                  {stat.value}
                </span>
                <span className="text-[10px] text-[#ff3545]">{stat.change}</span>
              </div>
            </div>
          )
        })}
      </div>

      {/* Security Events Area Chart & Exposure Flow */}
      <div className="grid gap-4 xl:grid-cols-[1.5fr_1fr]">
        <Panel
          title="Security events"
          subtitle={
            trendTelemetry.hasRealData
              ? `Live 7-day event volume & threat telemetry (${totals.events || events.length} events logged in Supabase)`
              : `Event volume & threat telemetry (Baseline / Demo — no events in 7-day window)`
          }
          action={
            <span className={`rounded-md px-2 py-1 text-[10px] ${
              trendTelemetry.hasRealData
                ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                : 'bg-amber-400/10 text-amber-300 border border-amber-400/20'
            }`}>
              {trendTelemetry.hasRealData ? `Live: Last ${range}` : 'Demo / Baseline'}
            </span>
          }
        >
          <div className="h-[250px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trendTelemetry.data}>
                <defs>
                  <linearGradient id="eventsGradient" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#ff3545" stopOpacity={0.22} />
                    <stop offset="95%" stopColor="#ff3545" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid stroke="#ffffff" strokeOpacity={0.06} vertical={false} />
                <XAxis dataKey="day" stroke="#82777a" tickLine={false} axisLine={false} fontSize={11} />
                <YAxis stroke="#82777a" tickLine={false} axisLine={false} fontSize={11} />
                <Tooltip contentStyle={{ background: '#171114', border: '1px solid #3a2024', borderRadius: 8, fontSize: 12 }} />
                <Area type="monotone" dataKey="events" stroke="#ff3545" strokeWidth={2} fill="url(#eventsGradient)" />
                <Area type="monotone" dataKey="threats" stroke="#ff9f5a" strokeWidth={2} fill="transparent" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
          <div className="mt-3 flex gap-5 text-[10px] text-[#aaa0a2]">
            <span><span className="mr-2 inline-block h-2 w-2 rounded-full bg-[#ff3545]" />Events ({totals.events || events.length} ingested)</span>
            <span><span className="mr-2 inline-block h-2 w-2 rounded-full bg-[#ff9f5a]" />Threats ({threatsDetectedCount} flagged)</span>
          </div>
        </Panel>

        <Panel title="Exposure flow" subtitle="Identified actor & destination telemetry">
          <div className="space-y-3">
            <div className="flex items-center gap-3 rounded-lg border border-white/[0.06] bg-white/[0.02] p-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-white/[0.04] text-[#ff3545]">
                <Users size={17} />
              </div>
              <div className="min-w-0 flex-1">
                <p className="text-xs font-medium">Employees</p>
                <p className="mt-1 text-[10px] text-[#aaa0a2]">{totals.employees || employees.length} users registered in Supabase</p>
              </div>
              <span className="text-[10px] text-emerald-400">Synced</span>
            </div>

            <div className="flex items-center gap-3 rounded-lg border border-white/[0.06] bg-white/[0.02] p-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-white/[0.04] text-[#d16b75]">
                <Bot size={17} />
              </div>
              <div className="min-w-0 flex-1">
                <p className="text-xs font-medium">AI Agents</p>
                <p className="mt-1 text-[10px] text-[#aaa0a2]">Monitored by Isolation Forest</p>
              </div>
              <span className="text-[10px] text-blue-400">ML Active</span>
            </div>

            <div className="flex items-center gap-3 rounded-lg border border-white/[0.06] bg-white/[0.02] p-3">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-white/[0.04] text-[#b77b83]">
                <Globe size={17} />
              </div>
              <div className="min-w-0 flex-1">
                <p className="text-xs font-medium">Connected Database</p>
                <p className="mt-1 text-[10px] text-[#aaa0a2]">{health?.database_type || 'Supabase PostgreSQL'}</p>
              </div>
              <span className="text-[10px] text-emerald-400">Online</span>
            </div>

            <div className="rounded-lg border border-orange-400/15 bg-orange-400/[0.04] p-3">
              <p className="text-[10px] font-semibold uppercase tracking-wider text-orange-300">
                Active Destinations Monitored
              </p>
              <div className="mt-3 flex flex-wrap gap-2">
                {['internal_workstation', 'removable_media', 'external_cloud', 'personal_email'].map(x => (
                  <span key={x} className="rounded-md border border-orange-300/10 bg-orange-300/[0.05] px-2 py-1 text-[10px] text-[#c7a58e]">
                    {x}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </Panel>
      </div>

      {/* Recent Incidents & Live Activity Feed */}
      <div className="grid gap-4 xl:grid-cols-[1.5fr_1fr]">
        <Panel
          title="Recent incidents"
          subtitle={`Latest security incidents (${totals.incidents || incidents.length} in Supabase)`}
          action={
            <button onClick={() => setPage('Incidents')} className="text-[11px] text-[#ff3545] hover:underline">
              View all →
            </button>
          }
        >
          {renderIncidentTable(incidents.slice(0, 4))}
        </Panel>

        <Panel title="Live activity feed" subtitle={`Recent events from Supabase (${totals.events || events.length} total)`}>
          {renderActivityList(events.slice(0, 4))}
        </Panel>
      </div>
    </>
  )

  const renderPage = () => {
    if (page === 'Overview') return overview

    // VIEW 2: INCIDENTS
    if (page === 'Incidents') {
      return (
        <Panel
          title="Security incidents"
          subtitle={`${filteredIncidents.length} shown of ${totals.incidents || incidents.length} incidents found in Supabase (Click any row to investigate)`}
        >
          {renderIncidentTable(filteredIncidents)}
          {incidents.length < totals.incidents && (
            <div className="mt-4 flex items-center justify-between border-t border-white/[0.06] pt-4 text-xs text-[#aaa0a2]">
              <span>Showing {incidents.length} of {totals.incidents} incidents in Supabase</span>
              <button
                disabled={loadingMoreIncidents}
                onClick={loadMoreIncidents}
                className="rounded-md border border-white/10 px-3 py-1.5 text-xs text-[#f4eff0] hover:border-[#ff3545]/40 disabled:opacity-50 transition"
              >
                {loadingMoreIncidents ? 'Loading...' : 'Load more incidents'}
              </button>
            </div>
          )}
        </Panel>
      )
    }

    // VIEW 3: ACTIVITY
    if (page === 'Activity') {
      return (
        <Panel title="Activity timeline" subtitle={`Real-time security event telemetry (${totals.events || events.length} total logged in Supabase)`}>
          {renderActivityList(events)}
          {events.length < totals.events && (
            <div className="mt-4 flex items-center justify-between border-t border-white/[0.06] pt-4 text-xs text-[#aaa0a2]">
              <span>Showing {events.length} of {totals.events} events in Supabase</span>
              <button
                disabled={loadingMoreEvents}
                onClick={loadMoreEvents}
                className="rounded-md border border-white/10 px-3 py-1.5 text-xs text-[#f4eff0] hover:border-[#ff3545]/40 disabled:opacity-50 transition"
              >
                {loadingMoreEvents ? 'Loading...' : 'Load more activity'}
              </button>
            </div>
          )}
        </Panel>
      )
    }

    // VIEW 4: FILES & SHARING
    if (page === 'Files & Sharing') {
      return (
        <Panel title="File activity" subtitle={`Monitored file operations from Supabase (${fileEvents.length} events)`}>
          {fileEvents.length ? (
            <div className="overflow-x-auto">
              <table className="w-full min-w-[650px] text-left text-xs">
                <thead className="text-[10px] uppercase tracking-wider text-[#91878a]">
                  <tr className="border-b border-white/10">
                    <th className="pb-3">File / Resource</th>
                    <th className="pb-3">Classification</th>
                    <th className="pb-3">Actor</th>
                    <th className="pb-3">Activity</th>
                    <th className="pb-3">Destination</th>
                    <th className="pb-3">Risk Level</th>
                  </tr>
                </thead>
                <tbody>
                  {fileEvents.map((evt) => (
                    <tr key={evt.event_id} className="border-b border-white/[0.05]">
                      <td className="py-4 font-mono text-[#e2d9db]">{evt.resource}</td>
                      <td className="py-4 text-[#aaa0a2]">
                        {evt.is_sensitive ? (
                          <span className="text-red-300 font-semibold">Sensitive</span>
                        ) : (
                          'Standard Asset'
                        )}
                      </td>
                      <td className="py-4">{evt.actor_id}</td>
                      <td className="py-4 text-[#aaa0a2] capitalize">{evt.action}</td>
                      <td className="py-4 font-mono text-[11px] text-[#aaa0a2]">{evt.destination || 'internal'}</td>
                      <td className="py-4">
                        <Severity
                          value={
                            evt.risk_level
                              ? evt.risk_level.charAt(0).toUpperCase() + evt.risk_level.slice(1).toLowerCase()
                              : getRiskLevel(evt.risk_score)
                          }
                        />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          ) : (
            <p className="py-8 text-center text-xs text-[#aaa0a2]">No file events currently recorded in Supabase.</p>
          )}
        </Panel>
      )
    }

    // VIEW 5: API MONITOR
    if (page === 'API Monitor') {
      return (
        <>
          <Panel
            title={apiTrendTelemetry.hasRealData ? 'API telemetry distribution' : 'API telemetry distribution (Demo / Baseline)'}
            subtitle={
              apiTrendTelemetry.hasRealData
                ? `Live request activity volume (${apiEvents.length} API events captured)`
                : 'Simulated baseline volume — no live API events recorded in Supabase'
            }
            action={
              <span className={`rounded-md px-2 py-1 text-[10px] ${
                apiTrendTelemetry.hasRealData
                  ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                  : 'bg-amber-400/10 text-amber-300 border border-amber-400/20'
              }`}>
                {apiTrendTelemetry.label}
              </span>
            }
          >
            <div className="h-[260px]">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={apiTrendTelemetry.data}>
                  <CartesianGrid stroke="#ffffff" strokeOpacity={0.06} vertical={false} />
                  <XAxis dataKey="day" stroke="#82777a" tickLine={false} axisLine={false} />
                  <YAxis stroke="#82777a" tickLine={false} axisLine={false} />
                  <Tooltip contentStyle={{ background: '#171114', border: '1px solid #3a2024', borderRadius: 8 }} />
                  <Bar dataKey="events" fill="#ff3545" radius={[5, 5, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </Panel>

          <Panel title="Monitored API calls" subtitle={`Ingested API events from Supabase (${apiEvents.length} events)`}>
            {apiEvents.length ? (
              apiEvents.map((evt) => (
                <div key={evt.event_id} className="flex flex-wrap items-center gap-3 border-b border-white/[0.06] py-4">
                  <div className="min-w-0 flex-1">
                    <p className="text-xs font-semibold">{evt.actor_id} <span className="font-mono text-[11px] text-[#aaa0a2]">({evt.actor_type})</span></p>
                    <p className="mt-1 font-mono text-[11px] text-[#e8dfe1]">{evt.resource}</p>
                    <p className="mt-1 text-[10px] text-[#91878a]">{evt.description || evt.action} · {formatTimeAgo(evt.timestamp)}</p>
                  </div>
                  <Severity
                    value={
                      evt.risk_level
                        ? evt.risk_level.charAt(0).toUpperCase() + evt.risk_level.slice(1).toLowerCase()
                        : getRiskLevel(evt.risk_score)
                    }
                  />
                </div>
              ))
            ) : (
              <p className="py-6 text-center text-xs text-[#aaa0a2]">No explicit API events recorded yet.</p>
            )}
          </Panel>
        </>
      )
    }

    // VIEW 6: DLP VIOLATIONS
    if (page === 'DLP Violations') {
      return (
        <Panel
          title="Data Loss Prevention (DLP) alerts"
          subtitle={`Confirmed DLP violations & exfiltration alerts from Supabase (${dlpAlerts.length} alerts)`}
        >
          {dlpAlerts.length ? (
            dlpAlerts.map((alt) => (
              <div key={alt.alert_id} className="flex flex-wrap items-center gap-3 border-b border-white/[0.06] py-4">
                <div className="flex-1">
                  <p className="text-xs font-semibold text-[#f4eff0]">{alt.message}</p>
                  <p className="mt-1 font-mono text-[10px] text-[#aaa0a2]">
                    {alt.alert_id} · Type: {alt.alert_type} · {formatTimeAgo(alt.created_at)}
                  </p>
                </div>
                <Severity value={alt.severity} />
                <button
                  onClick={() => handleMarkAlertRead(alt.alert_id)}
                  disabled={alt.is_read}
                  className={`rounded-md border px-3 py-2 text-[10px] transition ${
                    alt.is_read
                      ? 'border-emerald-500/20 text-emerald-400 bg-emerald-500/10'
                      : 'border-white/10 hover:border-[#ff3545]/40 text-[#c4babc]'
                  }`}
                >
                  {alt.is_read ? 'Acknowledged' : 'Acknowledge'}
                </button>
              </div>
            ))
          ) : (
            <p className="py-8 text-center text-xs text-[#aaa0a2]">No active DLP or data exfiltration alerts in Supabase.</p>
          )}

          {dlpEvents.length > 0 && (
            <div className="mt-6 pt-4 border-t border-white/[0.06]">
              <p className="text-xs font-semibold text-[#ff3545] mb-3">Corresponding Flagged DLP / Exfiltration Events</p>
              <div className="space-y-3">
                {dlpEvents.map(evt => (
                  <div key={evt.event_id} className="rounded-lg bg-white/[0.02] border border-white/[0.05] p-3 text-xs">
                    <div className="flex justify-between items-center">
                      <span className="font-mono text-[11px] text-[#f4eff0]">{evt.resource}</span>
                      <Severity
                        value={
                          evt.risk_level
                            ? evt.risk_level.charAt(0).toUpperCase() + evt.risk_level.slice(1).toLowerCase()
                            : getRiskLevel(evt.risk_score)
                        }
                      />
                    </div>
                    <p className="mt-1 text-[11px] text-[#aaa0a2]">Actor: {evt.actor_id} | Rule: {evt.rule_result}</p>
                    <p className="mt-1 text-[10px] text-orange-300">Action: {evt.recommended_action || 'Review recommended'}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </Panel>
      )
    }

    // VIEW 7: RISK & RECOMMENDATIONS
    const riskLevel = getRiskLevel(calculatedRiskScore)
    const ringBorderColor =
      riskLevel === 'Critical'
        ? 'border-red-500/80'
        : riskLevel === 'High'
          ? 'border-orange-400/80'
          : riskLevel === 'Medium'
            ? 'border-yellow-400/80'
            : 'border-emerald-400/80'

    return (
      <>
        <div className="grid gap-4 lg:grid-cols-2">
          <Panel title="Risk posture" subtitle="Calculated aggregate score from live events">
            <div className="flex items-center gap-6 py-4">
              <div className={`flex h-32 w-32 items-center justify-center rounded-full border-[9px] ${ringBorderColor}`}>
                <div className="text-center">
                  <p className="text-3xl font-semibold tabular-nums">{calculatedRiskScore}</p>
                  <p className="text-[10px] text-[#aaa0a2]">of 100</p>
                </div>
              </div>
              <div>
                <Severity value={riskLevel} />
                <p className="mt-3 max-w-[220px] text-xs leading-5 text-[#aaa0a2]">
                  {threatsDetectedCount > 0
                    ? `${threatsDetectedCount} anomalous activities flagged by the Vishnu Isolation Forest engine.`
                    : 'System within standard behavioral baseline.'}
                </p>
              </div>
            </div>
          </Panel>

          <Panel
            title="Risk by data category"
            subtitle={
              events.length > 0
                ? `Observed sensitivity distribution across ${events.length} ingested events`
                : 'Observed sensitivity distribution (Demo / Baseline — waiting for event telemetry)'
            }
            action={
              <span className={`rounded-md px-2 py-1 text-[10px] ${
                events.length > 0
                  ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/20'
                  : 'bg-amber-400/10 text-amber-300 border border-amber-400/20'
              }`}>
                {events.length > 0 ? 'Live Telemetry' : 'Demo / Baseline'}
              </span>
            }
          >
            <div className="space-y-4">
              {[
                { name: 'Customer PII', count: events.filter(e => (e.resource || '').toLowerCase().includes('customer')).length, color: '#ff6b6b' },
                { name: 'Payroll & Finance', count: events.filter(e => (e.resource || '').toLowerCase().includes('payroll') || (e.resource || '').toLowerCase().includes('salary')).length, color: '#ff9f5a' },
                { name: 'System Credentials', count: events.filter(e => (e.resource || '').includes('.env') || (e.resource || '').includes('key')).length, color: '#f2c94c' },
                { name: 'Internal Documentation', count: events.filter(e => !e.is_sensitive).length, color: '#ff3545' },
              ].map(d => {
                const pct = events.length > 0 ? Math.round((d.count / events.length) * 100) : 0
                return (
                  <div key={d.name}>
                    <div className="mb-2 flex justify-between text-xs">
                      <span>{d.name}</span>
                      <span className="text-[#aaa0a2]">
                        {events.length > 0 ? `${d.count} events (${pct}%)` : '0 events (Baseline)'}
                      </span>
                    </div>
                    <div className="h-2 overflow-hidden rounded-full bg-white/[0.06]">
                      <div
                        className="h-full rounded-full transition-all duration-300"
                        style={{
                          width: `${events.length > 0 ? Math.max(pct, d.count > 0 ? 5 : 0) : 0}%`,
                          background: d.color
                        }}
                      />
                    </div>
                  </div>
                )
              })}
            </div>
          </Panel>
        </div>

        <Panel title="Actionable recommendations" subtitle="Generated by risk engine and Isolation Forest anomalies">
          {events.filter(e => e.recommended_action && e.recommended_action !== 'none').length ? (
            events
              .filter(e => e.recommended_action && e.recommended_action !== 'none')
              .map((evt) => (
                <div key={evt.event_id} className="flex flex-wrap items-center gap-3 border-b border-white/[0.06] py-4">
                  <div className="flex-1">
                    <p className="text-xs font-semibold capitalize">{evt.recommended_action?.replace(/_/g, ' ')}</p>
                    <p className="mt-1 text-[11px] text-[#aaa0a2]">
                      Target: {evt.resource} · Actor: {evt.actor_id} ({evt.source})
                    </p>
                  </div>
                  <Severity
                    value={
                      evt.risk_level
                        ? evt.risk_level.charAt(0).toUpperCase() + evt.risk_level.slice(1).toLowerCase()
                        : getRiskLevel(evt.risk_score)
                    }
                  />
                  <button
                    onClick={() => notify(`Action initiated: ${evt.recommended_action}`)}
                    className="rounded-md border border-white/10 px-3 py-2 text-[11px] hover:border-[#ff3545]/40"
                  >
                    Execute
                  </button>
                </div>
              ))
          ) : (
            <div className="space-y-4 py-2">
              <div className="flex items-center gap-3 p-3 rounded-lg bg-emerald-500/10 border border-emerald-500/20 text-xs text-emerald-300">
                <CheckCircle2 size={16} /> All active workloads are performing within nominal behavioral bounds.
              </div>
            </div>
          )}
        </Panel>
      </>
    )
  }

  if (!isAuthenticated) {
    return <AuthPage onLogin={() => setIsAuthenticated(true)} />
  }

  return (
    <div className="min-h-screen bg-[#070708] text-[#f4eff0]">
      {mobileOpen && (
        <button
          aria-label="Close menu"
          onClick={() => setMobileOpen(false)}
          className="fixed inset-0 z-40 bg-black/70 lg:hidden"
        />
      )}

      {/* Sidebar Navigation */}
      <aside className={`fixed inset-y-0 left-0 z-50 flex w-[248px] flex-col border-r border-white/[0.07] bg-[#0b0b0d] transition-transform lg:translate-x-0 ${mobileOpen ? 'translate-x-0' : '-translate-x-full'}`}>
        <div className="flex h-[72px] items-center gap-3 border-b border-white/[0.07] px-6">
          <div className="flex h-9 w-9 items-center justify-center rounded-xl bg-[#e52b35] text-white">
            <Shield size={21} />
          </div>
          <div>
            <p className="text-[15px] font-bold tracking-tight">AI SHIELD</p>
            <p className="text-[9px] tracking-[.18em] text-[#91878a]">SECURITY COMMAND</p>
          </div>
          <button onClick={() => setMobileOpen(false)} className="ml-auto lg:hidden">
            <X size={18} />
          </button>
        </div>

        <div className="px-4 pt-6">
          <p className="mb-3 px-2 text-[9px] font-semibold uppercase tracking-[.18em] text-[#82777a]">
            Workspace
          </p>
          <nav className="space-y-1">
            {navigation.map(item => {
              const Icon = item.icon
              const isIncidents = item.name === 'Incidents'

              return (
                <button
                  key={item.name}
                  onClick={() => {
                    setPage(item.name)
                    setMobileOpen(false)
                  }}
                  className={`flex w-full items-center gap-3 rounded-lg px-3 py-3 text-left text-xs transition ${
                    page === item.name
                      ? 'bg-[#ff3545]/10 font-semibold text-[#ff3545]'
                      : 'text-[#aaa0a2] hover:bg-white/[0.04] hover:text-white'
                  }`}
                >
                  <Icon size={16} />
                  {item.name}
                  {isIncidents && openIncidentsCount > 0 && (
                    <span className="ml-auto rounded bg-orange-400/10 px-2 py-0.5 text-[10px] text-orange-300">
                      {openIncidentsCount}
                    </span>
                  )}
                </button>
              )
            })}
          </nav>
        </div>

        <div className="mt-auto p-4">
          <div className="rounded-xl border border-[#ff3545]/15 bg-[#ff3545]/[0.04] p-3">
            <div className="flex items-center gap-2 text-[#ff3545]">
              <ShieldCheck size={15} />
              <span className="text-[11px] font-semibold">
                {health?.database === 'connected' ? 'Supabase Active' : 'Protection Active'}
              </span>
            </div>
            <p className="mt-2 text-[10px] leading-4 text-[#aaa0a2]">
              Connected to Supabase PostgreSQL with Vishnu Isolation Forest pipeline.
            </p>
          </div>

          <button onClick={() => notify('Settings are configured via backend .env')} className="mt-4 flex w-full items-center gap-3 px-3 py-2 text-xs text-[#aaa0a2] hover:text-white">
            <Settings size={15} /> Settings
          </button>

          <div className="mt-3 flex items-center gap-3 border-t border-white/[0.07] pt-4">
            <div className="flex h-8 w-8 items-center justify-center rounded-full bg-white/[0.08]">
              <UserRound size={16} />
            </div>
            <div>
              <p className="text-xs font-medium">SecOps Admin</p>
              <p className="text-[10px] text-[#91878a]">AI Shield Operator</p>
            </div>
            <MoreHorizontal className="ml-auto text-[#91878a]" size={17} />
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="min-h-screen lg:pl-[248px]">
        <header className="sticky top-0 z-30 flex h-[72px] items-center justify-between border-b border-white/[0.07] bg-[#070708]/90 px-4 backdrop-blur-xl sm:px-7">
          <div className="flex items-center gap-3">
            <button onClick={() => setMobileOpen(true)} className="lg:hidden">
              <Menu size={20} />
            </button>
            <div>
              <p className="text-xs text-[#aaa0a2]">
                Workspace <span className="mx-1 text-[#4f5954]">/</span>
                <span className="text-[#f4eff0]">{page}</span>
              </p>
            </div>
          </div>

          <div className="flex items-center gap-2 sm:gap-4">
            <div className="hidden items-center gap-2 rounded-full border border-emerald-500/20 bg-emerald-500/[0.06] px-3 py-1.5 sm:flex">
              <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
              <span className="text-[10px] text-emerald-400 font-medium">
                {health?.database === 'connected' ? 'Supabase Connected' : 'Live Gateway'}
              </span>
            </div>

            <button
              onClick={() => notify(unreadAlertsCount > 0 ? `${unreadAlertsCount} unread alert(s) in Supabase` : 'All alerts acknowledged')}
              className="relative rounded-lg p-2 text-[#aaa0a2] hover:bg-white/[0.05]"
              title="Alerts"
            >
              <AlertTriangle size={17} />
              {unreadAlertsCount > 0 && (
                <span className="absolute right-1.5 top-1.5 h-1.5 w-1.5 rounded-full bg-orange-400" />
              )}
            </button>

            <div className="hidden h-7 w-px bg-white/10 sm:block" />
            <span className="hidden text-[11px] text-[#aaa0a2] sm:block">AI Shield Console</span>
          </div>
        </header>

        <div className="mx-auto max-w-[1600px] p-4 sm:p-7">
          <div className="mb-6 flex flex-wrap items-end justify-between gap-4">
            <div>
              <div className="mb-2 flex items-center gap-2">
                <span className="h-1.5 w-1.5 rounded-full bg-[#ff3545]" />
                <span className="text-[10px] uppercase tracking-[.16em] text-[#ff3545]">
                  Security center
                </span>
              </div>
              <h1 className="text-2xl font-semibold tracking-tight sm:text-[28px]">
                {heading[page]}
              </h1>
              <p className="mt-2 text-xs text-[#aaa0a2]">{subtitle[page]}</p>
            </div>

            <div className="flex flex-wrap items-center gap-2">
              {page === 'Overview' && (
                <select
                  value={range}
                  onChange={e => setRange(e.target.value)}
                  className="rounded-lg border border-white/10 bg-[#101012] px-3 py-2 text-xs text-[#c5cec8] outline-none"
                >
                  <option>24 hours</option>
                  <option>7 days</option>
                  <option>30 days</option>
                </select>
              )}
              <button
                disabled={loading}
                onClick={() => loadData(true)}
                className="flex items-center gap-2 rounded-lg border border-white/10 bg-[#101012] px-3 py-2 text-xs text-[#c5cec8] hover:border-[#ff3545]/30 disabled:opacity-50 transition"
              >
                <RefreshCw size={14} className={loading ? 'animate-spin text-[#ff3545]' : ''} />
                {loading ? 'Syncing...' : 'Refresh'}
              </button>
            </div>
          </div>

          {page === 'Incidents' && (
            <div className="mb-4 flex flex-wrap items-center gap-2">
              <div className="flex min-w-[220px] flex-1 items-center gap-2 rounded-lg border border-white/10 bg-[#101012] px-3 py-2">
                <Search size={14} className="text-[#91878a]" />
                <input
                  value={query}
                  onChange={e => setQuery(e.target.value)}
                  placeholder="Search incidents by ID, title, actor..."
                  className="w-full bg-transparent text-xs outline-none placeholder:text-[#82777a]"
                />
              </div>
              <button onClick={() => setQuery('')} className="flex items-center gap-2 rounded-lg border border-white/10 px-3 py-2 text-xs text-[#c4babc]">
                <Filter size={13} /> Clear filter
              </button>
            </div>
          )}

          <div className="space-y-4">{renderPage()}</div>

          <div className="mt-8 flex flex-wrap items-center justify-between gap-2 border-t border-white/[0.06] pt-4 text-[10px] text-[#82777a]">
            <span>AI SHIELD · Trustworthy AI & Enterprise Data Protection</span>
            <span>Live Supabase PostgreSQL Gateway · Isolation Forest Pipeline</span>
          </div>
        </div>
      </main>

      {/* Incident Slide-over Detail Drawer with Live Status Update */}
      {selectedIncident && (
        <div className="fixed inset-0 z-[60] flex justify-end bg-black/60" onClick={() => setSelectedIncident(null)}>
          <div
            onClick={e => e.stopPropagation()}
            className="h-full w-full max-w-[440px] overflow-y-auto border-l border-white/10 bg-[#101012] p-6 shadow-2xl"
          >
            <div className="flex items-center justify-between">
              <span className="text-[10px] uppercase tracking-widest text-[#ff3545]">
                Incident details
              </span>
              <button onClick={() => setSelectedIncident(null)}>
                <X size={18} />
              </button>
            </div>

            <h2 className="mt-6 text-xl font-semibold">{selectedIncident.title}</h2>
            <p className="mt-2 text-xs text-[#aaa0a2]">
              {selectedIncident.incident_id} · {formatTimeAgo(selectedIncident.created_at)}
            </p>

            <div className="mt-5">
              <Severity value={selectedIncident.severity} />
            </div>

            <div className="mt-7 space-y-4">
              {[
                ['Incident ID', selectedIncident.incident_id],
                ['Actor ID', selectedIncident.actor_id || 'System / External'],
                ['Event Reference', selectedIncident.event_id || 'Direct Incident'],
                ['Assigned Analyst', selectedIncident.assigned_to || 'Unassigned'],
                ['Current Status', selectedIncident.status.toUpperCase()],
                ['Description', selectedIncident.description],
                ['Updated At', selectedIncident.updated_at || selectedIncident.created_at],
              ].map(([a, b]) => (
                <div key={a} className="border-b border-white/[0.07] pb-3">
                  <p className="text-[10px] text-[#91878a]">{a}</p>
                  <p className="mt-1 text-sm font-medium">{b}</p>
                </div>
              ))}
            </div>

            <div className="mt-7 rounded-lg border border-orange-400/15 bg-orange-400/[0.04] p-4">
              <p className="text-xs font-semibold text-orange-300">Suggested Action</p>
              <p className="mt-2 text-xs leading-5 text-[#c4babc]">
                Review the associated event log, verify user permissions with HR/SecOps, and transition status to investigating.
              </p>
            </div>

            <button
              disabled={isUpdating}
              onClick={handleUpdateIncidentStatus}
              className="mt-6 w-full rounded-lg bg-[#e52b35] py-3 text-xs font-bold text-white transition hover:bg-[#ff3545] disabled:opacity-50"
            >
              {isUpdating
                ? 'Updating in Supabase...'
                : selectedIncident.status === 'investigating'
                  ? 'Mark as Resolved'
                  : 'Mark for Investigation'}
            </button>
          </div>
        </div>
      )}

      {/* Persistent Notification Toast */}
      {notice && (
        <div className="fixed bottom-5 right-5 z-[80] rounded-lg border border-[#ff3545]/20 bg-[#111a17] px-4 py-3 text-xs text-[#ff3545] shadow-xl">
          {notice}
        </div>
      )}
    </div>
  )
}

export default App
