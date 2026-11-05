import { useState, type ReactNode } from 'react'
import {
  Activity, AlertTriangle, Bot,
  Database, FileText, Filter, Gauge, Globe, LayoutDashboard,
  LockKeyhole, Menu, MoreHorizontal, Network, Search, Settings,
  Shield, ShieldAlert, ShieldCheck,
  UserRound, Users, X
} from 'lucide-react'
import {
  Area, AreaChart, Bar, BarChart, CartesianGrid, ResponsiveContainer,
  Tooltip, XAxis, YAxis
} from 'recharts'
import AuthPage from './AuthPage'

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

const incidents = [
  { id: 'INC-2048', title: 'Sensitive customer data downloaded', actor: 'Rahul Sharma', type: 'Employee', resource: 'customer_data.csv', severity: 'Critical', time: '2 min ago', status: 'Open' },
  { id: 'INC-2047', title: 'Unauthorized AI agent access', actor: 'unknown_agent', type: 'AI Agent', resource: 'invoices.csv', severity: 'High', time: '8 min ago', status: 'Investigating' },
  { id: 'INC-2046', title: 'External file sharing detected', actor: 'Priya Reddy', type: 'Employee', resource: 'salary_details.xlsx', severity: 'High', time: '21 min ago', status: 'Open' },
  { id: 'INC-2045', title: 'Unusual API request volume', actor: 'api_client_07', type: 'API Client', resource: '/api/customers', severity: 'Medium', time: '34 min ago', status: 'Resolved' },
  { id: 'INC-2044', title: 'Repeated access denied', actor: 'unknown_agent', type: 'AI Agent', resource: 'employee_records.csv', severity: 'Medium', time: '1 hr ago', status: 'Open' },
]

const activity = [
  { actor: 'Rahul Sharma', action: 'Downloaded', resource: 'customer_data.csv', time: '2 min ago', risk: 'Critical' },
  { actor: 'unknown_agent', action: 'Attempted access', resource: 'invoices.csv', time: '8 min ago', risk: 'High' },
  { actor: 'Priya Reddy', action: 'Shared externally', resource: 'salary_details.xlsx', time: '21 min ago', risk: 'High' },
  { actor: 'api_client_07', action: 'API requests', resource: '/api/customers', time: '34 min ago', risk: 'Medium' },
  { actor: 'Amit Kumar', action: 'Viewed', resource: 'company_report.pdf', time: '42 min ago', risk: 'Low' },
]

const trendData = [
  { day: 'Mon', events: 32, threats: 5 },
  { day: 'Tue', events: 45, threats: 8 },
  { day: 'Wed', events: 38, threats: 4 },
  { day: 'Thu', events: 62, threats: 12 },
  { day: 'Fri', events: 52, threats: 9 },
  { day: 'Sat', events: 76, threats: 16 },
  { day: 'Sun', events: 58, threats: 7 },
]

const exposure = [
  { source: 'Employees', detail: '12 active users', icon: Users, color: '#ff3545' },
  { source: 'AI Agents', detail: '4 connected agents', icon: Bot, color: '#d16b75' },
  { source: 'Connected apps', detail: '8 integrations', icon: Globe, color: '#b77b83' },
]

const dataTypes = [
  { name: 'Customer PII', value: 82, color: '#ff6b6b' },
  { name: 'Payroll data', value: 64, color: '#ff9f5a' },
  { name: 'Contracts', value: 43, color: '#f2c94c' },
  { name: 'Source code', value: 28, color: '#ff3545' },
]

function Severity({ value }: { value: string }) {
  const colors: Record<string, string> = {
    Critical: 'bg-red-400/10 text-red-400 border-red-400/20',
    High: 'bg-orange-400/10 text-orange-300 border-orange-400/20',
    Medium: 'bg-yellow-400/10 text-yellow-300 border-yellow-400/20',
    Low: 'bg-slate-400/10 text-slate-300 border-slate-400/20',
  }

  return (
    <span className={`inline-flex rounded-md border px-2 py-1 text-[11px] font-semibold ${colors[value] || colors.Low}`}>
      {value}
    </span>
  )
}

function Status({ value }: { value: string }) {
  const color =
    value === 'Resolved'
      ? 'text-emerald-300'
      : value === 'Investigating'
        ? 'text-blue-300'
        : 'text-orange-300'

  return <span className={`text-xs ${color}`}>● {value}</span>
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
  const [selected, setSelected] = useState<typeof incidents[number] | null>(null)
  const [mobileOpen, setMobileOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [notice, setNotice] = useState('')
  const [isAuthenticated, setIsAuthenticated] = useState(false)

  const notify = (message: string) => {
    setNotice(message)
    window.setTimeout(() => setNotice(''), 2800)
  }

  const filteredIncidents = incidents.filter(item =>
    `${item.id} ${item.title} ${item.actor} ${item.resource}`
      .toLowerCase()
      .includes(query.toLowerCase())
  )

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
    Overview: 'Monitor your organization’s security posture in one place.',
    Incidents: 'Investigate, prioritize and resolve security incidents.',
    Activity: 'A unified timeline of employee and AI agent activity.',
    'Files & Sharing': 'Track sensitive files and external sharing activity.',
    'API Monitor': 'Monitor API traffic, unusual requests and access patterns.',
    'DLP Violations': 'Identify and review potential data loss events.',
    'Risk & Recommendations': 'Understand risk exposure and take recommended action.',
  }

  const stats = [
    { label: 'Events monitored', value: '2,481', change: '+12.8%', icon: Activity, color: 'text-[#ff3545]', up: true },
    { label: 'Open incidents', value: '08', change: '+2 today', icon: AlertTriangle, color: 'text-orange-300', up: true },
    { label: 'Sensitive files', value: '124', change: 'Across 5 categories', icon: Database, color: 'text-blue-300', up: false },
    { label: 'Threats blocked', value: '36', change: '+8.4%', icon: ShieldCheck, color: 'text-emerald-300', up: true },
  ]

  const table = (items: typeof incidents) => (
    <div className="overflow-x-auto">
      <table className="w-full min-w-[680px] text-left">
        <thead>
          <tr className="border-b border-white/[0.07] text-[10px] uppercase tracking-wider text-[#91878a]">
            <th className="pb-3 font-medium">Incident</th>
            <th className="pb-3 font-medium">Actor</th>
            <th className="pb-3 font-medium">Resource</th>
            <th className="pb-3 font-medium">Severity</th>
            <th className="pb-3 font-medium">Time</th>
            <th className="pb-3 font-medium">Status</th>
          </tr>
        </thead>
        <tbody>
          {items.map(item => (
            <tr
              key={item.id}
              onClick={() => setSelected(item)}
              className="cursor-pointer border-b border-white/[0.045] transition hover:bg-white/[0.025]"
            >
              <td className="py-4 pr-4">
                <p className="text-xs font-medium text-[#f0e9ea]">{item.title}</p>
                <p className="mt-1 text-[10px] text-[#91878a]">{item.id}</p>
              </td>
              <td className="py-4 pr-4 text-xs text-[#d5ccce]">
                {item.actor}
                <p className="mt-1 text-[10px] text-[#91878a]">{item.type}</p>
              </td>
              <td className="py-4 pr-4 font-mono text-[11px] text-[#c4babc]">
                {item.resource}
              </td>
              <td className="py-4 pr-4">
                <Severity value={item.severity} />
              </td>
              <td className="py-4 pr-4 text-xs text-[#87928c]">{item.time}</td>
              <td className="py-4">
                <Status value={item.status} />
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )

  const activityList = (items = activity) => (
    <div className="space-y-4">
      {items.map((item, i) => (
        <div key={i} className="flex items-start gap-3">
          <div className="mt-1 h-2 w-2 shrink-0 rounded-full bg-[#ff3545]" />
          <div className="min-w-0 flex-1">
            <p className="text-xs text-[#e8dfe1]">
              <span className="font-semibold">{item.actor}</span>{' '}
              <span className="text-[#aaa0a2]">{item.action}</span>
            </p>
            <p className="mt-1 truncate font-mono text-[11px] text-[#aaa0a2]">
              {item.resource}
            </p>
            <p className="mt-1 text-[10px] text-[#82777a]">{item.time}</p>
          </div>
          <Severity value={item.risk} />
        </div>
      ))}
    </div>
  )

  const overview = (
    <>
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

      <div className="grid gap-4 xl:grid-cols-[1.5fr_1fr]">
        <Panel
          title="Security events"
          subtitle="Event volume and detected threats"
          action={
            <span className="rounded-md bg-white/[0.04] px-2 py-1 text-[10px] text-[#ff3545]">
              Last {range}
            </span>
          }
        >
          <div className="h-[250px] w-full">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trendData}>
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
            <span><span className="mr-2 inline-block h-2 w-2 rounded-full bg-[#ff3545]" />Events</span>
            <span><span className="mr-2 inline-block h-2 w-2 rounded-full bg-[#ff9f5a]" />Threats</span>
          </div>
        </Panel>

        <Panel title="Exposure flow" subtitle="Where sensitive data can move">
          <div className="space-y-3">
            {exposure.map(source => {
              const Icon = source.icon

              return (
                <div key={source.source} className="flex items-center gap-3 rounded-lg border border-white/[0.06] bg-white/[0.02] p-3">
                  <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-white/[0.04]" style={{ color: source.color }}>
                    <Icon size={17} />
                  </div>
                  <div className="min-w-0 flex-1">
                    <p className="text-xs font-medium">{source.source}</p>
                    <p className="mt-1 text-[10px] text-[#aaa0a2]">{source.detail}</p>
                  </div>
                  <div className="text-[#82777a]"><MoreHorizontal size={17} /></div>
                </div>
              )
            })}

            <div className="flex justify-center py-1 text-[#82777a]">
              <Network size={17} />
            </div>

            <div className="rounded-lg border border-orange-400/15 bg-orange-400/[0.04] p-3">
              <p className="text-[10px] font-semibold uppercase tracking-wider text-orange-300">
                Sensitive data destinations
              </p>
              <div className="mt-3 flex flex-wrap gap-2">
                {['External email', 'Public links', 'AI tools', 'Personal storage'].map(x => (
                  <span key={x} className="rounded-md border border-orange-300/10 bg-orange-300/[0.05] px-2 py-1 text-[10px] text-[#c7a58e]">
                    {x}
                  </span>
                ))}
              </div>
            </div>
          </div>
        </Panel>
      </div>

      <div className="grid gap-4 xl:grid-cols-[1.5fr_1fr]">
        <Panel
          title="Recent incidents"
          subtitle="Latest security events requiring attention"
          action={
            <button onClick={() => setPage('Incidents')} className="text-[11px] text-[#ff3545] hover:underline">
              View all →
            </button>
          }
        >
          {table(incidents.slice(0, 4))}
        </Panel>

        <Panel title="Live activity feed" subtitle="Recent employee and agent actions">
          {activityList(activity.slice(0, 4))}
        </Panel>
      </div>
    </>
  )

  const renderPage = () => {
    if (page === 'Overview') return overview

    if (page === 'Incidents') {
      return (
        <Panel title="All incidents" subtitle={`${filteredIncidents.length} incidents found`}>
          {filteredIncidents.length
            ? table(filteredIncidents)
            : <p className="py-8 text-center text-xs text-[#aaa0a2]">No incidents match your search.</p>}
        </Panel>
      )
    }

    if (page === 'Activity') {
      return (
        <Panel title="Activity timeline" subtitle="Illustrative employee and AI agent activity">
          {activityList()}
        </Panel>
      )
    }

    if (page === 'Files & Sharing') {
      const files = [
        ['customer_data.csv', 'Customer PII', 'Rahul Sharma', 'Downloaded', 'Critical'],
        ['salary_details.xlsx', 'Payroll', 'Priya Reddy', 'External share', 'High'],
        ['invoices.csv', 'Financial', 'unknown_agent', 'Access attempted', 'High'],
        ['company_report.pdf', 'Internal', 'Amit Kumar', 'Viewed', 'Low'],
        ['employee_records.csv', 'Employee PII', 'unknown_agent', 'Access denied', 'Medium'],
      ]

      return (
        <Panel title="File activity" subtitle="Sample sensitive file inventory and activity">
          <div className="overflow-x-auto">
            <table className="w-full min-w-[650px] text-left text-xs">
              <thead className="text-[10px] uppercase tracking-wider text-[#91878a]">
                <tr className="border-b border-white/10">
                  <th className="pb-3">File</th>
                  <th className="pb-3">Category</th>
                  <th className="pb-3">Actor</th>
                  <th className="pb-3">Activity</th>
                  <th className="pb-3">Risk</th>
                </tr>
              </thead>
              <tbody>
                {files.map(([file, category, actor, action, risk]) => (
                  <tr key={file} className="border-b border-white/[0.05]">
                    <td className="py-4 font-mono text-[#e2d9db]">{file}</td>
                    <td className="py-4 text-[#aaa0a2]">{category}</td>
                    <td className="py-4">{actor}</td>
                    <td className="py-4 text-[#aaa0a2]">{action}</td>
                    <td className="py-4"><Severity value={risk} /></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Panel>
      )
    }

    if (page === 'API Monitor') {
      return (
        <>
          <Panel title="API request volume" subtitle="Illustrative requests per day">
            <div className="h-[280px]">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={trendData}>
                  <CartesianGrid stroke="#ffffff" strokeOpacity={0.06} vertical={false} />
                  <XAxis dataKey="day" stroke="#82777a" tickLine={false} axisLine={false} />
                  <YAxis stroke="#82777a" tickLine={false} axisLine={false} />
                  <Tooltip contentStyle={{ background: '#171114', border: '1px solid #3a2024', borderRadius: 8 }} />
                  <Bar dataKey="events" fill="#ff3545" radius={[5, 5, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </Panel>

          <Panel title="Suspicious API requests" subtitle="Sample request events">
            {[
              ['api_client_07', '/api/customers', '1,240 requests / min', 'Critical'],
              ['unknown_agent', '/api/invoices', 'Repeated denied access', 'High'],
              ['service_user_03', '/api/employees', 'Unusual access time', 'Medium'],
            ].map(([actor, endpoint, detail, risk]) => (
              <div key={actor} className="flex flex-wrap items-center gap-3 border-b border-white/[0.06] py-4">
                <div className="min-w-0 flex-1">
                  <p className="text-xs font-semibold">{actor}</p>
                  <p className="mt-1 font-mono text-[11px] text-[#aaa0a2]">{endpoint}</p>
                  <p className="mt-1 text-[10px] text-[#91878a]">{detail}</p>
                </div>
                <Severity value={risk} />
              </div>
            ))}
          </Panel>
        </>
      )
    }

    if (page === 'DLP Violations') {
      return (
        <Panel title="Data loss prevention events" subtitle="Illustrative policy violations">
          {[
            ['Sensitive customer data sent to external email', 'customer_data.csv', 'Rahul Sharma', 'Critical'],
            ['Payroll file shared outside organization', 'salary_details.xlsx', 'Priya Reddy', 'High'],
            ['AI agent attempted restricted file access', 'employee_records.csv', 'unknown_agent', 'High'],
            ['Unusual bulk download detected', 'invoices.csv', 'api_client_07', 'Medium'],
          ].map(([title, file, actor, risk], i) => (
            <div key={i} className="flex flex-wrap items-center gap-3 border-b border-white/[0.06] py-4">
              <div className="flex-1">
                <p className="text-xs font-semibold">{title}</p>
                <p className="mt-1 font-mono text-[10px] text-[#aaa0a2]">{file} · {actor}</p>
              </div>
              <Severity value={risk} />
              <button onClick={() => notify('Demo: policy action selected')} className="rounded-md border border-white/10 px-3 py-2 text-[10px] hover:border-[#ff3545]/40">
                Review
              </button>
            </div>
          ))}
        </Panel>
      )
    }

    return (
      <>
        <div className="grid gap-4 lg:grid-cols-2">
          <Panel title="Risk posture" subtitle="Illustrative risk score">
            <div className="flex items-center gap-6 py-4">
              <div className="flex h-32 w-32 items-center justify-center rounded-full border-[9px] border-orange-400/70">
                <div className="text-center">
                  <p className="text-3xl font-semibold">72</p>
                  <p className="text-[10px] text-[#aaa0a2]">of 100</p>
                </div>
              </div>
              <div>
                <Severity value="High" />
                <p className="mt-3 max-w-[190px] text-xs leading-5 text-[#aaa0a2]">
                  Several high-risk activities need investigation and access review.
                </p>
              </div>
            </div>
          </Panel>

          <Panel title="Risk by data category" subtitle="Relative exposure indicator">
            <div className="space-y-5">
              {dataTypes.map(d => (
                <div key={d.name}>
                  <div className="mb-2 flex justify-between text-xs">
                    <span>{d.name}</span>
                    <span className="text-[#aaa0a2]">{d.value}%</span>
                  </div>
                  <div className="h-2 overflow-hidden rounded-full bg-white/[0.06]">
                    <div className="h-full rounded-full" style={{ width: `${d.value}%`, background: d.color }} />
                  </div>
                </div>
              ))}
            </div>
          </Panel>
        </div>

        <Panel title="Recommended actions" subtitle="Suggested actions based on the illustrative events">
          {[
            ['Restrict unknown agent access', 'Review and reduce permissions for unknown_agent.', 'High'],
            ['Investigate customer data download', 'Verify whether the download was authorized.', 'Critical'],
            ['Review external sharing policy', 'Check sharing permissions on payroll files.', 'High'],
            ['Enable API rate limits', 'Apply tighter limits to unusual API clients.', 'Medium'],
          ].map(([title, desc, level], i) => (
            <div key={i} className="flex flex-wrap items-center gap-3 border-b border-white/[0.06] py-4">
              <div className="flex-1">
                <p className="text-xs font-semibold">{title}</p>
                <p className="mt-1 text-[11px] text-[#aaa0a2]">{desc}</p>
              </div>
              <Severity value={level} />
              <button onClick={() => notify('Demo action selected: ' + title)} className="rounded-md border border-white/10 px-3 py-2 text-[11px] hover:border-[#ff3545]/40">
                Review
              </button>
            </div>
          ))}
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

              return (
                <button
                  key={item.name}
                  onClick={() => {
                    setPage(item.name)
                    setMobileOpen(false)
                  }}
                  className={`flex w-full items-center gap-3 rounded-lg px-3 py-3 text-left text-xs transition ${page === item.name ? 'bg-[#ff3545]/10 font-semibold text-[#ff3545]' : 'text-[#aaa0a2] hover:bg-white/[0.04] hover:text-white'}`}
                >
                  <Icon size={16} />
                  {item.name}
                  {item.name === 'Incidents' && (
                    <span className="ml-auto rounded bg-orange-400/10 px-2 py-0.5 text-[10px] text-orange-300">
                      8
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
              <span className="text-[11px] font-semibold">Protection active</span>
            </div>
            <p className="mt-2 text-[10px] leading-4 text-[#aaa0a2]">
              Demo environment. Some monitoring data is simulated.
            </p>
          </div>

          <button onClick={() => notify('Settings are not connected in this demo')} className="mt-4 flex w-full items-center gap-3 px-3 py-2 text-xs text-[#aaa0a2] hover:text-white">
            <Settings size={15} /> Settings
          </button>

          <div className="mt-3 flex items-center gap-3 border-t border-white/[0.07] pt-4">
            <div className="flex h-8 w-8 items-center justify-center rounded-full bg-white/[0.08]">
              <UserRound size={16} />
            </div>
            <div>
              <p className="text-xs font-medium">Admin User</p>
              <p className="text-[10px] text-[#91878a]">Organization owner</p>
            </div>
            <MoreHorizontal className="ml-auto text-[#91878a]" size={17} />
          </div>
        </div>
      </aside>

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
            <div className="hidden items-center gap-2 rounded-full border border-[#ff3545]/15 bg-[#ff3545]/[0.04] px-3 py-1.5 sm:flex">
              <span className="h-1.5 w-1.5 rounded-full bg-[#ff3545]" />
              <span className="text-[10px] text-[#ff3545]">Demo environment</span>
            </div>
            <button onClick={() => notify('No new notifications')} className="relative rounded-lg p-2 text-[#aaa0a2] hover:bg-white/[0.05]">
              <AlertTriangle size={17} />
              <span className="absolute right-1.5 top-1.5 h-1.5 w-1.5 rounded-full bg-orange-400" />
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
              <button onClick={() => notify('Demo data refreshed')} className="flex items-center gap-2 rounded-lg border border-white/10 bg-[#101012] px-3 py-2 text-xs text-[#c5cec8] hover:border-[#ff3545]/30">
                <Activity size={14} /> Refresh
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
                  placeholder="Search incidents..."
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
            <span>AI SHIELD · Trustworthy AI & Data Protection</span>
            <span>Prototype dashboard · Demo data · Not a live security feed</span>
          </div>
        </div>
      </main>

      {selected && (
        <div className="fixed inset-0 z-[60] flex justify-end bg-black/60" onClick={() => setSelected(null)}>
          <div
            onClick={e => e.stopPropagation()}
            className="h-full w-full max-w-[440px] overflow-y-auto border-l border-white/10 bg-[#101012] p-6 shadow-2xl"
          >
            <div className="flex items-center justify-between">
              <span className="text-[10px] uppercase tracking-widest text-[#ff3545]">
                Incident details
              </span>
              <button onClick={() => setSelected(null)}>
                <X size={18} />
              </button>
            </div>

            <h2 className="mt-6 text-xl font-semibold">{selected.title}</h2>
            <p className="mt-2 text-xs text-[#aaa0a2]">
              {selected.id} · {selected.time}
            </p>

            <div className="mt-5">
              <Severity value={selected.severity} />
            </div>

            <div className="mt-7 space-y-4">
              {[
                ['Actor', selected.actor],
                ['Actor type', selected.type],
                ['Resource', selected.resource],
                ['Status', selected.status],
                ['Event source', 'Simulated demo event'],
              ].map(([a, b]) => (
                <div key={a} className="border-b border-white/[0.07] pb-3">
                  <p className="text-[10px] text-[#91878a]">{a}</p>
                  <p className="mt-1 text-sm">{b}</p>
                </div>
              ))}
            </div>

            <div className="mt-7 rounded-lg border border-orange-400/15 bg-orange-400/[0.04] p-4">
              <p className="text-xs font-semibold text-orange-300">Suggested investigation</p>
              <p className="mt-2 text-xs leading-5 text-[#c4babc]">
                Verify the actor's identity, confirm whether the resource access was authorized,
                and review relevant access permissions.
              </p>
            </div>

            <button
              onClick={() => {
                notify('Demo: incident marked for review')
                setSelected(null)
              }}
              className="mt-6 w-full rounded-lg bg-[#e52b35] py-3 text-xs font-bold text-white"
            >
              Mark for review
            </button>
          </div>
        </div>
      )}

      {notice && (
        <div className="fixed bottom-5 right-5 z-[80] rounded-lg border border-[#ff3545]/20 bg-[#111a17] px-4 py-3 text-xs text-[#ff3545] shadow-xl">
          {notice}
        </div>
      )}
    </div>
  )
}

export default App