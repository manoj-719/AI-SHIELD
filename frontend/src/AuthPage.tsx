
import { useState, type FormEvent } from 'react'
import {
  ArrowRight,
  ShieldCheck,
  UserRound,
  Building2,
  Mail,
  LockKeyhole,
  Eye,
  EyeOff,
  Activity,
  BrainCircuit,
  Database,
  ChartNoAxesCombined,
} from 'lucide-react'
import BrandLogo from './components/BrandLogo'

type AuthPageProps = {
  onLogin: () => void
}

export default function AuthPage({ onLogin }: AuthPageProps) {
  const [mode, setMode] = useState<'signup' | 'login'>('signup')
  const [showPassword, setShowPassword] = useState(false)
  const [name, setName] = useState('')
  const [business, setBusiness] = useState('')
  const [email, setEmail] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')

  function handleSubmit(e: FormEvent<HTMLFormElement>) {
    e.preventDefault()
    setError('')

    if (mode === 'signup' && (!name.trim() || !business.trim())) {
      setError('Please enter your name and business name.')
      return
    }

    if (!email.trim() || !password) {
      setError('Please enter your email and password.')
      return
    }

    if (password.length < 8) {
      setError('Password must contain at least 8 characters.')
      return
    }

    // Demo navigation until real authentication is connected.
    onLogin()
  }

  return (
    <main className="relative min-h-screen overflow-hidden bg-[#070708] text-white">
      {/* Background effects */}
      <div className="pointer-events-none absolute -left-40 top-20 h-96 w-96 rounded-full bg-red-600/10 blur-[130px]" />
      <div className="pointer-events-none absolute -right-40 bottom-0 h-96 w-96 rounded-full bg-red-800/10 blur-[130px]" />

      <div className="relative z-10 mx-auto flex min-h-screen max-w-[1600px] flex-col lg:flex-row">

        {/* LEFT BRANDING SECTION */}
        <section className="flex w-full flex-col justify-between px-7 py-8 sm:px-12 lg:w-[52%] lg:px-16 lg:py-12">

          <header>
            <BrandLogo />
          </header>

          <div className="mx-auto my-12 w-full max-w-xl lg:my-0">

            {/* Shield illustration */}
            <div className="relative mx-auto mb-8 flex h-64 w-64 items-center justify-center sm:h-80 sm:w-80">
              <div className="absolute inset-4 rounded-full border border-red-500/10" />
              <div className="absolute inset-10 rounded-full border border-red-500/15" />
              <div className="absolute inset-0 rounded-full bg-red-600/10 blur-3xl" />

              <div className="absolute h-56 w-56 rounded-full border border-red-500/20 shadow-[0_0_50px_rgba(239,40,50,0.12)] sm:h-72 sm:w-72" />

              <div className="relative flex h-40 w-40 items-center justify-center rounded-[40px] border border-red-500/30 bg-gradient-to-br from-[#241013] to-[#0c0c0e] shadow-[0_0_60px_rgba(239,40,50,0.2)] sm:h-48 sm:w-48">
                <BrandLogo compact />
              </div>

              <div className="absolute bottom-2 h-5 w-48 rounded-full bg-red-500/20 blur-xl" />
            </div>

            <div className="text-center">
              <p className="mb-3 text-xs font-semibold uppercase tracking-[5px] text-red-500">
                Intelligent protection
              </p>

              <h1 className="text-4xl font-black tracking-tight sm:text-6xl">
                <span className="text-red-500">AI</span> SHIELD
              </h1>

              <p className="mt-4 text-sm font-semibold uppercase tracking-[5px] text-gray-300 sm:text-base">
                YOUR SECURITY. OUR PRIORITY.
              </p>

              <div className="mx-auto mt-6 h-[2px] w-20 bg-red-500" />

              <h2 className="mt-7 text-xl font-semibold text-white sm:text-2xl">
                Monitor. Protect. Prevent.
              </h2>

              <p className="mx-auto mt-3 max-w-md text-sm leading-7 text-gray-400 sm:text-base">
                Enterprise-grade AI security for a safer, smarter business.
              </p>
            </div>

            {/* Feature cards */}
            <div className="mt-10 grid grid-cols-2 gap-3 sm:grid-cols-4">
              {[
                { icon: ShieldCheck, label: 'Threat Detection' },
                { icon: BrainCircuit, label: 'AI Risk Analysis' },
                { icon: Database, label: 'Data Protection' },
                { icon: ChartNoAxesCombined, label: 'Security Analytics' },
              ].map(({ icon: Icon, label }) => (
                <div
                  key={label}
                  className="rounded-xl border border-white/[0.08] bg-white/[0.025] px-3 py-5 text-center transition-all duration-300 hover:border-red-500/40 hover:bg-red-500/[0.04]"
                >
                  <Icon className="mx-auto mb-3 h-6 w-6 text-red-400" />
                  <p className="text-xs font-medium text-gray-300">{label}</p>
                </div>
              ))}
            </div>
          </div>

          <footer className="hidden items-center justify-between text-xs text-gray-600 lg:flex">
            <span>AI Shield Security Platform</span>
            <span>Monitor · Protect · Prevent</span>
          </footer>
        </section>

        {/* RIGHT AUTH SECTION */}
        <section className="flex w-full items-center justify-center px-5 pb-12 sm:px-10 lg:w-[48%] lg:px-12 lg:py-12">

          <div className="w-full max-w-[510px] rounded-2xl border border-white/10 bg-[#101012]/90 p-6 shadow-[0_0_80px_rgba(0,0,0,0.5)] backdrop-blur-xl sm:p-9">

            <div className="mb-8">
              <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-red-500/20 bg-red-500/[0.07] px-3 py-1.5 text-xs font-medium text-red-400">
                <Activity size={14} />
                Secure business access
              </div>

              <h2 className="text-3xl font-bold tracking-tight">
                {mode === 'signup' ? (
                  <>Create your <span className="text-red-500">account</span></>
                ) : (
                  <>Welcome <span className="text-red-500">back</span></>
                )}
              </h2>

              <p className="mt-3 text-sm leading-6 text-gray-400">
                {mode === 'signup'
                  ? 'Start protecting your business with AI Shield.'
                  : 'Sign in to access your AI Shield security dashboard.'}
              </p>
            </div>

            {/* Login / Signup switch */}
            <div className="mb-8 grid grid-cols-2 rounded-xl border border-white/[0.08] bg-black/40 p-1">
              <button
                type="button"
                onClick={() => {
                  setMode('signup')
                  setError('')
                }}
                className={`rounded-lg py-3 text-sm font-semibold transition-all ${
                  mode === 'signup'
                    ? 'bg-red-600 text-white shadow-[0_0_20px_rgba(220,38,38,0.25)]'
                    : 'text-gray-400 hover:text-white'
                }`}
              >
                Create account
              </button>

              <button
                type="button"
                onClick={() => {
                  setMode('login')
                  setError('')
                }}
                className={`rounded-lg py-3 text-sm font-semibold transition-all ${
                  mode === 'login'
                    ? 'bg-red-600 text-white shadow-[0_0_20px_rgba(220,38,38,0.25)]'
                    : 'text-gray-400 hover:text-white'
                }`}
              >
                Log in
              </button>
            </div>

            <form onSubmit={handleSubmit} className="space-y-5">

              {mode === 'signup' && (
                <>
                  <div>
                    <label className="mb-2 block text-sm font-medium text-gray-300">
                      Full name
                    </label>
                    <div className="relative">
                      <UserRound className="absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-gray-500" />
                      <input
                        value={name}
                        onChange={(e) => setName(e.target.value)}
                        placeholder="Your full name"
                        autoComplete="name"
                        className="w-full rounded-xl border border-white/10 bg-[#171719] py-3.5 pl-12 pr-4 text-sm text-white outline-none transition-all placeholder:text-gray-600 focus:border-red-500/70 focus:ring-2 focus:ring-red-500/10"
                      />
                    </div>
                  </div>

                  <div>
                    <label className="mb-2 block text-sm font-medium text-gray-300">
                      Business name
                    </label>
                    <div className="relative">
                      <Building2 className="absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-gray-500" />
                      <input
                        value={business}
                        onChange={(e) => setBusiness(e.target.value)}
                        placeholder="Your company name"
                        autoComplete="organization"
                        className="w-full rounded-xl border border-white/10 bg-[#171719] py-3.5 pl-12 pr-4 text-sm text-white outline-none transition-all placeholder:text-gray-600 focus:border-red-500/70 focus:ring-2 focus:ring-red-500/10"
                      />
                    </div>
                  </div>
                </>
              )}

              <div>
                <label className="mb-2 block text-sm font-medium text-gray-300">
                  Business email
                </label>
                <div className="relative">
                  <Mail className="absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-gray-500" />
                  <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="you@company.com"
                    autoComplete="email"
                    className="w-full rounded-xl border border-white/10 bg-[#171719] py-3.5 pl-12 pr-4 text-sm text-white outline-none transition-all placeholder:text-gray-600 focus:border-red-500/70 focus:ring-2 focus:ring-red-500/10"
                  />
                </div>
              </div>

              <div>
                <label className="mb-2 block text-sm font-medium text-gray-300">
                  Password
                </label>
                <div className="relative">
                  <LockKeyhole className="absolute left-4 top-1/2 h-5 w-5 -translate-y-1/2 text-gray-500" />
                  <input
                    type={showPassword ? 'text' : 'password'}
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    placeholder="Enter at least 8 characters"
                    autoComplete={mode === 'signup' ? 'new-password' : 'current-password'}
                    className="w-full rounded-xl border border-white/10 bg-[#171719] py-3.5 pl-12 pr-12 text-sm text-white outline-none transition-all placeholder:text-gray-600 focus:border-red-500/70 focus:ring-2 focus:ring-red-500/10"
                  />
                  <button
                    type="button"
                    onClick={() => setShowPassword(!showPassword)}
                    aria-label={showPassword ? 'Hide password' : 'Show password'}
                    className="absolute right-4 top-1/2 -translate-y-1/2 text-gray-500 transition-colors hover:text-white"
                  >
                    {showPassword ? <EyeOff size={19} /> : <Eye size={19} />}
                  </button>
                </div>
                <p className="mt-2 text-xs text-gray-600">
                  Use at least 8 characters.
                </p>
              </div>

              {error && (
                <div className="rounded-lg border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-400">
                  {error}
                </div>
              )}

              <button
                type="submit"
                className="group flex w-full items-center justify-center gap-3 rounded-xl bg-gradient-to-r from-red-600 to-red-800 py-4 text-sm font-bold text-white shadow-[0_8px_30px_rgba(220,38,38,0.2)] transition-all duration-300 hover:-translate-y-0.5 hover:shadow-[0_10px_35px_rgba(220,38,38,0.35)] active:translate-y-0"
              >
                <ShieldCheck size={19} />
                {mode === 'signup' ? 'Create account' : 'Log in'}
                <ArrowRight size={18} className="transition-transform group-hover:translate-x-1" />
              </button>
            </form>

            <div className="my-7 flex items-center gap-4">
              <div className="h-px flex-1 bg-white/10" />
              <span className="text-xs text-gray-600">SECURE ACCESS</span>
              <div className="h-px flex-1 bg-white/10" />
            </div>

            <div className="flex items-center justify-center gap-2 text-xs text-gray-500">
              <ShieldCheck size={16} className="text-red-400" />
              Your security is our priority.
            </div>

            <p className="mt-7 text-center text-[11px] text-gray-600">
              AI Shield · Security monitoring platform · Demo authentication
            </p>
          </div>
        </section>
      </div>
    </main>
  )
}
