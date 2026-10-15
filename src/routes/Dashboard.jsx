import React, { useEffect, useState } from 'react'
import { Link, useNavigate } from 'react-router-dom'
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  BarChart3,
  Bot,
  Clock3,
  Globe,
  Play,
  RefreshCcw,
  Sparkles,
  Target,
  TrendingUp,
} from 'lucide-react'
import Header from '../components/Header'
import Card from '../components/Card'
import Badge from '../components/Badge'
import Button from '../components/Button'
import useAuthReconRunsStats from '../hooks/useAuthReconRunsStats'
import authreconApi from '../services/authreconApi'

const numberFormatter = new Intl.NumberFormat()

const formatNumber = (value) => {
  if (typeof value !== 'number' || Number.isNaN(value)) return '0'
  return numberFormatter.format(value)
}

const formatRelativeTime = (isoString) => {
  if (!isoString) return 'no recent activity'
  const timestamp = Date.parse(isoString)
  if (Number.isNaN(timestamp)) return 'no recent activity'
  const diffMs = Date.now() - timestamp
  const minutes = Math.floor(diffMs / 60000)
  if (minutes < 1) return 'just now'
  if (minutes < 60) return `${minutes}m ago`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}h ago`
  const days = Math.floor(hours / 24)
  return `${days}d ago`
}

const buildSparklinePoints = (series, width = 100, height = 60) => {
  if (!series || !series.length) {
    return {
      line: '',
      area: '',
    }
  }
  const maxValue = Math.max(...series.map((point) => point.total), 1)
  const denominator = series.length > 1 ? series.length - 1 : 1
  const coordinates = series.map((point, index) => {
    const x = (index / denominator) * width
    const y = height - (point.total / maxValue) * (height - 10) - 5
    return { x, y }
  })
  const line = coordinates.map((point) => `${point.x},${point.y}`).join(' ')
  const area = `${coordinates.map((point) => `${point.x},${point.y}`).join(' ')} ${width},${height} 0,${height}`
  return { line, area }
}

function Dashboard() {
  const navigate = useNavigate()
  const [refreshInterval, setRefreshInterval] = useState(false)
  const {
    data: runs = [],
    metrics,
    isLoading,
    isFetching,
    error,
    refetch,
  } = useAuthReconRunsStats({ refetchInterval: refreshInterval })

  useEffect(() => {
    const nextInterval = metrics?.activeCount > 0 ? 5000 : false
    setRefreshInterval((prev) => (prev === nextInterval ? prev : nextInterval))
  }, [metrics?.activeCount])

  const latestRuns = runs.slice(0, 5)
  const connectionBadge = error
    ? { variant: 'error', label: 'Portal offline' }
    : metrics?.activeCount > 0
      ? { variant: 'warning', label: 'Runs in progress' }
      : { variant: 'success', label: 'Connected' }

  const heroStats = [
    {
      id: 'runs24',
      label: 'Runs (24h)',
      value: formatNumber(metrics?.last24hCount ?? 0),
      detail: `${formatNumber(metrics?.last7dCount ?? 0)} in last 7d`,
    },
    {
      id: 'success',
      label: 'Success rate',
      value: metrics?.successRate24h !== null && metrics?.successRate24h !== undefined
        ? `${metrics.successRate24h}%`
        : '—',
      detail: `${formatNumber(metrics?.failureCount24h ?? 0)} failures in 24h`,
    },
    {
      id: 'queue',
      label: 'Active queue',
      value: formatNumber(metrics?.activeCount ?? 0),
      detail: `${formatNumber(metrics?.runningCount ?? 0)} running · ${formatNumber(metrics?.queuedCount ?? 0)} queued`,
    },
    {
      id: 'total',
      label: 'Total runs',
      value: formatNumber(metrics?.totalRuns ?? 0),
      detail: metrics?.successRateAll
        ? `${metrics.successRateAll}% lifetime success`
        : metrics?.hasData
          ? 'No aggregate rate yet'
          : 'Launch your first run',
    },
  ]

  const authReconLatestDesc = metrics?.latestRun
    ? `${metrics.latestRun.target_url || 'Unknown target'} • ${formatRelativeTime(metrics.latestRun.submitted_at)}`
    : 'No AuthRecon runs submitted'

  const quickActions = [
    {
      id: 'authrecon',
      label: 'Launch AuthRecon Run',
      description: authReconLatestDesc,
      icon: Play,
      href: '/authrecon/launch',
      badge: metrics?.activeCount ? `${metrics.activeCount} active` : 'Idle',
      badgeVariant: metrics?.activeCount ? 'warning' : 'success',
    },
    {
      id: 'atlas',
      label: 'Open Atlas',
      description: 'Asset intelligence + exposure mapping',
      icon: Globe,
      href: '/atlas',
      badge: 'Preview',
      badgeVariant: 'sky',
    },
  ]

  const { line: trendLine, area: trendArea } = buildSparklinePoints(metrics?.series || [])

  return (
    <>
      <Header
        title="AuthRecon Suite"
        subtitle="Login detection and verified Selenium scripts for Tenable WAS"
      />

      <div className="flex-1 overflow-y-auto scrollbar-thin p-6">
        <div className="max-w-7xl mx-auto space-y-8">
          <Card padding="lg" className="dashboard-hero">
            <div className="dashboard-hero__stars" aria-hidden="true" />
            <div className="dashboard-hero__grid" aria-hidden="true" />
            <div className="dashboard-hero-content space-y-6">
              <div className="flex flex-wrap items-start justify-between gap-6">
                <div className="space-y-3 max-w-3xl">
                  <div className="flex items-center gap-2 text-[var(--text-secondary)] uppercase text-xs tracking-[0.2em]">
                    <Sparkles className="w-4 h-4 text-[var(--accent-blue)]" />
                    Live AuthRecon Telemetry
                  </div>
                  <h1 className="text-3xl font-semibold text-white">
                    AuthRecon Control Center
                  </h1>
                  <p className="text-sm text-[var(--text-muted)] max-w-2xl">
                    Every metric below is sourced directly from the AuthRecon backend. Queue depth, success rate,
                    and recent targets update automatically whenever jobs are running.
                  </p>
                  <div className="flex flex-wrap items-center gap-3 text-xs text-[var(--text-secondary)]">
                    <Badge variant={connectionBadge.variant} dot>
                      {connectionBadge.label}
                    </Badge>
                    {metrics?.latestRun ? (
                      <span className="leading-tight">
                        Latest target{' '}
                        <span className="text-white">{metrics.latestRun.target_url || 'Unknown target'}</span>{' '}
                        • {formatRelativeTime(metrics.latestRun.submitted_at)}
                      </span>
                    ) : (
                      <span>No submissions yet — launch your first reconnaissance run.</span>
                    )}
                  </div>
                </div>
                <div className="flex flex-col gap-3 items-start md:items-end">
                  <div className="flex flex-wrap gap-3">
                    <Button
                      variant="primary"
                      size="md"
                      icon={Play}
                      onClick={() => navigate('/authrecon/launch')}
                    >
                      Launch Run
                    </Button>
                    <Button
                      variant="ghost"
                      size="md"
                      icon={RefreshCcw}
                      onClick={() => refetch()}
                      loading={isFetching}
                    >
                      Sync data
                    </Button>
                  </div>
                  <p className="text-xs text-[var(--text-secondary)]">
                    Auto-refresh {metrics?.activeCount ? 'enabled while runs are active' : 'idle until new jobs queue'}
                  </p>
                </div>
              </div>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                {heroStats.map((stat) => (
                  <div key={stat.id} className="rounded-2xl border border-white/5 bg-white/5 backdrop-blur-sm p-4">
                    <p className="text-xs uppercase tracking-wide text-[var(--text-muted)]">{stat.label}</p>
                    <p className="text-2xl font-semibold text-white mt-1">{stat.value}</p>
                    <p className="text-xs text-[var(--text-secondary)] mt-1">{stat.detail}</p>
                  </div>
                ))}
              </div>
            </div>
          </Card>

          <Card padding="lg">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-lg font-semibold text-slate-100">Quick Actions</h3>
                <p className="text-sm text-slate-400">Jump into common workflows with live context.</p>
              </div>
              <Button variant="ghost" size="sm" icon={RefreshCcw} onClick={() => refetch()} loading={isFetching}>
                Refresh data
              </Button>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {quickActions.map((action) => {
                const Icon = action.icon
                return (
                  <Link
                    key={action.id}
                    to={action.href}
                    className="quick-action-card"
                  >
                    <div className="flex items-center justify-between mb-4">
                      <div className="p-2 rounded-xl bg-white/5 text-white">
                        <Icon className="w-4 h-4" />
                      </div>
                      {action.badge && (
                        <Badge variant={action.badgeVariant} size="sm">
                          {action.badge}
                        </Badge>
                      )}
                    </div>
                    <div className="space-y-1">
                      <p className="text-sm font-semibold text-white">{action.label}</p>
                      <p className="text-xs text-[var(--text-secondary)] leading-snug">
                        {action.description}
                      </p>
                    </div>
                  </Link>
                )
              })}
            </div>
          </Card>

          <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
            <Card padding="lg" className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs uppercase text-[var(--text-muted)]">Worker Health</p>
                  <h3 className="text-xl font-semibold text-white">AuthRecon status</h3>
                </div>
                <Badge variant={connectionBadge.variant}>{connectionBadge.label}</Badge>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="rounded-xl border border-white/5 p-3">
                  <p className="text-xs text-[var(--text-muted)] uppercase">Jobs running</p>
                  <p className="text-xl font-semibold text-white">{formatNumber(metrics?.runningCount ?? 0)}</p>
                  <p className="text-xs text-[var(--text-secondary)]">active browser sessions</p>
                </div>
                <div className="rounded-xl border border-white/5 p-3">
                  <p className="text-xs text-[var(--text-muted)] uppercase">Queue depth</p>
                  <p className="text-xl font-semibold text-white">{formatNumber(metrics?.queuedCount ?? 0)}</p>
                  <p className="text-xs text-[var(--text-secondary)]">awaiting workers</p>
                </div>
                <div className="rounded-xl border border-white/5 p-3">
                  <p className="text-xs text-[var(--text-muted)] uppercase">Failures (24h)</p>
                  <p className="text-xl font-semibold text-white">{formatNumber(metrics?.failureCount24h ?? 0)}</p>
                  <p className="text-xs text-[var(--text-secondary)]">review in run history</p>
                </div>
                <div className="rounded-xl border border-white/5 p-3">
                  <p className="text-xs text-[var(--text-muted)] uppercase">API endpoint</p>
                  <p className="text-xs font-mono text-[var(--accent-blue-soft)] break-all">
                    {authreconApi.defaults.baseURL}
                  </p>
                </div>
              </div>
              <div className="flex items-center gap-3 text-sm text-[var(--text-secondary)]">
                {error ? (
                  <>
                    <AlertTriangle className="w-4 h-4 text-rose-400" />
                    Unable to reach AuthRecon API. Check docker-compose status.
                  </>
                ) : metrics?.activeCount ? (
                  <>
                    <Activity className="w-4 h-4 text-[var(--accent-blue)]" />
                    Worker processing {formatNumber(metrics.activeCount)} active job{metrics.activeCount === 1 ? '' : 's'} right now.
                  </>
                ) : (
                  <>
                    <Clock3 className="w-4 h-4 text-[var(--accent-blue-soft)]" />
                    Queue idle — ready for the next submission.
                  </>
                )}
              </div>
            </Card>

            <Card padding="lg" className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs uppercase text-[var(--text-muted)]">Run activity</p>
                  <h3 className="text-xl font-semibold text-white">7-day trend</h3>
                </div>
                <Badge variant="info">{metrics?.last7dCount ? `${formatNumber(metrics.last7dCount)} runs` : 'Awaiting data'}</Badge>
              </div>
              {trendLine ? (
                <div className="relative">
                  <svg viewBox="0 0 100 60" preserveAspectRatio="none" className="w-full h-32">
                    <defs>
                      <linearGradient id="trendFill" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="rgba(41,199,255,0.35)" />
                        <stop offset="100%" stopColor="rgba(13,27,45,0)" />
                      </linearGradient>
                    </defs>
                    <polyline
                      fill="url(#trendFill)"
                      stroke="none"
                      points={trendArea}
                    />
                    <polyline
                      fill="none"
                      stroke="var(--accent-blue)"
                      strokeWidth="1.5"
                      strokeLinecap="round"
                      points={trendLine}
                    />
                  </svg>
                  <div className="absolute inset-0 pointer-events-none rounded-2xl ring-1 ring-white/5" />
                </div>
              ) : (
                <div className="h-32 flex items-center justify-center text-sm text-[var(--text-secondary)] border border-dashed border-white/10 rounded-2xl">
                  No historical data to plot yet.
                </div>
              )}
              <div className="flex flex-wrap gap-4 text-xs text-[var(--text-secondary)]">
                {(metrics?.series || []).map((point) => (
                  <div key={point.key} className="space-y-1">
                    <p className="font-semibold text-white/80">{point.label}</p>
                    <p>{formatNumber(point.total)} runs</p>
                    <p className="text-[var(--accent-blue-soft)]">
                      {formatNumber(point.succeeded)} ok / {formatNumber(point.failed)} fail
                    </p>
                  </div>
                ))}
              </div>
            </Card>

            <Card padding="lg" className="space-y-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs uppercase text-[var(--text-muted)]">Recent activity</p>
                  <h3 className="text-xl font-semibold text-white">Latest AuthRecon runs</h3>
                </div>
                <Button
                  variant="ghost"
                  size="sm"
                  icon={ArrowRight}
                  iconPosition="right"
                  onClick={() => navigate('/authrecon')}
                  className="whitespace-nowrap flex-shrink-0"
                >
                  View runs
                </Button>
              </div>
              {isLoading ? (
                <div className="py-10 flex items-center justify-center text-[var(--text-secondary)]">
                  Loading runs…
                </div>
              ) : error ? (
                <div className="py-10 text-center text-sm">
                  <p className="text-rose-400 font-medium">Unable to load AuthRecon runs.</p>
                  <p className="text-[var(--text-muted)] mt-1">{error.message || 'Unexpected error from API.'}</p>
                </div>
              ) : !latestRuns.length ? (
                <div className="py-10 text-center text-[var(--text-secondary)]">
                  No runs yet — launch your first run to populate this feed.
                </div>
              ) : (
                <div className="space-y-3">
                  {latestRuns.map((run) => (
                    <Link
                      key={run.id}
                      to={`/authrecon/run/${run.id}`}
                      className="flex flex-col gap-1 rounded-2xl border border-white/5 p-4 hover:border-[var(--accent-blue)]/40 hover:bg-white/5 transition"
                    >
                      <div className="flex items-center justify-between gap-3">
                        <div className="flex items-center gap-2 min-w-0 flex-1">
                          <Target className="w-4 h-4 flex-shrink-0 text-[var(--accent-blue)]" />
                          <p className="text-sm text-white truncate" title={run.target_url}>{run.target_url || 'Unknown target'}</p>
                        </div>
                        <Badge
                          className="flex-shrink-0"
                          variant={
                            run.status === 'succeeded'
                              ? 'success'
                              : run.status === 'failed'
                                ? 'error'
                                : 'info'
                          }
                          size="sm"
                        >
                          {run.status}
                        </Badge>
                      </div>
                      <div className="flex flex-wrap items-center gap-3 text-xs text-[var(--text-secondary)]">
                        <span>{run.auth_type || 'unknown'} auth</span>
                        <span>•</span>
                        <span>{formatRelativeTime(run.submitted_at)}</span>
                        <span>•</span>
                        <span>{run.operator || 'AuthRecon'}</span>
                      </div>
                    </Link>
                  ))}
                </div>
              )}
            </Card>
          </div>
        </div>
      </div>
    </>
  )
}

export default Dashboard
