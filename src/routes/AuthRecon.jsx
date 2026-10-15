import React, { useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { useNavigate, useLocation } from 'react-router-dom'
import authreconApi from '../services/authreconApi'
import Card from '../components/Card'
import Badge from '../components/Badge'
import Button from '../components/Button'
import Header from '../components/Header'

const fetchRunsPreview = async () => {
  const response = await authreconApi.get('runs')
  return Array.isArray(response.data) ? response.data : []
}

function AuthRecon() {
  const navigate = useNavigate()
  const location = useLocation()
  const [successMessage, setSuccessMessage] = React.useState(null)
  const [pollingEnabled, setPollingEnabled] = React.useState(false)
  const [showAllRuns, setShowAllRuns] = React.useState(false)

  const { data, isLoading, error, refetch, isFetching } = useQuery({
    queryKey: ['authrecon', 'runs', 'preview'],
    queryFn: fetchRunsPreview,
    refetchOnWindowFocus: false,
    staleTime: 30_000,
    refetchInterval: pollingEnabled ? 5000 : false,
    refetchIntervalInBackground: false,
  })

  // Check for success message from navigation state
  useEffect(() => {
    if (location.state?.message) {
      setSuccessMessage(location.state.message)
      // Clear the message after 5 seconds
      const timer = setTimeout(() => setSuccessMessage(null), 5000)
      // Clear navigation state
      window.history.replaceState({}, document.title)
      return () => clearTimeout(timer)
    }
  }, [location])

  const runs = data || []
  const displayRuns = showAllRuns ? runs : runs.slice(0, 3)
  const hasMoreRuns = runs.length > 3

  useEffect(() => {
    if (!runs.length && pollingEnabled) {
      setPollingEnabled(false)
      return
    }
    const hasActiveRun = runs.some((run) => run.status === 'queued' || run.status === 'running')
    if (hasActiveRun !== pollingEnabled) {
      setPollingEnabled(hasActiveRun)
    }
  }, [runs, pollingEnabled])

  return (
    <>
      <Header title="AuthRecon" subtitle="Login runs, WAS scripts and troubleshooting" />
      <div className="flex-1 overflow-y-auto scrollbar-thin p-6">
        <div className="max-w-6xl mx-auto space-y-6">
        {/* Success Message Banner */}
        {successMessage && (
          <div className="p-4 rounded-lg border border-emerald-900/50 bg-emerald-950/20 animate-fade-in">
            <p className="text-sm text-emerald-400">
              ✓ {successMessage}
            </p>
          </div>
        )}

        <Card padding="md" className="min-h-[160px] dashboard-hero dashboard-hero--compact">
          <div className="dashboard-hero__stars" aria-hidden="true" />
          <div className="dashboard-hero__grid" aria-hidden="true" />
          <div className="dashboard-hero-content space-y-3">
            <div className="flex items-center justify-between flex-wrap gap-3">
              <div>
                <h1 className="text-2xl font-bold text-white">
                  AuthRecon
                </h1>
                <p className="text-sm text-(--text-secondary) mt-1">
                  Authentication reconnaissance and reporting suite
                </p>
              </div>
              <div className="text-right">
                <p className="text-xs text-(--text-muted)">API Endpoint</p>
                <p className="text-xs font-mono text-slate-100">
                  {authreconApi.defaults.baseURL}
                </p>
              </div>
            </div>
            <div className="flex items-center gap-3 flex-wrap">
              <Badge variant="info">
                {isFetching ? 'Refreshing' : 'Connected'}
              </Badge>
              {pollingEnabled && (
                <div className="flex items-center gap-2 text-xs text-(--text-muted)">
                  <span className="w-2 h-2 rounded-full bg-(--accent-blue) animate-pulse" />
                  Auto-refreshing
                </div>
              )}
              {error && (
                <Badge variant="error">
                  {error.message || 'Failed to load runs'}
                </Badge>
              )}
              <Button
                variant="primary"
                size="sm"
                onClick={() => navigate('/authrecon/launch')}
              >
                Launch Run
              </Button>
              <Button
                variant="ghost"
                size="sm"
                onClick={() => refetch()}
                loading={isFetching}
              >
                Refresh
              </Button>
            </div>
          </div>
        </Card>

        <Card padding="lg">
          <div className="flex items-center justify-between mb-4">
            <div>
              <h2 className="text-2xl font-semibold text-slate-50">
                {showAllRuns ? 'All Runs' : 'Recent Runs'}
                {!showAllRuns && runs.length > 0 && (
                  <span className="text-sm text-slate-400 ml-2">
                    ({runs.length} total)
                  </span>
                )}
              </h2>
              <p className="text-sm text-slate-400">
                {showAllRuns ? 'Complete run history from AuthRecon backend.' : 'Preview data pulled directly from AuthRecon backend.'}
              </p>
            </div>
          </div>

          {isLoading ? (
            <div className="py-12 flex items-center justify-center text-slate-400">
              Loading runs from AuthRecon…
            </div>
          ) : error ? (
            <div className="py-12 text-center">
              <p className="text-rose-400 font-medium">
                Unable to reach AuthRecon API
              </p>
              <p className="text-sm text-slate-500 mt-1">
                {error.message || 'Check docker stack and try again.'}
              </p>
            </div>
          ) : !displayRuns.length ? (
            <div className="py-12 text-center">
              <p className="text-slate-400 mb-4">
                No runs yet — launch your first run against a login page
              </p>
              <Button
                variant="primary"
                onClick={() => navigate('/authrecon/launch')}
              >
                Launch Run
              </Button>
            </div>
          ) : (
            <div className="space-y-4">
              {displayRuns.map((run) => {
                const submittedAt = run.submitted_at
                  ? new Date(run.submitted_at).toLocaleString()
                  : '—'
                return (
                <div
                  key={run.id}
                  onClick={() => navigate(`/authrecon/run/${run.id}`)}
                  className="p-4 rounded-2xl border border-slate-800/80 bg-slate-900/30 flex flex-wrap md:flex-nowrap gap-4 items-center hover:border-sky-500/50 hover:bg-slate-800/50 cursor-pointer transition-all"
                >
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-slate-500">
                      Target
                    </p>
                    <p className="text-base text-slate-50 truncate">
                      {run.target_url || 'Unknown target'}
                    </p>
                  </div>
                  <div className="flex flex-col">
                    <p className="text-sm text-slate-500">Auth Type</p>
                    <div className="flex items-center gap-2">
                      <p className="text-base text-slate-200">
                        {run.auth_type || 'unknown'}
                      </p>
                      {run.ai_assisted && (
                        <Badge variant="info" size="sm" title="An AI-suggested selector pattern was recorded for this run">
                          AI
                        </Badge>
                      )}
                    </div>
                  </div>
                  <div className="flex flex-col">
                    <p className="text-sm text-slate-500">Status</p>
                    <Badge variant={run.status === 'succeeded' ? 'success' : run.status === 'failed' ? 'error' : 'default'}>
                      {run.status}
                    </Badge>
                  </div>
                  <div className="flex flex-col">
                    <p className="text-sm text-slate-500">Submitted</p>
                    <p className="text-base text-slate-200 whitespace-nowrap">
                      {submittedAt}
                    </p>
                  </div>
                </div>
                )
              })}

              {/* Show All / Show Less Button */}
              {hasMoreRuns && (
                <div className="pt-4 border-t border-slate-800/80">
                  <Button
                    variant="outline"
                    size="sm"
                    onClick={() => setShowAllRuns(!showAllRuns)}
                    className="w-full"
                  >
                    {showAllRuns ? `Show Less (3 recent)` : `View All Runs (${runs.length} total)`}
                  </Button>
                </div>
              )}
            </div>
          )}
        </Card>
        </div>
      </div>
    </>
  )
}

export default AuthRecon
