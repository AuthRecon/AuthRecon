import React, { useEffect, useMemo, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import authreconApi from '../../services/authreconApi'
import Card from '../../components/Card'
import Header from '../../components/Header'
import Badge from '../../components/Badge'
import Button from '../../components/Button'
import Modal from '../../components/Modal'
import StageConsole from '../../components/StageConsole'
import ReplayModal from '../../components/ReplayModal'
import GlassTerminal from '../../components/GlassTerminal'
import VNCViewer from '../../components/VNCViewer'
import SummaryDashboard from './components/SummaryDashboard'
import AuthFlowSummary from './components/AuthFlowSummary'
import DetectionEvidence from './components/DetectionEvidence'
import AIAssistance from './components/AIAssistance'
import RoleSection from './components/RoleSection'
import ScreenshotGrid from './components/ScreenshotGrid'
import Timeline from './components/Timeline'
import ArtifactsSection from './components/ArtifactsSection'
import TechFingerprint from './components/TechFingerprint'
import WasSetupCard from './components/WasSetupCard'
import ApprovalBanner from './components/ApprovalBanner'
import FailureCard from './components/FailureCard'
import SecurityAnalysis from './components/SecurityAnalysis'
import HttpFlowViewer from './components/HttpFlowViewer'
import { PlayCircle, Terminal as TerminalIcon, RotateCw, Shield, Layout, Clock, Trash2, Network } from 'lucide-react'
import { buildStageData, buildTerminalLogs } from '../../utils/authreconTelemetry'

const fetchRunDetail = async (runId) => {
  const response = await authreconApi.get(`runs/${runId}`)
  return response.data
}

const fetchArtifacts = async (runId) => {
  const response = await authreconApi.get(`runs/${runId}/artifacts`)
  return response.data
}

// Truncate long URLs intelligently (keep protocol, domain, and end visible)
const truncateUrl = (url, maxLength = 80) => {
  if (!url || url.length <= maxLength) return url

  try {
    const urlObj = new URL(url)
    const protocol = urlObj.protocol + '//'
    const domain = urlObj.hostname
    const pathAndQuery = urlObj.pathname + urlObj.search + urlObj.hash

    const fixedPart = protocol + domain
    const remaining = maxLength - fixedPart.length - 3 // 3 for '...'

    if (remaining <= 10) {
      // URL is so long even domain doesn't fit, just truncate middle
      const start = url.substring(0, Math.floor(maxLength / 2) - 2)
      const end = url.substring(url.length - Math.floor(maxLength / 2) + 1)
      return start + '...' + end
    }

    // Keep beginning and end of path visible
    if (pathAndQuery.length > remaining) {
      const endLength = Math.floor(remaining / 2)
      const startLength = remaining - endLength
      const pathStart = pathAndQuery.substring(0, startLength)
      const pathEnd = pathAndQuery.substring(pathAndQuery.length - endLength)
      return fixedPart + pathStart + '...' + pathEnd
    }

    return url
  } catch (e) {
    // Not a valid URL, just truncate middle
    const start = url.substring(0, Math.floor(maxLength / 2) - 2)
    const end = url.substring(url.length - Math.floor(maxLength / 2) + 1)
    return start + '...' + end
  }
}

function AuthReconRunDetail() {
  const { runId } = useParams()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [expandedStageId, setExpandedStageId] = useState(null)
  const [isReplayOpen, setIsReplayOpen] = useState(false)
  const [terminalVisible, setTerminalVisible] = useState(false)
  const [terminalExpanded, setTerminalExpanded] = useState(false)
  const [terminalLogs, setTerminalLogs] = useState([])
  const [consoleCollapsed, setConsoleCollapsed] = useState(true)
  const [activeTab, setActiveTab] = useState('overview')
  const [showDeleteModal, setShowDeleteModal] = useState(false)
  const [isDeleting, setIsDeleting] = useState(false)
  const [manualSessionStarted, setManualSessionStarted] = useState(false)

  const { data: run, isLoading, error, refetch } = useQuery({
    queryKey: ['authrecon', 'run', runId],
    queryFn: () => fetchRunDetail(runId),
    refetchOnWindowFocus: false,
  })

  // Manual polling interval for active runs
  useEffect(() => {
    if (!run) return

    const isActive = run.status === 'queued' || run.status === 'running' || run.status === 'manual_recording'
    if (!isActive) return

    const interval = setInterval(() => {
      refetch()
    }, 2000)

    return () => {
      clearInterval(interval)
    }
  }, [run?.status, refetch])

  const { data: allArtifacts = [], refetch: refetchArtifacts } = useQuery({
    queryKey: ['authrecon', 'run', runId, 'artifacts'],
    queryFn: () => fetchArtifacts(runId),
    enabled: !!run,
    refetchOnWindowFocus: false,
  })

  // Poll both run data AND artifacts when run just succeeded
  // (security_context is in run data, artifacts are separate)
  useEffect(() => {
    if (!run || run.status !== 'succeeded') return

    const interval = setInterval(() => {
      refetch()  // Refetch run data (includes security_context, tech_fingerprint, flow_summary)
      refetchArtifacts()  // Refetch artifacts (screenshot, HAR)
    }, 2000)

    // Stop polling after 30 seconds (everything should be ready by then)
    const timeout = setTimeout(() => {
      clearInterval(interval)
    }, 30000)

    return () => {
      clearInterval(interval)
      clearTimeout(timeout)
    }
  }, [run?.status, refetch, refetchArtifacts])

  // Extract screenshots for the dedicated viewer (but keep them in artifacts too)
  const screenshots = allArtifacts.filter(a => a.type === 'screenshot')
  const artifacts = allArtifacts // Keep ALL artifacts including screenshots

  // Auto-start manual recording session
  useEffect(() => {
    if (run && run.status === 'manual_recording' && !manualSessionStarted) {
      setManualSessionStarted(true)
      authreconApi.post(`runs/${runId}/start-manual-session`)
        .catch((error) => {
          console.error('Failed to start manual session:', error)
        })
    }
  }, [run, runId, manualSessionStarted])

  useEffect(() => {
    if (run) {
      setTerminalLogs(buildTerminalLogs(run))
    }
  }, [run])

  const stageData = useMemo(
    () => buildStageData(run, { screenshots }),
    [run, screenshots],
  )

  const stageActiveIndex = useMemo(() => {
    if (!stageData.length) return -1

    // If run is complete, show all stages as complete
    if (run?.status === 'succeeded' || run?.status === 'failed') {
      return stageData.length - 1
    }

    // If run is running, find the first stage without data
    if (run?.status === 'running') {
      const pendingIndex = stageData.findIndex((stage) => !stage.meta && stage.logs.length === 0)
      if (pendingIndex === -1) return stageData.length - 1
      return Math.max(0, pendingIndex - 1)
    }

    // If queued, show first stage
    if (run?.status === 'queued') {
      return 0
    }

    // Fallback to finding first empty stage
    const pendingIndex = stageData.findIndex((stage) => !stage.meta && stage.logs.length === 0)
    if (pendingIndex === -1) return stageData.length - 1
    return Math.max(0, pendingIndex - 1)
  }, [stageData, run?.status])

  const consoleStatus = useMemo(() => {
    if (!run?.status) return ''
    if (run.status === 'running') return 'Live'
    if (run.status === 'queued') return 'Queued'
    return 'Complete'
  }, [run])

  if (isLoading) {
    return (
      <div className="flex-1 overflow-y-auto scrollbar-thin p-6">
        <div className="max-w-7xl mx-auto">
          <div className="flex items-center justify-center py-12">
            <div className="text-center">
            <div className="inline-flex items-center justify-center w-16 h-16 bg-(--sidebar-active-bg) rounded-2xl mb-4">
              <div className="w-8 h-8 border-4 border-[rgba(41,199,255,0.3)] border-t-(--accent-blue) rounded-full animate-spin" />
            </div>
              <p className="text-slate-400">Loading run details...</p>
            </div>
          </div>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex-1 overflow-y-auto scrollbar-thin p-6">
        <div className="max-w-7xl mx-auto">
          <Card padding="lg">
            <div className="text-center py-12">
              <p className="text-rose-400 font-medium mb-2">Failed to load run details</p>
              <p className="text-sm text-slate-500 mb-4">
                {error.message || 'An error occurred'}
              </p>
              <Button variant="outline" onClick={() => navigate('/authrecon')}>
                Back to Runs
              </Button>
            </div>
          </Card>
        </div>
      </div>
    )
  }

  const isManualRecording = run.status === 'manual_recording'
  const isStreamingRun = Boolean(run.streaming_enabled) && (run.status === 'queued' || run.status === 'running')

  const hasWarnings = run.status === 'succeeded' && run.warnings?.length > 0
  const statusVariant = run.status === 'succeeded' ? 'success' :
                        run.status === 'failed' ? 'error' :
                        run.status === 'running' ? 'info' : 'default'

  const handleReplayOpen = () => {
    if (!run) return
    setIsReplayOpen(true)
  }

  const handleRerun = async () => {
    if (!run) return
    try {
      const response = await authreconApi.post(`runs/${runId}/rerun`)
      const newRunId = response.data.id
      // Invalidate queries to prevent stale cache
      queryClient.invalidateQueries({ queryKey: ['authrecon', 'run', newRunId] })
      queryClient.invalidateQueries({ queryKey: ['authrecon', 'runs'] })
      // Navigate to the new run (note: singular 'run' not 'runs')
      navigate(`/authrecon/run/${newRunId}`)
    } catch (error) {
      console.error('Failed to re-run test:', error)
      // Could add toast notification here
    }
  }

  const handleDelete = async () => {
    if (!run) return
    setIsDeleting(true)
    try {
      await authreconApi.delete(`runs/${runId}`)
      // Invalidate runs list cache
      queryClient.invalidateQueries({ queryKey: ['authrecon', 'runs'] })
      // Navigate back to runs list
      navigate('/authrecon')
    } catch (error) {
      console.error('Failed to delete run:', error)
      // Could add toast notification here
    } finally {
      setIsDeleting(false)
      setShowDeleteModal(false)
    }
  }

  const toggleTerminal = () => {
    setTerminalVisible((prev) => {
      if (prev) return false
      setTerminalExpanded(false)
      return true
    })
  }

  return (
    <>
    <Header title="Run details" subtitle={`${run.id} · ${run.auth_type || 'detecting'} · ${run.status}`} />
    <div className="flex-1 overflow-y-auto scrollbar-thin p-6">
      <div className="max-w-7xl mx-auto space-y-6">
        {/* Header */}
        <Card padding="lg">
          <div className="flex flex-wrap items-center justify-between gap-4 mb-4">
            <div className="space-y-1 max-w-3xl">
              <h1 className="text-2xl font-semibold text-slate-50 wrap-break-word" title={run.target_url}>
                {truncateUrl(run.target_url) || 'Target'}
                <span className="text-slate-500"> — </span>
                <span className="font-mono text-sm text-slate-300">{run.id}</span>
              </h1>
              <p className="text-xs text-slate-400 uppercase tracking-widest">
                Authentication reconnaissance run details
              </p>
            </div>
            <div className="flex flex-wrap gap-3 justify-end">
              <Button variant="outline" size="sm" onClick={toggleTerminal}>
                <TerminalIcon className="w-4 h-4" />
                Glass Terminal
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={handleRerun}
                disabled={run.status === 'running' || run.status === 'queued'}
              >
                <RotateCw className="w-4 h-4" />
                Re-run Test
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={handleReplayOpen}
                disabled={!run.timeline?.length}
              >
                <PlayCircle className="w-4 h-4" />
                Replay Sequence
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={() => setShowDeleteModal(true)}
                className="text-rose-400 hover:text-rose-300 hover:border-rose-500/50"
              >
                <Trash2 className="w-4 h-4" />
                Delete Run
              </Button>
              <Button variant="ghost" size="sm" onClick={() => navigate('/authrecon')}>
                Back to Runs
              </Button>
            </div>
          </div>
          <div className="flex flex-wrap items-center gap-3 text-sm">
            <Badge variant={hasWarnings ? 'warning' : statusVariant}>
              {hasWarnings ? 'succeeded with warnings' : run.status}
            </Badge>
            <Badge variant="default">
              {run.auth_type || 'unknown'}
            </Badge>
            {Array.isArray(run.roles) && run.roles.length > 1 && (
              <Badge variant="info">
                Multi-role
              </Badge>
            )}
            {run.status === 'running' && (
              <div className="flex items-center gap-2 text-sm text-(--accent-blue)">
                <div className="w-2 h-2 bg-(--accent-blue) rounded-full animate-pulse" />
                <span>Auto-refreshing...</span>
              </div>
            )}
          </div>
          {hasWarnings && (
            <div className="mt-4 p-3 rounded-lg border border-amber-900/50 bg-amber-950/20 text-sm text-amber-200 space-y-1">
              {run.warnings.map(w => <p key={w}>{w}</p>)}
            </div>
          )}
        </Card>

        {/* Live browser view: manual recording sessions, or automated runs with
            streaming enabled while they are queued/running. Hidden once the run
            completes (the worker also clears vnc_port then). */}
        {(isManualRecording || isStreamingRun) && (
          <Card padding="lg">
            {/* No vnc_port yet: the worker is still starting the display. Wait
                instead of requesting a ticket, which would 404 until then. */}
            {!run.vnc_port ? (
              <div className="flex flex-col items-center justify-center py-12">
                <div className="animate-spin rounded-full h-12 w-12 border-b-2 border-sky-500 mb-4"></div>
                <h3 className="text-lg font-semibold text-slate-200 mb-2">
                  {isManualRecording ? 'Preparing VNC Session' : 'Live stream starting…'}
                </h3>
                <p className="text-sm text-slate-400 mb-1">
                  {run.status === 'queued'
                    ? 'Waiting for a worker to pick up this run...'
                    : 'Starting virtual display and browser...'}
                </p>
                <p className="text-xs text-slate-500">This updates automatically every 2s</p>
              </div>
            ) : (
              <>
                <VNCViewer
                  key={`${runId}-${run.vnc_port}`}
                  runId={runId}
                  autoConnect={true}
                  hint={isManualRecording
                    ? undefined
                    : 'The live view opens in a popup and closes when the run finishes. Each "Reopen" issues a fresh access ticket.'}
                />
                {/* End Recording button for manual sessions */}
                {run.status === 'manual_recording' && (
                  <div className="mt-4 flex justify-end">
                    <Button
                      onClick={async () => {
                        try {
                          await authreconApi.post(`runs/${runId}/end-manual-session`)
                          queryClient.invalidateQueries(['authrecon', 'run', runId])
                        } catch (error) {
                          console.error('Failed to end manual session:', error)
                          alert('Failed to end recording session')
                        }
                      }}
                      variant="primary"
                    >
                      End Recording
                    </Button>
                  </div>
                )}
              </>
            )}
          </Card>
        )}

        <div className="telemetry-container space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <p className="text-xs uppercase tracking-widest text-(--text-muted)">Stage Console</p>
              <p className="text-sm text-slate-400">Live telemetry from this run&apos;s timeline</p>
            </div>
            <Button
              type="button"
              variant={consoleCollapsed ? 'outline-solid' : 'ghost'}
              size="sm"
              onClick={() => setConsoleCollapsed((prev) => !prev)}
            >
              {consoleCollapsed ? 'View telemetry' : 'Hide telemetry'}
            </Button>
          </div>
          {!consoleCollapsed && (
            <StageConsole
              stages={stageData}
              activeIndex={stageActiveIndex}
              expandedStage={expandedStageId}
              onToggleStage={setExpandedStageId}
              replayLabel={consoleStatus}
              showHeader={false}
            />
          )}
        </div>

        {/* Error Message (if failed) */}
        {run.status === 'failed' && (run.failure || run.error_message) && (
          <FailureCard failure={run.failure} errorMessage={run.error_message} />
        )}

        {/* Tab Navigation */}
        <div className="border-b border-slate-700/50">
          <div className="flex gap-1">
            <button
              onClick={() => setActiveTab('overview')}
              className={`px-6 py-3 text-sm font-medium border-b-2 transition-colors ${
                activeTab === 'overview'
                  ? 'border-(--accent-blue) text-(--accent-blue)'
                  : 'border-transparent text-slate-400 hover:text-slate-300 hover:border-slate-600'
              }`}
              style={activeTab === 'overview' ? {
                borderBottomColor: 'var(--accent-blue)',
                color: 'var(--accent-blue)'
              } : {}}
            >
              <div className="flex items-center gap-2">
                <Layout className="w-4 h-4" />
                Overview
              </div>
            </button>
            <button
              onClick={() => setActiveTab('security')}
              className={`px-6 py-3 text-sm font-medium border-b-2 transition-colors ${
                activeTab === 'security'
                  ? 'border-(--accent-blue) text-(--accent-blue)'
                  : 'border-transparent text-slate-400 hover:text-slate-300 hover:border-slate-600'
              }`}
              style={activeTab === 'security' ? {
                borderBottomColor: 'var(--accent-blue)',
                color: 'var(--accent-blue)'
              } : {}}
            >
              <div className="flex items-center gap-2">
                <Shield className="w-4 h-4" />
                Security Analysis
              </div>
            </button>
            <button
              onClick={() => setActiveTab('timeline')}
              className={`px-6 py-3 text-sm font-medium border-b-2 transition-colors ${
                activeTab === 'timeline'
                  ? 'border-(--accent-blue) text-(--accent-blue)'
                  : 'border-transparent text-slate-400 hover:text-slate-300 hover:border-slate-600'
              }`}
              style={activeTab === 'timeline' ? {
                borderBottomColor: 'var(--accent-blue)',
                color: 'var(--accent-blue)'
              } : {}}
            >
              <div className="flex items-center gap-2">
                <Clock className="w-4 h-4" />
                Timeline
              </div>
            </button>
            <button
              onClick={() => setActiveTab('httpflow')}
              className={`px-6 py-3 text-sm font-medium border-b-2 transition-colors ${
                activeTab === 'httpflow'
                  ? 'border-(--accent-blue) text-(--accent-blue)'
                  : 'border-transparent text-slate-400 hover:text-slate-300 hover:border-slate-600'
              }`}
              style={activeTab === 'httpflow' ? {
                borderBottomColor: 'var(--accent-blue)',
                color: 'var(--accent-blue)'
              } : {}}
            >
              <div className="flex items-center gap-2">
                <Network className="w-4 h-4" />
                HTTP Flow
              </div>
            </button>
          </div>
        </div>

        {/* Tab Content */}
        {activeTab === 'overview' && (
          <div className="space-y-6">
            <ApprovalBanner run={run} onChanged={refetch} />
            {/* What to put in the scanner */}
            {run.was_setup && (
              <WasSetupCard runId={run.id} setup={run.was_setup} onChanged={refetch} />
            )}

            {/* Summary Dashboard */}
            <SummaryDashboard run={run} artifactCount={artifacts.length} screenshotCount={screenshots.length} />

            {/* Authentication Flow Summary */}
            {/* Describes a successful login; misleading on failed runs */}
            {run.flow_summary && run.status === 'succeeded' && (
              <AuthFlowSummary flowSummary={run.flow_summary} />
            )}

            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Left Column (2/3 width) */}
              <div className="lg:col-span-2 space-y-6">
                {/* Detection Evidence */}
                <DetectionEvidence run={run} />

                {/* AI Assistance — only renders when ai_suggestions is non-empty */}
                <AIAssistance run={run} />

                {/* Role Section (Multi-Role Support) */}
                {run.roles && run.roles.length > 0 && (
                  <RoleSection runId={run.id} roles={run.roles} />
                )}

                {/* Screenshots */}
                {screenshots && screenshots.length > 0 && (
                  <ScreenshotGrid screenshots={screenshots} />
                )}

                {/* Artifacts */}
                {artifacts && artifacts.length > 0 && (
                  <ArtifactsSection
                    runId={run.id}
                    artifacts={artifacts}
                    runStatus={run.status}
                  />
                )}

                {/* Tech Fingerprint */}
                {(run.tech_fingerprint || run.js_frameworks) && (
                  <TechFingerprint techFingerprint={run.tech_fingerprint} jsFrameworks={run.js_frameworks} />
                )}
              </div>

              {/* Right Column (1/3 width) */}
              <div className="space-y-6">
                {/* Timeline */}
                <Timeline timeline={run.timeline} compact />
              </div>
            </div>
          </div>
        )}

        {/* Security Analysis Tab */}
        {activeTab === 'security' && (
          <SecurityAnalysis securityContext={run.security_context} />
        )}

        {/* Timeline Tab */}
        {activeTab === 'timeline' && (
          <Timeline timeline={run.timeline} />
        )}

        {/* HTTP Flow Tab */}
        {activeTab === 'httpflow' && (
          <HttpFlowViewer runId={runId} />
        )}
      </div>
      {run && (
        <ReplayModal
          open={isReplayOpen}
          onClose={() => setIsReplayOpen(false)}
          stages={stageData}
          timeline={run.timeline || []}
          rawData={run}
        />
      )}
      {terminalVisible && (
        <GlassTerminal
          logs={terminalLogs}
          expanded={terminalExpanded}
          onToggleExpand={() => setTerminalExpanded((prev) => !prev)}
          onClose={() => setTerminalVisible(false)}
        />
      )}
      <Modal
        isOpen={showDeleteModal}
        onClose={() => setShowDeleteModal(false)}
        title="Delete Run"
        description="Are you sure you want to delete this run? This action cannot be undone."
        size="sm"
        footer={
          <div className="flex justify-end gap-3">
            <Button
              variant="ghost"
              onClick={() => setShowDeleteModal(false)}
              disabled={isDeleting}
            >
              Cancel
            </Button>
            <Button
              variant="primary"
              onClick={handleDelete}
              disabled={isDeleting}
              className="bg-rose-600 hover:bg-rose-700 text-white"
            >
              {isDeleting ? 'Deleting...' : 'Delete Run'}
            </Button>
          </div>
        }
      >
        <div className="text-sm text-slate-300 space-y-2">
          <p>This will permanently delete:</p>
          <ul className="list-disc list-inside space-y-1 text-slate-400">
            <li>Run details and timeline</li>
            <li>Screenshots and artifacts</li>
            <li>HAR files and network data</li>
            <li>Security analysis results</li>
          </ul>
        </div>
      </Modal>
    </div>
    </>
  )
}

export default AuthReconRunDetail
