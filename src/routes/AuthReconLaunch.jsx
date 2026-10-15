import React, { useEffect, useMemo, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useMutation, useQuery } from '@tanstack/react-query'
import { nanoid } from 'nanoid'
import authreconApi from '../services/authreconApi'
import Card from '../components/Card'
import Input from '../components/Input'
import Button from '../components/Button'
import Badge from '../components/Badge'
import Header from '../components/Header'
import { Sparkles, PlayCircle, Terminal as TerminalIcon, ArrowRight, HelpCircle, ChevronDown } from 'lucide-react'
import StageConsole from '../components/StageConsole'
import ReplayModal from '../components/ReplayModal'
import GlassTerminal from '../components/GlassTerminal'
import AuthReconHelpModal from '../components/AuthReconHelpModal'
import { buildStageData, buildTerminalLogs, stageBlueprints } from '../utils/authreconTelemetry'

const AUTH_TYPE_OPTIONS = [
  { value: '', label: 'Auto-detect' },
  { value: 'basic_auth', label: 'Basic authentication (401 challenge)' },
  { value: 'form_auth', label: 'HTML form (single step)' },
  { value: 'two_step_form', label: 'Two-step form (MFA / wizard)' },
  { value: 'ldap', label: 'LDAP / ADFS / domain login' },
  { value: 'azure_ad', label: 'Azure AD / Entra ID (including branded portals)' },
  { value: 'saml', label: 'SAML 2.0 Enterprise SSO (Shibboleth, SimpleSAMLphp, etc.)' },
  { value: 'okta', label: 'Okta / Identity proxy' },
  { value: 'oauth', label: 'OAuth / custom IdP redirect' },
]

const normalizeAuthType = (value) => (value ? value.trim().toLowerCase() : '')

const createRole = (label) => ({
  id: typeof crypto !== 'undefined' && crypto.randomUUID ? crypto.randomUUID() : nanoid(),
  label,
  username: '',
  password: '',
  authType: '',
  tags: '',
})

const consoleSteps = stageBlueprints.map((stage) => stage.label)

const preflightMessages = [
  'Validating target…',
  'Checking credential mode…',
  'Preparing agent…',
  'Ready to launch'
]

function AuthReconLaunch() {
  const navigate = useNavigate()
  const [targetUrl, setTargetUrl] = useState('')
  const [loginHint, setLoginHint] = useState('')
  const [domainPrefix, setDomainPrefix] = useState('')
  const [authTypeOverride, setAuthTypeOverride] = useState('')
  const [selectedEngines, setSelectedEngines] = useState(['selenium'])
  const [mode, setMode] = useState('inline')
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [saveCredentialName, setSaveCredentialName] = useState('')
  const [showSaveCredential, setShowSaveCredential] = useState(false)
  const [selectedCredentialId, setSelectedCredentialId] = useState(null)
  const [roles, setRoles] = useState([createRole('Primary role')])
  const [launchPhase, setLaunchPhase] = useState('idle')
  const [activeConsoleStep, setActiveConsoleStep] = useState(-1)
  const [consoleComplete, setConsoleComplete] = useState(false)
  const [pendingRunDetail, setPendingRunDetail] = useState(null)
  const [lastRunDetail, setLastRunDetail] = useState(null)
  const [terminalLogs, setTerminalLogs] = useState([])
  const [terminalVisible, setTerminalVisible] = useState(false)
  const [terminalExpanded, setTerminalExpanded] = useState(false)
  const [isReplayOpen, setIsReplayOpen] = useState(false)
  const [expandedStageId, setExpandedStageId] = useState(null)
  const [buttonPulse, setButtonPulse] = useState(false)
  const [preflightIndex, setPreflightIndex] = useState(0)
  const [formCollapsed, setFormCollapsed] = useState(false)
  const [activeRunId, setActiveRunId] = useState(null)
  const [consoleCollapsed, setConsoleCollapsed] = useState(true)
  const [isHelpModalOpen, setIsHelpModalOpen] = useState(false)
  const [streamingEnabled, setStreamingEnabled] = useState(false)
  const [recordingMode, setRecordingMode] = useState('auto')
  const [advancedOptionsOpen, setAdvancedOptionsOpen] = useState(false)
  const consoleTimersRef = useRef([])

  // Always use pendingRunDetail for live updates, fallback to lastRunDetail
  const stageData = useMemo(
    () => buildStageData(pendingRunDetail || lastRunDetail),
    [pendingRunDetail, lastRunDetail],
  )

  const replayStageData = useMemo(
    () => buildStageData(lastRunDetail),
    [lastRunDetail],
  )

  const stageActiveIndex = useMemo(() => {
    if (!stageData.length) return -1
    if (launchPhase === 'preflight') return 0

    // If we have pendingRunDetail, calculate progress based on actual run status
    if (pendingRunDetail) {
      const status = pendingRunDetail.status
      const timelineLength = pendingRunDetail.timeline?.length || 0

      // If run is complete (succeeded/failed), show all stages as complete
      if (status === 'succeeded' || status === 'failed') {
        return stageData.length - 1
      }

      // If run is running, calculate progress based on timeline events
      if (status === 'running') {
        // Map timeline events to stage progress (0-4 stages, 5 total)
        // Use timeline length as a proxy for completion
        const progressRatio = Math.min(timelineLength / 10, 1) // Assume ~10 events = complete
        return Math.floor(progressRatio * (stageData.length - 1))
      }

      // If queued, show first stage as active
      if (status === 'queued') {
        return 0
      }
    }

    // Fallback to animation-based index for initial launch sequence
    if (launchPhase === 'success') return stageData.length - 1
    return activeConsoleStep
  }, [activeConsoleStep, launchPhase, stageData.length, pendingRunDetail])

  const latestTimelineEntry = useMemo(() => {
    if (!pendingRunDetail?.timeline?.length) return null
    return pendingRunDetail.timeline[pendingRunDetail.timeline.length - 1]
  }, [pendingRunDetail])

  const liveStatusLabel = useMemo(() => {
    if (!pendingRunDetail) return ''
    const status = (pendingRunDetail.status || '').toLowerCase()
    const prefixMap = {
      queued: 'Queued',
      running: 'Running',
      succeeded: 'Completed',
      failed: 'Failed',
    }
    const prefix = prefixMap[status]
    if (!prefix) return ''
    const note = latestTimelineEntry?.message
    return note ? `${prefix}: ${note}` : `${prefix}…`
  }, [pendingRunDetail, latestTimelineEntry])

  const livePollingActive = useMemo(
    () =>
      Boolean(
        activeRunId &&
        pendingRunDetail &&
        (pendingRunDetail.status === 'queued' || pendingRunDetail.status === 'running'),
      ),
    [activeRunId, pendingRunDetail],
  )

  const consoleLiveLabel = useMemo(() => {
    if (liveStatusLabel) {
      return livePollingActive ? `${liveStatusLabel} • Auto-refreshing` : liveStatusLabel
    }
    return livePollingActive ? 'Auto-refreshing' : ''
  }, [liveStatusLabel, livePollingActive])

  const consoleStatusLabel = useMemo(() => {
    if (launchPhase === 'preflight') return 'Initializing'
    if (launchPhase === 'inProgress') return 'Live'
    if (launchPhase === 'success') return 'Complete'
    if (lastRunDetail) return 'Last run'
    return ''
  }, [launchPhase, lastRunDetail])

  useEffect(() => {
    return () => {
      consoleTimersRef.current.forEach((timer) => clearTimeout(timer))
      consoleTimersRef.current = []
    }
  }, [])

  const scheduleTimer = (callback, delay) => {
    const timer = setTimeout(callback, delay)
    consoleTimersRef.current.push(timer)
    return timer
  }

  const triggerButtonPulse = () => {
    setButtonPulse(true)
    setTimeout(() => setButtonPulse(false), 350)
  }

  const resetLaunchExperience = () => {
    consoleTimersRef.current.forEach((timer) => clearTimeout(timer))
    consoleTimersRef.current = []
    setLaunchPhase('idle')
    setActiveConsoleStep(-1)
    setConsoleComplete(false)
    setPendingRunDetail(null)
    setLastRunDetail(null)
    setPreflightIndex(0)
    setExpandedStageId(null)
    setIsReplayOpen(false)
    setFormCollapsed(false)
    setConsoleCollapsed(true)
    setActiveRunId(null)
  }

  const runConsoleSequence = (speed = 220, markComplete = true) => {
    setActiveConsoleStep(-1)
    consoleSteps.forEach((_, index) => {
      scheduleTimer(() => {
        setActiveConsoleStep(index)
        if (markComplete && index === consoleSteps.length - 1) {
          scheduleTimer(() => setConsoleComplete(true), speed)
        }
      }, index * speed)
    })
  }

  const canSubmit = () => {
    if (!targetUrl) return false
    // Manual recording only needs URL (operator logs in manually)
    if (recordingMode === 'manual') return true
    // Automated mode requires credentials
    if (mode === 'inline') {
      return Boolean(username && password)
    }
    if (mode === 'stored') {
      return Boolean(selectedCredentialId)
    }
    if (mode === 'roles') {
      return roles.some((role) => role.username.trim() && role.password.trim())
    }
    return true
  }

  const credentialsQuery = useQuery({
    queryKey: ['authrecon', 'credentials'],
    queryFn: async () => {
      const response = await authreconApi.get('credentials')
      return Array.isArray(response.data) ? response.data : []
    },
  })

  const loadRunDetail = async (runId) => {
    try {
      const response = await authreconApi.get(`runs/${runId}`)
      const runData = response.data
      setPendingRunDetail(runData)
      // Update terminal logs from fresh data
      setTerminalLogs(buildTerminalLogs(runData))
      setActiveRunId(runId)
    } catch (error) {
      console.error('Failed to load run detail', error)
      const fallback = { id: runId, target_url: targetUrl, status: 'queued', timeline: [] }
      setPendingRunDetail(fallback)
      setTerminalLogs(buildTerminalLogs(fallback))
      setActiveRunId(runId)
    }
  }

  const submitRunMutation = useMutation({
    mutationFn: async (payload) => {
      const response = await authreconApi.post('runs', payload)
      return response.data
    },
    onSuccess: (data) => {
      // Manual recording: skip animation, go directly to run detail page
      if (recordingMode === 'manual') {
        navigate(`/authrecon/run/${data.id}`)
        return
      }

      // Automated: normal flow with animation
      setActiveRunId(data.id)
      loadRunDetail(data.id)
    },
    onError: () => {
      setLaunchPhase('idle')
      setConsoleComplete(false)
      setActiveConsoleStep(-1)
      setActiveRunId(null)
    }
  })

  useEffect(() => {
    if (!activeRunId) return undefined
    const interval = setInterval(() => {
      loadRunDetail(activeRunId)
    }, 5000)
    return () => clearInterval(interval)
  }, [activeRunId])

  useEffect(() => {
    if (!pendingRunDetail) return
    if (pendingRunDetail.status === 'succeeded' || pendingRunDetail.status === 'failed') {
      setActiveRunId(null)
    }
  }, [pendingRunDetail])

  const openReplayModal = () => {
    if (!lastRunDetail) return
    setIsReplayOpen(true)
  }

  const handleViewRun = () => {
    if (lastRunDetail?.id) {
      navigate(`/authrecon/run/${lastRunDetail.id}`)
    }
  }

  const toggleTerminal = () => {
    setTerminalVisible((prev) => {
      if (prev) return false
      setTerminalExpanded(false)
      return true
    })
  }

  useEffect(() => {
    if (launchPhase !== 'preflight') {
      setPreflightIndex(0)
      return undefined
    }
    let cancelled = false
    setPreflightIndex(0)
    preflightMessages.forEach((_, index) => {
      scheduleTimer(() => {
        if (!cancelled) {
          setPreflightIndex(index)
        }
      }, index * 220)
    })
    return () => {
      cancelled = true
    }
  }, [launchPhase])

  useEffect(() => {
    if (consoleComplete && pendingRunDetail) {
      setLaunchPhase('success')
      setLastRunDetail(pendingRunDetail)
    }
  }, [consoleComplete, pendingRunDetail])

  const handleSubmit = (e) => {
    e.preventDefault()
    triggerButtonPulse()

    if (!targetUrl) {
      alert('Please enter a target URL')
      return
    }

    if (!canSubmit()) {
      alert('Please complete the credential details for the selected mode')
      return
    }

    const payload = {
      target_url: targetUrl.trim(),
      engines: selectedEngines,
      options: {},
      streaming_enabled: streamingEnabled,
      recording_mode: recordingMode
    }

    // Add login_hint if provided
    const trimmedHint = loginHint.trim()
    if (trimmedHint) {
      payload.login_hint = trimmedHint
    }

    // Add domain_prefix if provided
    const trimmedDomainPrefix = domainPrefix.trim()
    if (trimmedDomainPrefix) {
      payload.domain_prefix = trimmedDomainPrefix
    }

    const normalizedAuthType = normalizeAuthType(authTypeOverride)
    if (normalizedAuthType) {
      payload.auth_type = normalizedAuthType
    }

    // Manual recording mode: operator logs in manually, no credentials needed upfront
    if (recordingMode !== 'manual') {
      if (mode === 'inline') {
        if (!username || !password) {
          alert('Please enter credentials')
          return
        }
        payload.username = username
        payload.password = password
        if (showSaveCredential && saveCredentialName.trim()) {
          payload.save_credential_name = saveCredentialName.trim()
        }
      } else if (mode === 'stored') {
        if (!selectedCredentialId) {
          alert('Select a saved credential or switch to inline mode')
          return
        }
        payload.credential_id = selectedCredentialId
      } else if (mode === 'roles') {
        const sanitizedRoles = roles
          .map((role, index) => ({
            label: role.label || `Role ${index + 1}`,
            username: role.username.trim(),
            password: role.password.trim(),
            auth_type: normalizeAuthType(role.authType),
            tags: role.tags
              .split(',')
              .map((tag) => tag.trim())
              .filter(Boolean),
          }))
          .filter((role) => role.username && role.password)
        if (!sanitizedRoles.length) {
          alert('Provide at least one role with credentials')
          return
        }
        payload.roles = sanitizedRoles
      }
    }

    resetLaunchExperience()

    // Collapse the form after a brief delay to show the animation
    scheduleTimer(() => setFormCollapsed(true), 400)

    setLaunchPhase('preflight')
    setTerminalLogs([])
    setTerminalVisible(false)
    submitRunMutation.mutate(payload)
    scheduleTimer(() => {
      setLaunchPhase('inProgress')
      runConsoleSequence()
    }, 900)
  }

  const isCardAnimating = launchPhase === 'preflight' || launchPhase === 'inProgress'
 const showSummary = launchPhase === 'success' && lastRunDetail
  const showConsolePanel = launchPhase !== 'idle' || Boolean(lastRunDetail)
  const stageHeaderActions = (
    <Button
      type="button"
      variant={consoleCollapsed ? 'outline' : 'ghost'}
      size="sm"
      onClick={() => setConsoleCollapsed((prev) => !prev)}
    >
      {consoleCollapsed ? 'View stages' : 'Hide stages'}
    </Button>
  )

  return (
    <>
      <Header title="Launch AuthRecon Run" subtitle="Detect a login and record a verified script for Tenable WAS" />
      <div className="flex-1 overflow-y-auto scrollbar-thin p-6">
        <div className="max-w-6xl mx-auto space-y-6">
          <div className="flex justify-between items-center">
            <Button variant="ghost" onClick={() => setIsHelpModalOpen(true)}>
              <HelpCircle className="w-4 h-4 mr-2" />
              Detection Guide
            </Button>
            <Button variant="ghost" onClick={() => navigate('/authrecon')}>
              Back to Runs
            </Button>
          </div>
          <Card
            padding="lg"
            className={`border border-[var(--stroke-dark)] shadow-[var(--shadow-card)] transition-all duration-700 ease-in-out ${
              isCardAnimating ? 'launch-card-anim relative overflow-hidden' : ''
            } ${
              formCollapsed
                ? 'max-h-0 opacity-0 scale-y-0 origin-top overflow-hidden pointer-events-none transform'
                : 'max-h-[2000px] opacity-100 scale-y-100'
            }`}
          >
          {isCardAnimating && (
            <div className="pointer-events-none absolute inset-0 rounded-[1.5rem] overflow-hidden">
              <div className="launch-sweep" />
            </div>
          )}
          <form onSubmit={handleSubmit} className="space-y-6 relative">
            {/* Target URL */}
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-2">
                Target URL *
              </label>
              <Input
                type="url"
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                placeholder="https://example.com/login"
                required
              />
              <p className="text-xs text-slate-500 mt-1">
                The login page or application entry point to analyze
              </p>
            </div>

            {/* Recording Mode */}
            <div>
              <label className="block text-sm font-medium text-slate-300 mb-3">
                Recording Mode
              </label>
              <div className="space-y-2.5">
                {/* Auto Mode */}
                <label className="flex items-start gap-3 p-3 rounded-lg border border-slate-800/80 hover:border-slate-700/80 cursor-pointer transition-colors">
                  <input
                    type="radio"
                    name="recording-mode"
                    value="auto"
                    checked={recordingMode === 'auto'}
                    onChange={(e) => setRecordingMode(e.target.value)}
                    className="mt-0.5 w-4 h-4 rounded-full border-slate-700 bg-slate-900 text-[var(--accent-blue)] focus:ring-[var(--stroke-blue)] focus:ring-offset-0 focus:ring-2"
                  />
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-slate-200">Automated</span>
                      <Badge variant="info">Recommended</Badge>
                    </div>
                    <p className="text-xs text-slate-500 mt-1">
                      Automation logs in using provided credentials. Fastest option for standard authentication flows.
                    </p>
                  </div>
                </label>

                {/* Manual Mode */}
                <label className="flex items-start gap-3 p-3 rounded-lg border border-slate-800/80 hover:border-slate-700/80 cursor-pointer transition-colors">
                  <input
                    type="radio"
                    name="recording-mode"
                    value="manual"
                    checked={recordingMode === 'manual'}
                    onChange={(e) => setRecordingMode(e.target.value)}
                    className="mt-0.5 w-4 h-4 rounded-full border-slate-700 bg-slate-900 text-[var(--accent-blue)] focus:ring-[var(--stroke-blue)] focus:ring-offset-0 focus:ring-2"
                  />
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <span className="text-sm font-medium text-slate-200">Manual Recording</span>
                    </div>
                    <p className="text-xs text-slate-500 mt-1">
                      You guide the browser through authentication manually via VNC. Best for complex flows (2FA, CAPTCHAs, biometrics).
                    </p>
                  </div>
                </label>
              </div>
            </div>

            {/* Advanced Options Accordion - Only for automated mode */}
            {recordingMode === 'auto' && (
              <div className="border-t border-slate-800 pt-6">
                <button
                  type="button"
                  onClick={() => setAdvancedOptionsOpen(!advancedOptionsOpen)}
                  className="w-full flex items-center justify-between text-left group"
                >
                  <div className="flex items-center gap-2">
                    <span className="text-sm font-medium text-slate-300 group-hover:text-slate-200 transition-colors">
                      Advanced Options
                    </span>
                    <Badge variant="default" size="sm">Optional</Badge>
                  </div>
                  <ChevronDown
                    className={`w-4 h-4 text-slate-500 transition-transform duration-200 ${
                      advancedOptionsOpen ? 'rotate-180' : ''
                    }`}
                  />
                </button>
                <p className="text-xs text-slate-500 mt-1 mb-4">
                  Fine-tune authentication detection, domain settings, and automation engines
                </p>

                {advancedOptionsOpen && (
                  <div className="space-y-6 pt-4 animate-fade-in">
                    {/* Login Hint */}
                    <div>
                      <label htmlFor="login-hint" className="block text-sm font-medium text-slate-300 mb-2">
                        Login Hint <span className="text-slate-500 font-normal">(Optional)</span>
                      </label>
                      <Input
                        id="login-hint"
                        type="text"
                        value={loginHint}
                        onChange={(e) => setLoginHint(e.target.value)}
                        placeholder="e.g., funeral, medical, partner, client"
                      />
                      <p className="text-xs text-slate-500 mt-1">
                        If the site has multiple login buttons, enter a keyword to select the correct one
                      </p>
                    </div>

                    {/* Authentication Type Override */}
                    <div>
                      <label htmlFor="auth-type" className="block text-sm font-medium text-slate-300 mb-2">
                        Authentication Type <span className="text-slate-500 font-normal">(Optional)</span>
                      </label>
                      <div className="relative">
                        <select
                          id="auth-type"
                          value={authTypeOverride}
                          onChange={(e) => setAuthTypeOverride(e.target.value)}
                          className="input-field w-full px-4 py-2.5 bg-transparent border border-slate-800/80 rounded-xl text-slate-100 text-sm focus:outline-none focus:border-[var(--stroke-blue)] appearance-none"
                        >
                          {AUTH_TYPE_OPTIONS.map((option) => (
                            <option key={option.value || 'auto'} value={option.value}>
                              {option.label}
                            </option>
                          ))}
                        </select>
                        <span className="pointer-events-none absolute right-4 top-1/2 -translate-y-1/2 text-slate-500">
                          <ArrowRight className="w-4 h-4 rotate-90" aria-hidden="true" />
                        </span>
                      </div>
                      <p className="text-xs text-slate-500 mt-1">
                        Force a specific automation path when you already know the site uses Azure AD, LDAP, Okta, etc.
                      </p>
                    </div>

                    {/* Domain Prefix */}
                    <div>
                      <label htmlFor="domain-prefix" className="block text-sm font-medium text-slate-300 mb-2">
                        Domain Prefix <span className="text-slate-500 font-normal">(Optional)</span>
                      </label>
                      <Input
                        id="domain-prefix"
                        type="text"
                        value={domainPrefix}
                        onChange={(e) => setDomainPrefix(e.target.value)}
                        placeholder="e.g., COMPANY, DOMAIN, NS"
                      />
                      <p className="text-xs text-slate-500 mt-1">
                        For DOMAIN\username or username@DOMAIN format (common in enterprise/government sites)
                      </p>
                    </div>

                    {/* Authentication Engines */}
                    <div>
                      <label className="block text-sm font-medium text-slate-300 mb-3">
                        Authentication Engines <span className="text-slate-500 font-normal">(Advanced)</span>
                      </label>
                      <div className="space-y-2.5">
                        <label className="flex items-start gap-3 p-3 rounded-lg border border-slate-800/80 hover:border-slate-700/80 cursor-pointer transition-colors">
                          <input
                            type="checkbox"
                            checked={selectedEngines.includes('selenium')}
                            onChange={(e) => {
                              if (e.target.checked) {
                                setSelectedEngines([...selectedEngines, 'selenium'])
                              } else {
                                setSelectedEngines(selectedEngines.filter(eng => eng !== 'selenium'))
                              }
                            }}
                            className="mt-0.5 w-4 h-4 rounded border-slate-700 bg-slate-900 text-[var(--accent-blue)] focus:ring-[var(--stroke-blue)] focus:ring-offset-0 focus:ring-2"
                          />
                          <div className="flex-1">
                            <div className="flex items-center gap-2">
                              <span className="text-sm font-medium text-slate-200">Selenium</span>
                              <Badge variant="default" size="sm">Default</Badge>
                            </div>
                            <p className="text-xs text-slate-500 mt-1">
                              Generates .side files for Tenable scanner integration. Classic form automation.
                            </p>
                          </div>
                        </label>

                        <label className="flex items-start gap-3 p-3 rounded-lg border border-slate-800/80 hover:border-slate-700/80 cursor-pointer transition-colors">
                          <input
                            type="checkbox"
                            checked={selectedEngines.includes('playwright')}
                            onChange={(e) => {
                              if (e.target.checked) {
                                setSelectedEngines([...selectedEngines, 'playwright'])
                              } else {
                                setSelectedEngines(selectedEngines.filter(eng => eng !== 'playwright'))
                              }
                            }}
                            className="mt-0.5 w-4 h-4 rounded border-slate-700 bg-slate-900 text-[var(--accent-blue)] focus:ring-[var(--stroke-blue)] focus:ring-offset-0 focus:ring-2"
                          />
                          <div className="flex-1">
                            <div className="flex items-center gap-2">
                              <span className="text-sm font-medium text-slate-200">Playwright</span>
                              <Badge variant="info" size="sm">HAR Capture</Badge>
                            </div>
                            <p className="text-xs text-slate-500 mt-1">
                              Captures complete network trace (HAR file). Best for modern SPAs and API discovery.
                            </p>
                          </div>
                        </label>

                        <label className="flex items-start gap-3 p-3 rounded-lg border border-slate-800/80 hover:border-slate-700/80 cursor-pointer transition-colors">
                          <input
                            type="checkbox"
                            checked={selectedEngines.includes('httpx')}
                            onChange={(e) => {
                              if (e.target.checked) {
                                setSelectedEngines([...selectedEngines, 'httpx'])
                              } else {
                                setSelectedEngines(selectedEngines.filter(eng => eng !== 'httpx'))
                              }
                            }}
                            className="mt-0.5 w-4 h-4 rounded border-slate-700 bg-slate-900 text-[var(--accent-blue)] focus:ring-[var(--stroke-blue)] focus:ring-offset-0 focus:ring-2"
                          />
                          <div className="flex-1">
                            <div className="flex items-center gap-2">
                              <span className="text-sm font-medium text-slate-200">HTTPX</span>
                              <Badge variant="success" size="sm">Fast</Badge>
                            </div>
                            <p className="text-xs text-slate-500 mt-1">
                              Headless HTTP client, ~100x faster. Use for API-only auth (no JavaScript required).
                            </p>
                          </div>
                        </label>
                      </div>
                      <p className="text-xs text-slate-500 mt-2">
                        Engines run sequentially with 2-3 second delays to avoid triggering rate limits
                      </p>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Mode Selector - Only for automated mode */}
            {recordingMode === 'auto' && (
              <div className="border-t border-slate-800 pt-6">
                <h3 className="text-lg font-semibold text-slate-50 mb-4">Credential Mode</h3>
                <div className="flex flex-wrap gap-3">
                  {[
                    { id: 'inline', label: 'Inline credential' },
                    { id: 'stored', label: 'Saved credential' },
                    { id: 'roles', label: 'Multi-role pack' },
                  ].map((option) => (
                    <button
                      key={option.id}
                      type="button"
                      className={`px-4 py-2 rounded-2xl border text-sm ${
                        mode === option.id
                          ? 'border-[var(--stroke-blue)] bg-[var(--sidebar-active-bg)] text-[var(--text-primary)]'
                          : 'border-[var(--stroke-dark)] text-[var(--text-secondary)] hover:border-[var(--stroke-blue)]'
                      }`}
                      onClick={() => setMode(option.id)}
                    >
                      {option.label}
                    </button>
                  ))}
                </div>
              </div>
            )}

            {/* Inline Credentials - Only for automated mode */}
            {recordingMode === 'auto' && mode === 'inline' && (
              <div className="border-t border-slate-800 pt-6 space-y-4">
                <h3 className="text-lg font-semibold text-slate-50">Credentials</h3>
                <Input
                  label="Username"
                  value={username}
                  onChange={(e) => setUsername(e.target.value)}
                  placeholder="user@example.com"
                  autoComplete="off"
                  required
                />
                <Input
                  label="Password"
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="••••••••"
                  autoComplete="new-password"
                  required
                />
                <div className="flex items-start gap-3">
                  <input
                    type="checkbox"
                    id="saveCredential"
                    checked={showSaveCredential}
                    onChange={(e) => setShowSaveCredential(e.target.checked)}
                    className="mt-1 w-4 h-4 rounded border-slate-700 bg-slate-900 focus:ring-[var(--accent-blue)] focus:ring-offset-slate-950"
                    style={{ accentColor: 'var(--accent-blue)' }}
                  />
                  <div className="flex-1">
                    <label htmlFor="saveCredential" className="block text-sm font-medium text-slate-300 cursor-pointer">
                      Save these credentials for future use
                    </label>
                    <p className="text-xs text-slate-500 mt-1">
                      Credentials will be encrypted and stored in your vault
                    </p>
                  </div>
                </div>
                {showSaveCredential && (
                  <div className="ml-7 pt-2">
                    <Input
                      label="Credential name"
                      value={saveCredentialName}
                      onChange={(e) => setSaveCredentialName(e.target.value)}
                      placeholder="e.g., Example App - Admin"
                    />
                  </div>
                )}
              </div>
            )}

            {/* Saved Credentials - Only for automated mode */}
            {recordingMode === 'auto' && mode === 'stored' && (
              <div className="border-t border-slate-800 pt-6">
                <h3 className="text-lg font-semibold text-slate-50 mb-4">Saved Credentials</h3>
                {credentialsQuery.isLoading ? (
                  <p className="text-sm text-slate-500">Loading credentials…</p>
                ) : (
                  <div className="space-y-3">
                    {credentialsQuery.data?.map((credential) => (
                      <label
                        key={credential.id}
                        className={`flex items-center justify-between p-4 rounded-2xl border cursor-pointer ${
                          selectedCredentialId === credential.id
                            ? 'border-[var(--stroke-blue)] bg-[var(--sidebar-active-bg)]'
                            : 'border-[var(--stroke-dark)] hover:border-[var(--stroke-blue)]'
                        }`}
                      >
                        <div>
                          <p className="text-sm font-semibold text-slate-100">{credential.name}</p>
                          <p className="text-xs text-slate-500">{credential.username}</p>
                        </div>
                        <input
                          type="radio"
                          name="credential"
                          className="w-4 h-4"
                          style={{ accentColor: 'var(--accent-blue)' }}
                          checked={selectedCredentialId === credential.id}
                          onChange={() => setSelectedCredentialId(credential.id)}
                        />
                      </label>
                    ))}
                    {!credentialsQuery.data?.length && (
                      <p className="text-sm text-slate-500">
                        No saved credentials yet. Switch to inline mode to create one.
                      </p>
                    )}
                  </div>
                )}
              </div>
            )}

            {/* Multi-role - Only for automated mode */}
            {recordingMode === 'auto' && mode === 'roles' && (
              <div className="border-t border-slate-800 pt-6 space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-lg font-semibold text-slate-50">Multi-role pack</h3>
                    <p className="text-sm text-slate-500">Launch multiple identities in a single job.</p>
                  </div>
                  <Button
                    type="button"
                    variant="secondary"
                    size="sm"
                    onClick={() => setRoles((prev) => [...prev, createRole(`Role ${prev.length + 1}`)])}
                  >
                    + Add role
                  </Button>
                </div>
                <div className="space-y-3">
                  {roles.map((role, index) => (
                    <div key={role.id} className="p-4 rounded-2xl border border-slate-700/60">
                      <div className="flex items-center justify-between mb-4">
                        <input
                          className="text-base font-semibold bg-transparent border-b border-transparent focus:border-[var(--accent-blue)] outline-none text-slate-100 flex-1 mr-4"
                          value={role.label}
                          onChange={(e) => {
                            const next = [...roles]
                            next[index].label = e.target.value
                            setRoles(next)
                          }}
                          placeholder="Role label"
                        />
                        {roles.length > 1 && (
                          <Button
                            type="button"
                            variant="ghost"
                            size="sm"
                            onClick={() => setRoles((prev) => prev.filter((r) => r.id !== role.id))}
                          >
                            Remove
                          </Button>
                        )}
                      </div>
                      <div className="grid md:grid-cols-2 gap-4">
                        <Input
                          label="Username"
                          value={role.username}
                          onChange={(e) => {
                            const next = [...roles]
                            next[index].username = e.target.value
                            setRoles(next)
                          }}
                          autoComplete="off"
                        />
                        <Input
                          label="Password"
                          type="password"
                          value={role.password}
                          onChange={(e) => {
                            const next = [...roles]
                            next[index].password = e.target.value
                            setRoles(next)
                          }}
                          autoComplete="new-password"
                        />
                        <div>
                          <label className="block text-sm font-medium text-slate-300 mb-2">
                            Auth Type <span className="text-slate-500 font-normal">(Optional)</span>
                          </label>
                          <select
                            value={role.authType}
                            onChange={(e) => {
                              const next = [...roles]
                              next[index].authType = e.target.value
                              setRoles(next)
                            }}
                            className="input-field w-full px-4 py-2.5 bg-transparent border border-slate-800/80 rounded-xl text-slate-100 text-sm focus:outline-none focus:border-[var(--stroke-blue)] appearance-none"
                          >
                            {AUTH_TYPE_OPTIONS.map((option) => (
                              <option key={`${role.id}-${option.value || 'auto'}`} value={option.value}>
                                {option.label}
                              </option>
                            ))}
                          </select>
                        </div>
                        <Input
                          label="Tags"
                          value={role.tags}
                          onChange={(e) => {
                            const next = [...roles]
                            next[index].tags = e.target.value
                            setRoles(next)
                          }}
                          placeholder="admin, azure-ad"
                        />
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Streaming Option - Only for automated mode (manual mode always has VNC) */}
            {recordingMode === 'auto' && (
              <div className="border-t border-slate-800 pt-6">
                <div className="flex items-start gap-3">
                  <input
                    type="checkbox"
                    id="streamingEnabled"
                    checked={streamingEnabled}
                    onChange={(e) => setStreamingEnabled(e.target.checked)}
                    className="mt-1 w-4 h-4 rounded border-slate-700 bg-slate-900 focus:ring-[var(--accent-blue)] focus:ring-offset-slate-950"
                    style={{ accentColor: 'var(--accent-blue)' }}
                  />
                  <div className="flex-1">
                    <label htmlFor="streamingEnabled" className="block text-sm font-medium text-slate-300 cursor-pointer">
                      Enable live browser streaming <span className="text-slate-500 font-normal">(Optional)</span>
                    </label>
                    <p className="text-xs text-slate-500 mt-1">
                      Watch the Selenium browser in real time via the portal&apos;s authenticated VNC proxy. Useful for debugging complex auth flows. Slightly increases resource usage.
                    </p>
                  </div>
                </div>
              </div>
            )}

            {/* Submit Button */}
            <div className="flex items-center justify-between pt-6 border-t border-slate-800">
              {recordingMode === 'auto' ? (
                <div className="flex items-center gap-3">
                  <Badge variant="info">
                    Authentication Detection Enabled
                  </Badge>
                  <Badge variant="default">
                    Tech Fingerprinting Enabled
                  </Badge>
                </div>
              ) : (
                <div className="flex items-center gap-3">
                  <Badge variant="info">
                    Manual VNC Control
                  </Badge>
                  <Badge variant="default">
                    Interaction Recording Enabled
                  </Badge>
                </div>
              )}

              <div className="flex items-center gap-3">
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => navigate('/authrecon')}
                >
                  Cancel
                </Button>
                <Button
                  type="submit"
                  variant="primary"
                  loading={submitRunMutation.isLoading}
                  disabled={submitRunMutation.isLoading}
                  className={`origin-center transform transition-transform ${
                    buttonPulse ? 'scale-[0.98]' : 'scale-100'
                  }`}
                  style={buttonPulse ? { boxShadow: '0 0 12px rgba(0,180,255,0.35)' } : undefined}
                >
                  {recordingMode === 'manual' ? 'Start Manual Session' : 'Launch Scan'}
                </Button>
              </div>
            </div>

            {launchPhase === 'preflight' && (
              <div className="pt-4">
                <div className="rounded-2xl border border-[var(--stroke-blue)] bg-[var(--bg-1)] p-4 shadow-[var(--shadow-card)]">
                  <div className="flex items-center gap-2 text-[11px] uppercase tracking-[0.2em] text-[var(--text-secondary)] mb-3">
                    <Sparkles className="w-3.5 h-3.5 text-[var(--accent-blue)]" />
                    Initialization
                  </div>
                  <div className="flex flex-wrap gap-2">
                    {preflightMessages.map((message, index) => {
                      const status = index <= preflightIndex ? 'active' : 'pending'
                      return (
                        <div
                          key={message}
                          className={`flex items-center gap-2 rounded-xl border px-3 py-1.5 text-xs font-mono transition ${
                            status === 'active'
                              ? 'border-[var(--stroke-blue)] text-[var(--text-primary)] bg-[var(--sidebar-active-bg)]'
                              : 'border-slate-800/70 text-[var(--text-muted)]'
                          }`}
                        >
                          <span
                            className={`h-2 w-2 rounded-full ${
                              status === 'active' ? 'bg-[var(--accent-blue)] animate-pulse' : 'bg-slate-600'
                            }`}
                          />
                          {message}
                        </div>
                      )
                    })}
                  </div>
                </div>
              </div>
            )}

            {/* Error Message */}
            {submitRunMutation.isError && (
              <div className="p-4 rounded-lg border border-rose-900/50 bg-rose-950/20">
                <p className="text-sm text-rose-400">
                  <strong>Error:</strong> {submitRunMutation.error?.response?.data?.detail || submitRunMutation.error?.message || 'Failed to submit run'}
                </p>
              </div>
            )}
          </form>
        </Card>

        {(launchPhase !== 'idle' || lastRunDetail) && (
          <div className="space-y-4">
            {showConsolePanel && (
              <StageConsole
                stages={stageData}
                activeIndex={stageActiveIndex}
                expandedStage={expandedStageId}
                onToggleStage={setExpandedStageId}
                replayLabel={consoleStatusLabel}
                liveLabel={consoleLiveLabel}
                headerActions={stageHeaderActions}
                collapsed={consoleCollapsed}
              />
            )}

        {showSummary && lastRunDetail && (
          <SuccessSummary
            detail={lastRunDetail}
            onReplay={openReplayModal}
            onViewRun={handleViewRun}
            onToggleTerminal={toggleTerminal}
          />
        )}
          </div>
        )}

        {/* Info Card */}
        <Card padding="lg" className="bg-slate-900/30">
          <h3 className="text-sm font-semibold text-slate-300 mb-3">
            What happens next?
          </h3>
          <ul className="space-y-2 text-sm text-slate-400">
            <li className="flex items-start gap-2">
              <span className="text-[var(--accent-blue)] mt-0.5">•</span>
              <span>AuthRecon will navigate to the target URL and detect the authentication type</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-[var(--accent-blue)] mt-0.5">•</span>
              <span>Credentials will be tested to verify successful authentication</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-[var(--accent-blue)] mt-0.5">•</span>
              <span>Technology stack will be fingerprinted (JS frameworks, libraries, security headers)</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-[var(--accent-blue)] mt-0.5">•</span>
              <span>Results will include session cookies, auth patterns, and reconnaissance data</span>
            </li>
            <li className="flex items-start gap-2">
              <span className="text-[var(--accent-blue)] mt-0.5">•</span>
              <span>Typical run time: 30-60 seconds</span>
            </li>
          </ul>
        </Card>
        </div>
      </div>
      {lastRunDetail && (
        <ReplayModal
          open={isReplayOpen}
          onClose={() => setIsReplayOpen(false)}
          stages={replayStageData}
          timeline={lastRunDetail?.timeline || []}
          rawData={lastRunDetail || {}}
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
      <AuthReconHelpModal
        isOpen={isHelpModalOpen}
        onClose={() => setIsHelpModalOpen(false)}
      />
    </>
  )
}

function TimelinePreview({ timeline }) {
  if (!timeline?.length) return null
  const preview = timeline.slice(0, 5)
  return (
    <div className="mt-5">
      <p className="text-xs uppercase tracking-widest text-slate-500 mb-2">Timeline preview</p>
      <div className="flex items-center gap-4">
        {preview.map((entry, idx) => (
          <div key={`${entry.occurred_at}-${idx}`} className="flex flex-col items-center text-xs text-slate-400">
            <div className="w-2.5 h-2.5 rounded-full bg-sky-400 animate-pulse-slow mb-1" />
            <span>{new Date(entry.occurred_at).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

function SuccessSummary({ detail, onReplay, onViewRun, onToggleTerminal }) {
  return (
    <Card padding="lg" className="animate-success-card">
      <div className="flex flex-col gap-4">
        <div className="flex flex-wrap items-start justify-between gap-4">
          <div className="space-y-1 text-sm text-slate-300">
            <p>Auth flow detected: <span className="text-slate-50 font-semibold">{detail?.detected_auth?.auth_type || detail?.auth_type || 'Auto'}</span></p>
            <p>Final URL: <span className="text-slate-50 font-semibold">{detail?.final_url || 'Pending'}</span></p>
            <p>Fingerprint: <span className="text-slate-50 font-semibold">{detail?.tech_fingerprint?.js_frameworks?.join(', ') || '—'}</span></p>
            <p>Run ID: <span className="text-slate-50 font-semibold">{detail?.id}</span></p>
          </div>
          <div className="flex flex-wrap gap-3">
            <Button type="button" variant="outline" size="sm" onClick={onReplay}>
              <PlayCircle className="w-4 h-4" />
              Replay Sequence
            </Button>
            <Button type="button" variant="ghost" size="sm" onClick={onToggleTerminal}>
              <TerminalIcon className="w-4 h-4" />
              Glass Terminal
            </Button>
            <Button type="button" variant="primary" size="sm" onClick={onViewRun}>
              View Run
              <ArrowRight className="w-4 h-4" />
            </Button>
          </div>
        </div>
        <TimelinePreview timeline={detail?.timeline} />
      </div>
    </Card>
  )
}

export default AuthReconLaunch
