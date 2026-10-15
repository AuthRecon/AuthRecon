import { nanoid } from 'nanoid'

export const stageBlueprints = [
  { id: 'detect', label: 'Detecting login type…' },
  { id: 'fingerprint', label: 'Fingerprinting technologies…' },
  { id: 'credential', label: 'Testing credential flow…' },
  { id: 'redirects', label: 'Evaluating redirects…' },
  { id: 'results', label: 'Preparing results…' },
]

export const buildTerminalLogs = (detail) => {
  if (!detail) return []
  const timeline = Array.isArray(detail.timeline) ? detail.timeline : []
  const logs = []

  logs.push(`[TARGET] ${detail.target_url}`)

  if (detail.detected_auth?.auth_type) {
    logs.push(`[DETECT] ${detail.detected_auth.auth_type}`)
  }

  if (detail.login_hint) {
    logs.push(`[HINT] ${detail.login_hint}`)
  }

  if (detail.status) {
    logs.push(`[STATUS] ${detail.status.toUpperCase()}`)
  }

  timeline.slice(-25).forEach((entry) => {
    if (!entry) return
    const ts = entry.occurred_at ? formatTimestamp(entry.occurred_at) : '—'
    logs.push(`[${ts}] ${entry.message || entry.description || 'Telemetry event'}`)
  })

  if (detail.error_message) {
    logs.push(`[ERROR] ${detail.error_message}`)
  }

  if (detail.final_url) {
    logs.push(`[FINAL] ${detail.final_url}`)
  }

  return logs
}

export const buildStageData = (detail, extras = {}) => {
  const { screenshots = [], artifacts = [] } = extras
  const baseStages = stageBlueprints.map((stage) => ({
    ...stage,
    meta: null,
    logs: [],
    details: [],
    id: stage.id,
  }))

  if (!detail) return baseStages

  const timeline = Array.isArray(detail.timeline) ? detail.timeline : []
  if (!timeline.length) {
    return baseStages.map((stage) => ({
      ...stage,
      meta: stageMetaFromDetail(stage.id, detail, [], extras),
      details: stageDetailsFromDetail(stage.id, detail, [], extras),
      logs: stageLogsFromExtras(stage.id, [], extras),
    }))
  }

  const chunkSize = Math.max(1, Math.ceil(timeline.length / stageBlueprints.length))
  return stageBlueprints.map((stage, index) => {
    const sliceStart = index * chunkSize
    const events = timeline.slice(sliceStart, sliceStart + chunkSize)
    return {
      ...stage,
      meta: stageMetaFromDetail(stage.id, detail, events, extras),
      logs: [
        ...stageLogsFromExtras(stage.id, events, extras),
        ...events.slice(0, 3).map(formatTimelineEvent),
      ].filter(Boolean),
      details: stageDetailsFromDetail(stage.id, detail, events, extras),
    }
  })
}

const stageMetaFromDetail = (stageId, detail, events = [], extras = {}) => {
  switch (stageId) {
    case 'detect':
      return detail?.detected_auth?.auth_type
        ? `Detected ${detail.detected_auth.auth_type}`
        : events.length ? 'Awaiting signal' : null
    case 'fingerprint': {
      const frameworks = detail?.tech_fingerprint?.js_frameworks
      return Array.isArray(frameworks) && frameworks.length
        ? `JS: ${frameworks.slice(0, 2).join(', ')}`
        : null
    }
    case 'credential':
      if (detail?.roles?.length) return `${detail.roles.length} role${detail.roles.length > 1 ? 's' : ''} loaded`
      if (detail?.username) return 'Inline credential'
      return null
    case 'redirects':
      return detail?.final_url ? `Final URL ${detail.final_url}` : null
    case 'results':
      return detail?.status ? `Status: ${detail.status}` : null
    default:
      return null
  }
}

const stageDetailsFromDetail = (stageId, detail, events = [], extras = {}) => {
  const lines = []
  const { screenshots = [] } = extras

  if (events.length) {
    const startTs = events[0]?.occurred_at
    const endTs = events[events.length - 1]?.occurred_at
    if (startTs) {
      lines.push(`Started ${formatTimestamp(startTs)}`)
    }
    if (startTs && endTs) {
      const duration = new Date(endTs) - new Date(startTs)
      if (!Number.isNaN(duration) && duration >= 0) {
        lines.push(`Duration ${formatDuration(duration)}`)
      }
    }
  }

  if (stageId === 'fingerprint') {
    const headers = detail?.tech_fingerprint?.security_headers
    if (Array.isArray(headers) && headers.length) {
      lines.push(`Headers: ${headers.slice(0, 2).join(', ')}`)
    }
  }

  if (stageId === 'detect' && detail?.detected_auth?.vendor) {
    lines.push(`Provider: ${detail.detected_auth.vendor}`)
  }

  if (stageId === 'credential') {
    if (detail?.roles?.length) {
      lines.push(`Roles configured: ${detail.roles.length}`)
    } else if (detail?.username) {
      lines.push(`Testing ${detail.username}`)
    }
  }

  if (stageId === 'results') {
    if (detail?.detected_auth?.input_fields?.length) {
      lines.push(`Inputs: ${detail.detected_auth.input_fields.length} captured`)
    }
    if (detail?.final_url) {
      lines.push(`Completed at ${detail.final_url}`)
    }
    if (screenshots.length) {
      const sample = screenshots.slice(0, 2).map((shot) => shot.filename || shot.name || 'screenshot')
      const suffix = screenshots.length > sample.length ? ` +${screenshots.length - sample.length} more` : ''
      lines.push(`Screenshots: ${sample.join(', ')}${suffix}`)
    }
  }

  if (stageId === 'redirects' && Array.isArray(detail?.redirect_chain) && detail.redirect_chain.length) {
    lines.push(`${detail.redirect_chain.length} redirect hop${detail.redirect_chain.length > 1 ? 's' : ''}`)
  }

  if (!lines.length && events.length) {
    lines.push(`${events.length} telemetry events recorded`)
  }

  return lines
}

const stageLogsFromExtras = (stageId, events = [], extras = {}) => {
  const lines = []
  const { screenshots = [] } = extras
  if (stageId === 'results' && screenshots.length) {
    lines.push(`${screenshots.length} screenshot${screenshots.length > 1 ? 's' : ''} captured`)
  }
  return lines
}

const formatTimelineEvent = (entry) => {
  if (!entry) return ''
  const ts = entry.occurred_at ? formatTimestamp(entry.occurred_at) : '—'
  const label = entry.message || entry.description || entry.type || 'Event recorded'
  return `${ts} • ${label}`
}

const formatTimestamp = (value) => {
  try {
    return new Date(value).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
  } catch (error) {
    return '—'
  }
}

const formatDuration = (ms) => {
  if (ms < 1000) return `${ms}ms`
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`
  return `${(ms / 60000).toFixed(1)}m`
}

export const createTelemetryStage = (overrides = {}) => ({
  id: overrides.id || nanoid(),
  label: overrides.label || 'Custom stage',
  ...overrides,
})
