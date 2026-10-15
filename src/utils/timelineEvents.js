// Turn raw timeline entries ({occurred_at, message}) into display events with
// a level, the role they belong to, and whether they are low-level detail.
// The worker writes plain messages, so the level is inferred from wording.

const ROLE_PREFIX = /^\[([^\]]+)\]\s*/

const ERROR_RE = /\b(failed|failure|error|unreachable|rejected|could not|unable to|timed out|not supported|denied)\b/i
const WARNING_RE = /\b(warning|warnings|retry|retrying|fallback|low confidence|too low|skipp(ed|ing)|not retrying)\b/i
const SUCCESS_RE = /\b(succeeded|successful(ly)?|completed successfully|authenticated|passed|generated|captured|logged in)\b/i
// Bookkeeping lines that matter when debugging, not when reading the outcome.
const DETAIL_RE = /^(\s{2,}|Discovery:|Playbook confidence|Pre-login prompt handling|Found prompt button|Attempting to locate|\[DEBUG\])/i

export function classifyTimelineEntry(entry, index = 0) {
  const raw = entry?.message || entry?.description || ''
  const roleMatch = raw.match(ROLE_PREFIX)
  const role = roleMatch ? roleMatch[1] : null
  const message = roleMatch ? raw.slice(roleMatch[0].length) : raw

  let level = 'info'
  if (ERROR_RE.test(message)) level = 'error'
  if (WARNING_RE.test(message)) level = 'warning' // "not retrying (lockout)" reads as a caution, not a crash
  if (/with warnings/i.test(message)) level = 'warning'
  if (level === 'info' && SUCCESS_RE.test(message)) level = 'success'
  if (/^Run completed successfully/i.test(message)) level = 'success'
  if (/^The site rejected these credentials/i.test(message)) level = 'error'

  return {
    id: entry?.id ?? `${index}-${entry?.occurred_at || ''}`,
    timestamp: entry?.occurred_at || entry?.timestamp || null,
    message,
    role,
    level,
    detail: level === 'info' && DETAIL_RE.test(message),
  }
}

export function classifyTimeline(timeline = []) {
  return timeline.map((entry, index) => classifyTimelineEntry(entry, index))
}
