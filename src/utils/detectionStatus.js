// How to present the submit-time detection probe's error on the run page.
//
// The probe (a quick HTTP request at submit time) can time out on slow sites
// even though the worker later detects the auth type and the run succeeds.
// Only show the red "Detection Failed" banner when the run itself failed;
// otherwise the probe error is a small amber note.

const UNKNOWN_AUTH_TYPES = new Set(['', 'unknown', 'generic'])

export function isTimeoutError(error) {
  return /timed? ?out|timeout/i.test(error || '')
}

export function hasKnownAuthType(authType) {
  return !UNKNOWN_AUTH_TYPES.has(String(authType || '').trim().toLowerCase())
}

/**
 * @returns {null | {severity: 'error' | 'warning', title: string, detail: string}}
 */
export function describeDetectionError(run) {
  const detection = (run && run.detected_auth) || {}
  const error = detection.error
  if (!error) return null

  if (run.status === 'failed') {
    return { severity: 'error', title: 'Detection Failed', detail: error }
  }

  const authType = run.auth_type || detection.auth_type
  const probe = isTimeoutError(error) ? 'Pre-run detection probe timed out' : 'Pre-run detection probe failed'

  if (run.status === 'succeeded' || hasKnownAuthType(authType)) {
    return { severity: 'warning', title: `${probe}; auth type was detected during the run`, detail: error }
  }

  // Queued/running/manual with nothing detected yet: the worker detects again.
  return { severity: 'warning', title: `${probe}; the run will detect the auth type itself`, detail: error }
}
