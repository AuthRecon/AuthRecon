import React, { useState, useEffect, useCallback } from 'react'
import Badge from './Badge'
import Button from './Button'
import config from '../config'
import api from '../services/api'

/**
 * VNCViewer — opens the authenticated noVNC viewer in a popup window.
 *
 * Auth flow:
 *   1. POST /api/authrecon/vnc-token/{runId} (JWT-authenticated) → Redis-backed
 *      ticket: cryptographically random, scoped to run_id + user_id, 120s TTL.
 *   2. Ticket embedded in the noVNC WebSocket path as ?t=TICKET.
 *   3. Portal WebSocket handler validates ticket from Redis, deletes it on first
 *      successful backend connection (one-time), then proxies to the worker.
 *
 * "Reopen" always fetches a fresh ticket so a re-opened popup always has a
 * valid credential regardless of how long the user waited.
 *
 * VNC ports are internal-only (not published in docker-compose).
 */
function VNCViewer({ runId, autoConnect = true, className = '', hint }) {
  const [vncToken, setVncToken] = useState(null)
  const [tokenError, setTokenError] = useState(null)
  const [loading, setLoading] = useState(false)

  const buildVncUrl = useCallback((token) => {
    const portalBase = config.api.portal
    const portalUrl = new URL(portalBase)
    const port = portalUrl.port || (portalUrl.protocol === 'https:' ? '443' : '80')
    const encrypt = portalUrl.protocol === 'https:' ? '1' : '0'
    const wsPath = `apps/authrecon/vnc/${runId}?t=${encodeURIComponent(token)}`

    // Chrome resolves 'localhost' to ::1 (IPv6) for WebSocket connections while
    // WSL2 Docker only forwards IPv4. Force 127.0.0.1 for local dev to ensure
    // the WebSocket upgrade reaches the portal. Production hostnames are unaffected.
    const wsHost = portalUrl.hostname === 'localhost' ? '127.0.0.1' : portalUrl.hostname

    return (
      `${portalBase}/apps/authrecon/novnc/vnc.html` +
      `?host=${wsHost}` +
      `&port=${port}` +
      `&path=${encodeURIComponent(wsPath)}` +
      `&autoconnect=${autoConnect ? '1' : '0'}` +
      `&encrypt=${encrypt}` +
      `&resize=scale`
    )
  }, [runId, autoConnect])

  const fetchTicketAndOpen = useCallback(async (signal) => {
    setLoading(true)
    setTokenError(null)
    try {
      const res = await api.post(`/api/authrecon/vnc-token/${runId}`, null, { signal })
      if (signal?.aborted) return
      const token = res.data.token
      setVncToken(token)
      const url = buildVncUrl(token)
      window.open(url, `vnc-${runId}`, 'width=1280,height=800,menubar=no,toolbar=no,location=no,status=no')
    } catch (err) {
      if (err?.name === 'CanceledError' || err?.name === 'AbortError') return
      setTokenError('Could not obtain VNC access token. Try refreshing.')
    } finally {
      if (!signal?.aborted) setLoading(false)
    }
  }, [runId, buildVncUrl])

  // Auto-fetch and open on first mount. Cleanup aborts any in-flight request so
  // React StrictMode's double-invoke doesn't issue two tickets and navigate the
  // popup away from the first one (which would abort the WebSocket mid-handshake).
  useEffect(() => {
    if (!runId) return
    const controller = new AbortController()
    fetchTicketAndOpen(controller.signal)
    return () => controller.abort()
  }, [runId]) // eslint-disable-line react-hooks/exhaustive-deps

  if (tokenError) {
    return (
      <div className={`vnc-viewer ${className}`}>
        <div className="flex flex-col items-center justify-center py-12 gap-3">
          <p className="text-sm text-rose-400">{tokenError}</p>
          <Button variant="secondary" onClick={() => fetchTicketAndOpen()} disabled={loading}>
            Retry
          </Button>
        </div>
      </div>
    )
  }

  return (
    <div className={`vnc-viewer ${className}`}>
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <h3 className="text-lg font-semibold">Live Browser Stream</h3>
          {vncToken && <Badge variant="info" dot={true}>Streaming</Badge>}
        </div>
      </div>

      <div
        className="border-2 border-slate-700 rounded-lg bg-slate-900/50 flex flex-col items-center justify-center"
        style={{ height: '200px' }}
      >
        {loading ? (
          <>
            <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-sky-500 mb-3" />
            <p className="text-sm text-slate-400">Opening VNC session…</p>
          </>
        ) : (
          <>
            <p className="text-sm text-slate-400 mb-4">
              VNC viewer opened in a separate window.
            </p>
            <Button variant="secondary" onClick={() => fetchTicketAndOpen()} disabled={loading}>
              Reopen VNC Viewer
            </Button>
          </>
        )}
      </div>

      <p className="mt-3 text-xs text-slate-500">
        {hint || 'The VNC viewer opens in a popup. Complete the login there, then return here and click End Recording. Each "Reopen" issues a fresh access ticket.'}
      </p>
    </div>
  )
}

export default VNCViewer
