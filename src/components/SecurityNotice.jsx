import React, { useCallback, useEffect, useState } from 'react'
import { ShieldAlert } from 'lucide-react'
import Modal from './Modal'
import Button from './Button'
import api from '../services/api'
import useAuthStore from '../store/authStore'

// Shown after login until acknowledged, then again every 7 days (and whenever
// the server's notice version changes; bump NOTICE_VERSION in
// backend/security-portal/security_notice.py if you change this text).
// Acknowledgements are stored per user on the server and audit-logged.
export const SHOW_SECURITY_NOTICE_EVENT = 'authrecon:show-security-notice'

function SecurityNotice() {
  const user = useAuthStore((state) => state.user)
  const [open, setOpen] = useState(false)
  const [required, setRequired] = useState(false)
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState(null)

  useEffect(() => {
    let cancelled = false
    api.get('/api/security-notice')
      .then(({ data }) => {
        if (!cancelled && data?.required) {
          setRequired(true)
          setOpen(true)
        }
      })
      .catch(() => {}) // never block the app on this check
    return () => { cancelled = true }
  }, [user?.id])

  useEffect(() => {
    const show = () => setOpen(true)
    window.addEventListener(SHOW_SECURITY_NOTICE_EVENT, show)
    return () => window.removeEventListener(SHOW_SECURITY_NOTICE_EVENT, show)
  }, [])

  const acknowledge = useCallback(async () => {
    setSaving(true)
    setError(null)
    try {
      await api.post('/api/security-notice/ack')
      setRequired(false)
      setOpen(false)
    } catch {
      setError('Could not save your acknowledgement. Please try again.')
    } finally {
      setSaving(false)
    }
  }, [])

  return (
    <Modal
      isOpen={open}
      onClose={() => { if (!required) setOpen(false) }}
      closeButton={!required}
      size="lg"
      title="Before you use AuthRecon"
      footer={
        <div className="flex items-center justify-between gap-3 w-full">
          <p className="text-xs text-(--text-muted)">
            {required ? 'We’ll show this again in 7 days.' : 'You can reopen this from the footer at any time.'}
          </p>
          {required ? (
            <Button variant="primary" onClick={acknowledge} loading={saving}>I understand</Button>
          ) : (
            <Button variant="outline" onClick={() => setOpen(false)}>Close</Button>
          )}
        </div>
      }
    >
      <div className="space-y-4 text-sm text-slate-300">
        <div className="flex items-start gap-3 p-3 rounded-lg border border-amber-900/50 bg-amber-950/20">
          <ShieldAlert className="w-5 h-5 text-amber-400 shrink-0 mt-0.5" />
          <p>
            AuthRecon signs in to applications with real credentials, and it stores credentials, session
            cookies and login scripts. Every effort has been made to protect them (encryption at rest,
            per-user keys, audit logging), but no application can guarantee security on its own.
          </p>
        </div>
        <ul className="space-y-2 list-disc pl-5">
          <li>Run it on a trusted, access-controlled network, never directly on the internet.</li>
          <li>Limit what it can reach to the applications you are authorised to test.</li>
          <li>Use dedicated test accounts with the least privilege needed, and rotate their passwords after an engagement.</li>
          <li>Treat downloaded <code>.side</code>, HAR and export files as sensitive: they can contain working credentials or sessions.</li>
          <li>Only connect AI clients you trust, with keys you can revoke (Settings &rsaquo; AI &amp; MCP).</li>
        </ul>
        {user?.is_admin && (
          <div className="p-3 rounded-lg border border-(--stroke-dark) bg-(--bg-2)">
            <p className="text-xs uppercase tracking-wide text-slate-500 mb-1">For administrators</p>
            <p>
              Restrict ports 9000 and 8001 with a firewall or reverse proxy, put HTTPS in front of the portal,
              keep LoginLab off when it is not in use, and keep <code>.env.secrets</code> backed up somewhere safe.
            </p>
          </div>
        )}
        {error && <p className="text-rose-400">{error}</p>}
      </div>
    </Modal>
  )
}

export default SecurityNotice
