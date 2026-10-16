import { useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { ShieldCheck } from 'lucide-react'
import PanelShell from './PanelShell'
import Badge from '../../../components/Badge'
import Button from '../../../components/Button'
import api from '../../../services/api'
import useAuthStore from '../../../store/authStore'
import { copyText } from '../../../utils/copyText'

const MFA_KEY = ['portal', 'mfa']

function CodeInput({ value, onChange, placeholder = '6-digit code' }) {
  return (
    <input
      type="text"
      inputMode="numeric"
      autoComplete="one-time-code"
      className="px-3 py-2 rounded-lg bg-(--bg-1) border border-(--stroke-dark) text-sm text-slate-100 w-48 font-mono"
      placeholder={placeholder}
      value={value}
      onChange={(e) => onChange(e.target.value)}
    />
  )
}

function BackupCodes({ codes, onDone }) {
  const [copied, setCopied] = useState(false)
  return (
    <div className="space-y-3">
      <p className="text-sm text-amber-200">
        Save these backup codes somewhere safe, such as your password manager. Each works once if you lose your phone.
        They are not shown again.
      </p>
      <pre className="px-3 py-2 rounded-lg bg-(--bg-1) border border-(--stroke-dark) text-sm text-slate-100 font-mono grid grid-cols-2 gap-x-6">
        {codes.map(c => <span key={c}>{c}</span>)}
      </pre>
      <div className="flex gap-2">
        <Button variant="outline" size="sm" onClick={async () => { if (await copyText(codes.join('\n'))) setCopied(true) }}>
          {copied ? 'Copied' : 'Copy codes'}
        </Button>
        <Button size="sm" onClick={onDone}>I have saved them</Button>
      </div>
    </div>
  )
}

/**
 * Two-factor authentication (TOTP) for the signed-in user. Backend: portal mfa.py.
 */
export function MfaPanel() {
  const queryClient = useQueryClient()
  const user = useAuthStore((s) => s.user)
  const setSession = useAuthStore((s) => s.setSession)
  const { data: status, refetch } = useQuery({ queryKey: MFA_KEY, queryFn: async () => (await api.get('/api/auth/mfa')).data })
  const [setup, setSetup] = useState(null)
  const [code, setCode] = useState('')
  const [password, setPassword] = useState('')
  const [backupCodes, setBackupCodes] = useState(null)
  const [mode, setMode] = useState(null) // 'disable' | 'codes'
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)

  const run = async (fn) => {
    setBusy(true); setError('')
    try { await fn() } catch (err) { setError(err.response?.data?.detail || 'Something went wrong') } finally { setBusy(false) }
  }

  const start = () => run(async () => { setSetup((await api.post('/api/auth/mfa/setup')).data); setCode('') })
  const enable = () => run(async () => {
    const { data } = await api.post('/api/auth/mfa/enable', { code })
    // The portal replaced the session cookie with a full session (an
    // enrolment-only one becomes a normal one).
    localStorage.removeItem('mfa_enroll')
    setSession(user)
    setSetup(null); setCode(''); setBackupCodes(data.backup_codes)
    refetch()
  })
  const disable = () => run(async () => {
    await api.post('/api/auth/mfa/disable', { password, code })
    setMode(null); setPassword(''); setCode(''); refetch()
  })
  const newCodes = () => run(async () => {
    const { data } = await api.post('/api/auth/mfa/backup-codes', { code })
    setMode(null); setCode(''); setBackupCodes(data.backup_codes); refetch()
  })
  const setPolicy = (on) => run(async () => {
    await api.put('/api/auth/mfa/policy', { require_for_admins: on })
    queryClient.invalidateQueries({ queryKey: MFA_KEY })
  })

  const enrolRequired = (() => { try { return localStorage.getItem('mfa_enroll') === '1' } catch { return false } })()

  return (
    <PanelShell
      eyebrow="Security"
      title="Two-factor authentication"
      description="Ask for a code from an authenticator app (Microsoft or Google Authenticator, 1Password, ...) after your password."
      actions={status?.enabled
        ? <Badge variant="success">On</Badge>
        : !setup && !backupCodes && <Button icon={ShieldCheck} onClick={start} loading={busy}>Set up</Button>}
    >
      <div className="space-y-4 text-sm">
        {enrolRequired && !status?.enabled && (
          <p className="px-3 py-2 rounded-lg border border-amber-500/40 bg-amber-500/10 text-amber-200">
            Two-factor authentication is required for administrators. Set it up to continue.
          </p>
        )}

        {setup && (
          <div className="flex flex-wrap gap-6 items-start">
            <img alt="QR code for your authenticator app" className="rounded-lg w-44 h-44 bg-white"
              src={setup.qr_data_uri} />
            <div className="space-y-3 min-w-0">
              <p className="text-slate-300">1. Scan the code with your authenticator app, or enter this key:</p>
              <p className="font-mono text-slate-100 break-all">{setup.secret}</p>
              <p className="text-slate-300">2. Enter the 6-digit code it shows:</p>
              <div className="flex gap-2 items-center">
                <CodeInput value={code} onChange={setCode} />
                <Button onClick={enable} loading={busy} disabled={code.trim().length < 6}>Turn on</Button>
              </div>
            </div>
          </div>
        )}

        {backupCodes && <BackupCodes codes={backupCodes} onDone={() => setBackupCodes(null)} />}

        {status?.enabled && !backupCodes && (
          <div className="space-y-3">
            <p className="text-slate-400">
              {status.backup_codes_left} backup code{status.backup_codes_left === 1 ? '' : 's'} left.
              {status.backup_codes_left <= 3 && ' Make new ones soon.'}
            </p>
            {mode === null && (
              <div className="flex gap-2">
                <Button variant="outline" size="sm" onClick={() => setMode('codes')}>New backup codes</Button>
                {!status.required && <Button variant="outline" size="sm" onClick={() => setMode('disable')}>Turn off</Button>}
              </div>
            )}
            {mode === 'codes' && (
              <div className="flex gap-2 items-center">
                <CodeInput value={code} onChange={setCode} />
                <Button size="sm" onClick={newCodes} loading={busy}>Make new codes</Button>
                <Button size="sm" variant="ghost" onClick={() => { setMode(null); setCode('') }}>Cancel</Button>
              </div>
            )}
            {mode === 'disable' && (
              <div className="flex flex-wrap gap-2 items-center">
                <input type="password" autoComplete="current-password" placeholder="Your password"
                  className="px-3 py-2 rounded-lg bg-(--bg-1) border border-(--stroke-dark) text-sm text-slate-100"
                  value={password} onChange={(e) => setPassword(e.target.value)} />
                <CodeInput value={code} onChange={setCode} placeholder="Code or backup code" />
                <Button size="sm" variant="danger" onClick={disable} loading={busy}>Turn off</Button>
                <Button size="sm" variant="ghost" onClick={() => { setMode(null); setCode(''); setPassword('') }}>Cancel</Button>
              </div>
            )}
          </div>
        )}

        {user?.is_admin && status && (
          <label className="flex items-center gap-3 pt-3 border-t border-(--stroke-dark)">
            <input type="checkbox" className="w-4 h-4" style={{ accentColor: 'var(--accent-blue)' }}
              checked={!!status.required_for_admins} disabled={busy}
              onChange={(e) => setPolicy(e.target.checked)} />
            <span className="text-slate-300">
              Require two-factor for all administrators
              <span className="block text-xs text-slate-500">
                Admins without it must set it up at their next sign-in. Turn it on for yourself first.
              </span>
            </span>
          </label>
        )}

        {error && <p className="text-rose-300">{error}</p>}
      </div>
    </PanelShell>
  )
}

export default MfaPanel
