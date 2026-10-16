import React, { useEffect, useState } from 'react'
import { CheckCircle2, Copy, Download, Loader2, PlayCircle, ShieldCheck, XCircle } from 'lucide-react'
import Card from '../../../components/Card'
import Button from '../../../components/Button'
import authreconApi from '../../../services/authreconApi'
import ScanReadiness from './ScanReadiness'
import { copyText } from '../../../utils/copyText'

function Field({ label, value, hint, mono = true }) {
  const [copied, setCopied] = useState(false)
  if (!value) return null
  return (
    <div className="space-y-1">
      <p className="text-xs uppercase tracking-wide text-slate-500">{label}</p>
      <div className="flex items-center gap-2">
        <code className={`flex-1 min-w-0 px-3 py-2 rounded-lg bg-(--bg-1) border border-(--stroke-dark) text-sm text-slate-200 break-all ${mono ? 'font-mono' : ''}`}>
          {value}
        </code>
        <button
          type="button"
          onClick={async () => { if (await copyText(value)) { setCopied(true); setTimeout(() => setCopied(false), 1500) } }}
          className="shrink-0 p-2 rounded-lg border border-(--stroke-dark) text-slate-400 hover:text-(--accent-blue) hover:border-(--stroke-blue)"
          title={`Copy ${label.toLowerCase()}`}
        >
          {copied ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
        </button>
      </div>
      {hint && <p className="text-xs text-slate-500">{hint}</p>}
    </div>
  )
}

function VerificationStatus({ verification }) {
  if (!verification) {
    return <span className="text-xs text-slate-500">Not verified yet</span>
  }
  const { status } = verification
  if (status === 'queued' || status === 'running') {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs text-(--accent-blue)">
        <Loader2 className="w-3.5 h-3.5 animate-spin" /> {status === 'queued' ? 'Queued…' : 'Replaying in a clean browser…'}
      </span>
    )
  }
  if (status === 'passed') {
    return (
      <span className="inline-flex items-center gap-1.5 text-xs text-emerald-400">
        <ShieldCheck className="w-3.5 h-3.5" /> Replay verified — reached {verification.landed_url || 'the verification page'}
      </span>
    )
  }
  return (
    <span className="inline-flex items-start gap-1.5 text-xs text-rose-300">
      <XCircle className="w-3.5 h-3.5 mt-0.5 shrink-0" />
      <span>
        {verification.failed_step
          ? `Replay broke at step ${verification.failed_step} (${verification.step}): ${verification.message}`
          : verification.message || 'Replay failed'}
      </span>
    </span>
  )
}

function WasSetupCard({ runId, setup, onChanged }) {
  const [busy, setBusy] = useState({})
  const [error, setError] = useState(null)
  const pending = (setup?.scripts || []).some(s => ['queued', 'running'].includes(s.verification?.status))

  // Poll while a replay is in flight; the run itself is already finished.
  useEffect(() => {
    if (!pending) return undefined
    const timer = setInterval(() => onChanged?.(), 3000)
    return () => clearInterval(timer)
  }, [pending, onChanged])

  if (!setup) return null

  const download = async (script) => {
    setBusy(b => ({ ...b, [`d-${script.artifact_id}`]: true }))
    try {
      const response = await authreconApi.get(`runs/${runId}/artifacts/${script.artifact_id}/download`, { responseType: 'blob' })
      const url = window.URL.createObjectURL(new Blob([response.data]))
      const link = document.createElement('a')
      link.href = url
      link.download = script.name
      link.click()
      window.URL.revokeObjectURL(url)
    } catch {
      setError('Download failed.')
    } finally {
      setBusy(b => ({ ...b, [`d-${script.artifact_id}`]: false }))
    }
  }

  const verify = async (script) => {
    setError(null)
    setBusy(b => ({ ...b, [`v-${script.artifact_id}`]: true }))
    try {
      await authreconApi.post(`runs/${runId}/artifacts/${script.artifact_id}/verify`)
      onChanged?.()
    } catch (err) {
      setError(err.response?.data?.detail || 'Could not start the replay check.')
    } finally {
      setBusy(b => ({ ...b, [`v-${script.artifact_id}`]: false }))
    }
  }

  return (
    <Card padding="lg" className="border-(--stroke-blue)">
      <div className="flex flex-wrap items-start justify-between gap-3 mb-5">
        <div>
          <p className="text-xs uppercase tracking-widest text-(--accent-blue)">Scan configuration</p>
          <h3 className="text-lg font-semibold text-slate-50">Tenable WAS setup</h3>
          <p className="text-sm text-slate-400">Authentication: {setup.method_label}</p>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <Field label="Login page" value={setup.login_url} />
        <Field label="Page to verify" value={setup.page_to_verify}
          hint="The page the login lands on; the scanner checks it to confirm it is still logged in." />
        <Field label="Pattern to verify (regex)" value={setup.pattern_regex}
          hint={setup.pattern_to_verify ? `Matches the text "${setup.pattern_to_verify}" on that page.` : undefined} />
        {setup.pattern_missing && (
          <div className="space-y-1">
            <p className="text-xs uppercase tracking-wide text-slate-500">Pattern to verify (regex)</p>
            <p className="px-3 py-2 rounded-lg border border-amber-500/40 bg-amber-500/10 text-sm text-amber-200">
              Not found automatically. Enter text that only appears when logged in (see the note below).
            </p>
          </div>
        )}
      </div>

      {setup.scripts?.length > 0 && (
        <div className="mt-5 space-y-2">
          <p className="text-xs uppercase tracking-wide text-slate-500">Selenium script{setup.scripts.length > 1 ? 's' : ''}</p>
          {setup.scripts.map(script => (
            <div key={script.artifact_id} className="p-3 rounded-lg border border-(--stroke-dark) bg-(--bg-2) space-y-2">
              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="min-w-0">
                  <p className="text-sm font-medium text-slate-200 truncate">{script.name}</p>
                  {script.role_label && <p className="text-xs text-slate-500">Role: {script.role_label}</p>}
                </div>
                <div className="flex gap-2">
                  <Button size="sm" variant="primary" icon={Download} onClick={() => download(script)}
                    loading={busy[`d-${script.artifact_id}`]}>
                    Download .side
                  </Button>
                  <Button size="sm" variant="outline" icon={PlayCircle} onClick={() => verify(script)}
                    loading={busy[`v-${script.artifact_id}`]}
                    disabled={['queued', 'running'].includes(script.verification?.status)}
                    title="Replays the script in a clean browser, like the scanner will. This logs in to the target once more.">
                    Verify
                  </Button>
                </div>
              </div>
              <VerificationStatus verification={script.verification} />
            </div>
          ))}
          <p className="text-xs text-slate-500">
            Verify replays the script in a clean browser the way the scanner will, and counts as one more login on the account.
          </p>
        </div>
      )}

      {setup.notes?.length > 0 && (
        <ul className="mt-4 space-y-1 text-sm text-slate-400 list-disc pl-5">
          {setup.notes.map(note => <li key={note}>{note}</li>)}
        </ul>
      )}
      <ScanReadiness readiness={setup.readiness} />
      {error && <p className="mt-3 text-sm text-rose-400">{error}</p>}
    </Card>
  )
}

export default WasSetupCard
