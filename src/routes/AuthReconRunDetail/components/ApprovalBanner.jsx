import { useState } from 'react'
import { ShieldAlert } from 'lucide-react'
import Button from '../../../components/Button'
import authreconApi from '../../../services/authreconApi'

// A run an AI client (MCP) started, held until a person approves it
// (admin setting in Settings › AI & MCP; backend api/runs.py approve/reject).
function ApprovalBanner({ run, onChanged }) {
  const [busy, setBusy] = useState(null)
  const [error, setError] = useState('')
  if (!run?.awaiting_approval) return null

  const decide = async (action) => {
    if (action === 'reject' && !window.confirm('Reject this run? It will not log in to the target.')) return
    setBusy(action); setError('')
    try {
      await authreconApi.post(`runs/${run.id}/${action}`)
      onChanged?.()
    } catch (err) {
      setError(err.response?.data?.detail || `Could not ${action} the run`)
    } finally {
      setBusy(null)
    }
  }

  return (
    <div className="p-4 rounded-lg border border-amber-500/40 bg-amber-500/10 space-y-3">
      <div className="flex gap-3">
        <ShieldAlert className="w-5 h-5 text-amber-300 shrink-0" />
        <div className="text-sm">
          <p className="font-semibold text-amber-100">Waiting for your approval</p>
          <p className="text-amber-200/80">
            An AI client started this run. It will log in to <span className="font-mono">{run.target_url}</span> with
            the selected account only after you approve it. Check the target and account are what you expect.
          </p>
        </div>
      </div>
      <div className="flex gap-2">
        <Button size="sm" onClick={() => decide('approve')} loading={busy === 'approve'} disabled={!!busy}>Approve</Button>
        <Button size="sm" variant="outline" onClick={() => decide('reject')} loading={busy === 'reject'} disabled={!!busy}>Reject</Button>
      </div>
      {error && <p className="text-sm text-rose-300">{error}</p>}
    </div>
  )
}

export default ApprovalBanner
