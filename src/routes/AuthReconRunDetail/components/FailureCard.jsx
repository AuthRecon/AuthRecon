import React, { useState } from 'react'
import { AlertOctagon } from 'lucide-react'
import Card from '../../../components/Card'

// Plain-language "what went wrong / what to do next" for failed runs
// (built server-side in services/was_setup.py), with the raw error on demand.
function FailureCard({ failure, errorMessage }) {
  const [showRaw, setShowRaw] = useState(false)
  const raw = failure?.error || errorMessage
  if (!failure && !raw) return null
  return (
    <Card padding="lg" className="border-rose-900/50 bg-rose-950/20">
      <div className="flex items-start gap-3">
        <AlertOctagon className="w-5 h-5 text-rose-400 flex-shrink-0 mt-0.5" />
        <div className="flex-1 min-w-0 space-y-3">
          <h3 className="text-lg font-semibold text-rose-300">{failure?.title || 'The run failed.'}</h3>
          {failure?.next_steps?.length > 0 && (
            <div>
              <p className="text-xs uppercase tracking-wide text-slate-500 mb-1">What to do next</p>
              <ul className="space-y-1 text-sm text-slate-300 list-disc pl-5">
                {failure.next_steps.map(step => <li key={step}>{step}</li>)}
              </ul>
            </div>
          )}
          {raw && (
            <div>
              <button type="button" onClick={() => setShowRaw(v => !v)} className="text-xs text-slate-400 hover:text-slate-200 underline">
                {showRaw ? 'Hide' : 'Show'} error details
              </button>
              {showRaw && (
                <p className="mt-2 text-sm text-rose-300/90 font-mono whitespace-pre-wrap break-words">{raw}</p>
              )}
            </div>
          )}
        </div>
      </div>
    </Card>
  )
}

export default FailureCard
