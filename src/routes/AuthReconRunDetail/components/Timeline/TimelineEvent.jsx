import React from 'react'
import { AlertTriangle, CheckCircle2, Info, XCircle } from 'lucide-react'

const LEVELS = {
  error: { icon: XCircle, tone: 'bg-rose-500/10 text-rose-400', border: 'border-rose-900/50' },
  warning: { icon: AlertTriangle, tone: 'bg-amber-500/10 text-amber-400', border: 'border-amber-900/50' },
  success: { icon: CheckCircle2, tone: 'bg-emerald-500/10 text-emerald-400', border: 'border-[var(--stroke-dark)]' },
  info: { icon: Info, tone: 'bg-slate-500/10 text-slate-400', border: 'border-[var(--stroke-dark)]' },
}

const formatTime = (timestamp) => {
  if (!timestamp) return ''
  const date = new Date(timestamp)
  return Number.isNaN(date.getTime()) ? '' : date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

function TimelineEvent({ event, compact = false }) {
  const { icon: Icon, tone, border } = LEVELS[event.level] || LEVELS.info
  return (
    <div className={`p-3 rounded-lg border ${border} bg-[var(--bg-2)] ${event.detail ? 'opacity-70' : ''}`}>
      <div className="flex items-start gap-3">
        <div className={`flex-shrink-0 w-7 h-7 rounded-lg flex items-center justify-center ${tone}`}>
          <Icon className="w-4 h-4" />
        </div>
        <div className="flex-1 min-w-0">
          <p className={`${compact ? 'text-xs' : 'text-sm'} text-slate-300 break-words`}>{event.message || 'No message'}</p>
          <div className="flex flex-wrap items-center gap-2 mt-1 text-xs text-slate-500">
            {event.timestamp && <span className="font-mono">{formatTime(event.timestamp)}</span>}
            {event.role && (
              <span className="px-1.5 py-0.5 rounded border border-[var(--stroke-dark)] text-slate-400">{event.role}</span>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

export default TimelineEvent
