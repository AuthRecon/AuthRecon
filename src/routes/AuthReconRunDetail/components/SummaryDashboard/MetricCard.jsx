import React from 'react'
import Card from '../../../../components/Card'

function MetricCard({ label, value, icon, sublabel, allowWrap = false }) {
  return (
    <Card padding="md" className="flex items-start gap-3">
      {icon && (
        <div className="shrink-0 w-10 h-10 rounded-xl bg-white/5 border border-(--stroke-dark) flex items-center justify-center">
          <div className="text-white/60" style={{ width: 22, height: 22 }}>
            {icon}
          </div>
        </div>
      )}
      <div className="flex-1 min-w-0">
        <p className="text-xs text-slate-500 mb-1">{label}</p>
        {allowWrap ? (
          <div className="max-h-20 overflow-y-auto">
            <p
              className="text-sm font-semibold text-slate-50 break-all leading-snug"
              title={value}
            >
              {value || '—'}
            </p>
          </div>
        ) : (
          <p
            className="text-lg font-semibold text-slate-50 truncate"
            title={value}
          >
            {value || '—'}
          </p>
        )}
        {sublabel && (
          <p className="text-xs text-slate-400 mt-1">{sublabel}</p>
        )}
      </div>
    </Card>
  )
}

export default MetricCard
