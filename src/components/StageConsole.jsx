import React from 'react'
import { ChevronDown } from 'lucide-react'

/**
 * StageConsole Component
 * Displays a progress tube with stage-by-stage details.
 */
function StageConsole({
  stages = [],
  activeIndex = -1,
  expandedStage = null,
  onToggleStage = () => {},
  replayLabel = '',
  showDetails = true,
  showHeader = true,
  liveLabel = '',
  headerActions = null,
  collapsed = false,
}) {
  const total = stages.length || 1
  const progress = Math.min(Math.max((activeIndex + 1) / total, 0), 1)

  return (
    <div className="telemetry-container">
      {showHeader && (
        <div className="flex items-center justify-between mb-4">
          <div className="text-sm font-semibold text-(--text-primary) tracking-wide">Stage Console</div>
          <div className="flex items-center gap-3">
            {liveLabel && (
              <div className="flex items-center gap-2 text-xs text-(--accent-blue)">
                <span className="w-2 h-2 rounded-full bg-(--accent-blue) animate-pulse" />
                {liveLabel}
              </div>
            )}
            {replayLabel && (
              <span className="text-xs text-(--text-secondary) font-mono">{replayLabel}</span>
            )}
            {headerActions}
          </div>
        </div>
      )}

      <div className={`timeline-track ${showHeader ? '' : 'mt-1'} mb-6`}>
        <div
          className="timeline-bar transition-all duration-500"
          style={{ width: `${progress * 100}%` }}
        />
      </div>

      {!collapsed && (
      <div className="space-y-4">
        {stages.map((stage, index) => {
          const status = index < activeIndex ? 'complete' : index === activeIndex ? 'active' : 'pending'
          const isExpanded = expandedStage === stage.id
          return (
            <div key={stage.id} className="rounded-2xl border border-(--stroke-dark) bg-(--bg-2) p-4 hover:border-(--stroke-blue) transition">
              <div className="flex items-center gap-3">
                <div
                  className={`w-3 h-3 rounded-full ${
                    status === 'complete'
                      ? 'bg-emerald-400'
                      : status === 'active'
                        ? 'bg-(--accent-blue) animate-pulse'
                        : 'bg-slate-600'
                  }`}
                />
                <div className="flex-1 min-w-0">
                  <p className={`text-sm font-medium ${status === 'pending' ? 'text-(--text-muted)' : 'text-(--text-primary)'}`}>
                    {stage.label}
                  </p>
                  {stage.meta && (
                    <p className="text-xs text-(--text-muted) mt-1">
                      {stage.meta}
                    </p>
                  )}
                </div>
                {showDetails && (
                  <button
                    type="button"
                    onClick={() => onToggleStage(isExpanded ? null : stage.id)}
                    className="text-xs text-(--accent-blue) flex items-center gap-1"
                  >
                    Details
                    <ChevronDown className={`w-4 h-4 transition-transform ${isExpanded ? 'rotate-180' : ''}`} />
                  </button>
                )}
              </div>

              {stage.logs?.length > 0 && (
                <div className="mt-3 text-xs font-mono text-(--text-secondary) space-y-1">
                  {stage.logs.slice(0, 2).map((log, idx) => (
                    <p key={`${stage.id}-log-${idx}`} className="truncate">
                      {log}
                    </p>
                  ))}
                  {stage.logs.length > 2 && (
                    <p className="text-slate-500 italic">+{stage.logs.length - 2} more events</p>
                  )}
                </div>
              )}

              {showDetails && isExpanded && (
                <div className="mt-4 rounded-xl bg-(--bg-1) border border-(--stroke-dark) p-3 space-y-2 text-xs text-(--text-secondary)">
                  {stage.details?.length
                    ? stage.details.map((detail, idx) => (
                        <div key={`${stage.id}-detail-${idx}`} className="flex items-start gap-2">
                          <span className="text-(--accent-blue) mt-0.5">•</span>
                          <span className="text-(--text-primary)">{detail}</span>
                        </div>
                      ))
                    : <span className="text-(--text-muted)">No additional data captured for this stage.</span>
                  }
                </div>
              )}
            </div>
          )
        })}
      </div>
      )}
    </div>
  )
}

export default StageConsole
