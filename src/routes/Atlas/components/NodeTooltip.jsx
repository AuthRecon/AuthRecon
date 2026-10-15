import React from 'react'
import { SEVERITY_COLORS, AUTH_TYPE_COLORS } from '../../../services/atlas/types'

/**
 * Node Tooltip Component
 *
 * Hover tooltip showing quick information about a node.
 * Positioned relative to the node being hovered.
 */
function NodeTooltip({ node, position, visible }) {
  if (!visible || !node || !position) {
    return null
  }

  const severity = node.severity || 'info'
  const severityColor = SEVERITY_COLORS[severity]
  const categoryColor = AUTH_TYPE_COLORS[node.category] || AUTH_TYPE_COLORS.unknown

  return (
    <div
      className="fixed z-50 pointer-events-none"
      style={{
        left: position.x + 15,
        top: position.y - 10,
        transform: 'translateY(-100%)',
      }}
    >
      <div className="bg-slate-900/95 backdrop-blur-xs border border-slate-700/50 rounded-lg shadow-xl p-3 min-w-[200px] max-w-[280px]">
        {/* Header */}
        <div className="flex items-start gap-2 mb-2">
          <div
            className="w-3 h-3 rounded-full mt-1 shrink-0"
            style={{ backgroundColor: node.color || severityColor }}
          />
          <div className="flex-1 min-w-0">
            <div className="text-sm font-semibold text-slate-200 truncate">
              {node.label}
            </div>
            {node.subtitle && (
              <div className="text-xs text-slate-500 truncate">{node.subtitle}</div>
            )}
          </div>
        </div>

        {/* Quick stats */}
        <div className="space-y-1.5 border-t border-slate-800/50 pt-2">
          {/* Score */}
          {typeof node.score === 'number' && (
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-500">Score</span>
              <span
                className="font-semibold px-1.5 py-0.5 rounded-sm"
                style={{
                  backgroundColor: `${severityColor}20`,
                  color: severityColor,
                }}
              >
                {node.score}
              </span>
            </div>
          )}

          {/* Severity */}
          <div className="flex items-center justify-between text-xs">
            <span className="text-slate-500">Severity</span>
            <span
              className="font-medium capitalize"
              style={{ color: severityColor }}
            >
              {severity}
            </span>
          </div>

          {/* Category/Type */}
          {node.category && (
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-500">Type</span>
              <span
                className="font-medium uppercase"
                style={{ color: categoryColor }}
              >
                {node.category}
              </span>
            </div>
          )}

          {/* Additional metadata hints */}
          {node.metadata?.type === 'target' && node.metadata?.runCount && (
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-500">Scans</span>
              <span className="text-slate-300">{node.metadata.runCount}</span>
            </div>
          )}

          {node.metadata?.type === 'idp' && node.metadata?.targetCount && (
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-500">Targets</span>
              <span className="text-slate-300">{node.metadata.targetCount}</span>
            </div>
          )}

          {node.metadata?.type === 'asset' && node.metadata?.vulnerabilityCount > 0 && (
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-500">Vulnerabilities</span>
              <span className="text-slate-300">{node.metadata.vulnerabilityCount}</span>
            </div>
          )}
        </div>

        {/* Click hint */}
        <div className="mt-2 pt-2 border-t border-slate-800/50">
          <div className="text-[10px] text-slate-600 text-center">
            Click for details
          </div>
        </div>

        {/* Tooltip arrow */}
        <div
          className="absolute -bottom-1.5 left-4 w-3 h-3 bg-slate-900/95 border-r border-b border-slate-700/50 transform rotate-45"
        />
      </div>
    </div>
  )
}

export default NodeTooltip
