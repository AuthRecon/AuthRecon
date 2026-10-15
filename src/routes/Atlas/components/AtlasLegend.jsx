import React from 'react'

/**
 * Atlas Legend Component
 *
 * Dynamic legend based on story configuration.
 * Supports circles, lines, gradients, and size indicators.
 */
function AtlasLegend({ story, className = '' }) {
  if (!story?.legend || story.legend.length === 0) {
    return null
  }

  return (
    <div
      className={`bg-slate-900/90 backdrop-blur-xs border border-slate-800/50 rounded-lg p-3 space-y-2 ${className}`}
    >
      <div className="text-xs font-semibold text-slate-400 mb-2">Legend</div>

      {story.legend.map((item, index) => (
        <LegendItem key={index} item={item} />
      ))}
    </div>
  )
}

/**
 * Individual legend item renderer
 */
function LegendItem({ item }) {
  if (item.type === 'divider') {
    return <div className="border-t border-slate-700/50 my-2" />
  }

  if (item.type === 'circle') {
    return (
      <div className="flex items-center gap-2">
        <div
          className="w-3 h-3 rounded-full shadow-xs"
          style={{ backgroundColor: item.color }}
        />
        <div className="flex-1">
          <span className="text-xs text-slate-300">{item.label}</span>
          {item.description && (
            <span className="text-xs text-slate-500 ml-1">({item.description})</span>
          )}
        </div>
      </div>
    )
  }

  if (item.type === 'line') {
    return (
      <div className="flex items-center gap-2">
        <div
          className="w-4 h-0.5 rounded-full"
          style={{ backgroundColor: item.color }}
        />
        <div className="flex-1">
          <span className="text-xs text-slate-300">{item.label}</span>
          {item.description && (
            <span className="text-xs text-slate-500 ml-1">({item.description})</span>
          )}
        </div>
      </div>
    )
  }

  if (item.type === 'gradient') {
    const gradientStyle = {
      background: `linear-gradient(to right, ${item.colors.join(', ')})`,
    }

    return (
      <div className="space-y-1">
        <div className="text-xs text-slate-300">{item.label}</div>
        <div className="h-2 rounded-full overflow-hidden" style={gradientStyle} />
        {item.labels && (
          <div className="flex justify-between">
            {item.labels.map((label, i) => (
              <span key={i} className="text-[10px] text-slate-500">
                {label}
              </span>
            ))}
          </div>
        )}
      </div>
    )
  }

  if (item.type === 'size') {
    return (
      <div className="flex items-center gap-2">
        <div className="flex items-end gap-1">
          <div className="w-2 h-2 rounded-full bg-slate-500" />
          <div className="w-3 h-3 rounded-full bg-slate-500" />
          <div className="w-4 h-4 rounded-full bg-slate-500" />
        </div>
        <div className="flex-1">
          <span className="text-xs text-slate-300">{item.label}</span>
          {item.description && (
            <span className="text-xs text-slate-500 ml-1">= {item.description}</span>
          )}
        </div>
      </div>
    )
  }

  if (item.type === 'ring-3') {
    return (
      <div className="flex items-center gap-2">
        <div className="relative w-4 h-4">
          <div className="absolute inset-0 rounded-full border-2 border-slate-600" />
          <div
            className="absolute inset-0 rounded-full border-2 border-cyan-500"
            style={{
              clipPath: 'polygon(50% 0%, 100% 0%, 100% 50%, 50% 50%)',
            }}
          />
        </div>
        <div className="flex-1">
          <span className="text-xs text-slate-300">{item.label}</span>
          {item.description && (
            <span className="text-xs text-slate-500 ml-1">= {item.description}</span>
          )}
        </div>
      </div>
    )
  }

  // Fallback for unknown types
  return (
    <div className="text-xs text-slate-400">{item.label}</div>
  )
}

export default AtlasLegend
