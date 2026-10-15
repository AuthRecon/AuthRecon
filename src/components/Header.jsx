import React from 'react'
import { Link } from 'react-router-dom'
import { Sparkles } from 'lucide-react'
import { useAiStatus } from '../services/useAiStatus'

/**
 * Header Component
 * Page title plus the AI connection indicator. AuthRecon's AI is an external
 * client connected over MCP (see Settings › AI & MCP), so that's what we show.
 */
function Header({ title, subtitle, actions }) {
  const { data, isLoading, isError } = useAiStatus()
  const enabled = Boolean(data?.mcp_enabled)
  const lastSeen = data?.last_client_activity ? new Date(data.last_client_activity) : null
  // "Connected" = one of your keys reached MCP in the last 15 minutes.
  const connected = enabled && lastSeen && Date.now() - lastSeen.getTime() < 15 * 60 * 1000

  const label = isLoading ? 'AI: checking…' : connected ? 'AI: connected' : enabled ? 'AI: ready' : 'AI: off'
  const tooltip = isError
    ? 'Could not check AI status.'
    : connected
      ? `An AI client connected at ${lastSeen.toLocaleString()}. Click for details.`
      : enabled
        ? 'MCP is enabled. Click to connect an AI client.'
        : 'MCP is disabled. Click for AI settings.'
  const classes = connected
    ? 'border-emerald-500/40 bg-emerald-500/10 text-emerald-100'
    : 'border-slate-700/70 bg-slate-900/60 text-slate-300'

  return (
    <header className="header-banner">
      <div className="flex items-center justify-between">
        <div>
          {title && (
            <h2 className="text-2xl font-bold text-white">{title}</h2>
          )}
          {subtitle && (
            <p className="text-sm text-muted mt-0.5">{subtitle}</p>
          )}
        </div>

        <div className="flex items-center gap-3">
          <Link
            to="/settings?tab=ai"
            className={`flex items-center gap-2 px-3 py-2 rounded-lg border text-xs font-semibold tracking-wide transition-colors ${classes}`}
            title={tooltip}
          >
            <Sparkles className="w-4 h-4" />
            <span>{label}</span>
          </Link>
          {actions}
        </div>
      </div>
    </header>
  )
}

export default Header
