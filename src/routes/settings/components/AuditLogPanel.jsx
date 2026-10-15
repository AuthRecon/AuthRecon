import React, { useState } from 'react'
import { RefreshCw, Filter } from 'lucide-react'
import PanelShell from './PanelShell'
import { useAuditLog } from '../../../services/useAuditLog'

const EVENT_LABELS = {
  login_success: { label: 'Login', color: 'text-emerald-400' },
  login_failure: { label: 'Login Failed', color: 'text-red-400' },
  logout: { label: 'Logout', color: 'text-slate-400' },
  user_created: { label: 'User Created', color: 'text-sky-400' },
  user_deleted: { label: 'User Deleted', color: 'text-orange-400' },
  user_updated: { label: 'User Updated', color: 'text-yellow-400' },
  password_changed: { label: 'Password Changed', color: 'text-yellow-400' },
  password_reset: { label: 'Password Reset', color: 'text-orange-400' },
  setup_completed: { label: 'Setup', color: 'text-purple-400' },
  credential_revealed: { label: 'Credential Revealed', color: 'text-red-400' },
  role_changed: { label: 'Role Changed', color: 'text-orange-400' },
  user_deactivated: { label: 'User Deactivated', color: 'text-orange-400' },
  user_activated: { label: 'User Activated', color: 'text-sky-400' },
  license_generated: { label: 'License Generated', color: 'text-sky-400' },
  license_revoked: { label: 'License Revoked', color: 'text-orange-400' },
  loginlab_enabled: { label: 'LoginLab Enabled', color: 'text-amber-400' },
  loginlab_disabled: { label: 'LoginLab Disabled', color: 'text-slate-400' },
  security_notice_acknowledged: { label: 'Security Notice Acknowledged', color: 'text-slate-400' },
}

const ALL_EVENTS = Object.keys(EVENT_LABELS)

function formatDate(iso) {
  if (!iso) return '—'
  return new Date(iso).toLocaleString('en-CA', {
    year: 'numeric', month: 'short', day: 'numeric',
    hour: '2-digit', minute: '2-digit', second: '2-digit',
  })
}

function AuditLogPanel() {
  const [eventFilter, setEventFilter] = useState('')
  const { data, isLoading, error, refetch, isFetching } = useAuditLog({
    limit: 200,
    eventType: eventFilter || undefined,
  })

  const entries = data?.entries ?? []
  const total = data?.total ?? 0

  return (
    <PanelShell
      eyebrow="Security"
      title="Audit log"
      description="Logins, user and role changes, password resets, licenses, LoginLab and security-notice events."
      actions={
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <Filter className="w-4 h-4 text-slate-500" />
            <select
              value={eventFilter}
              onChange={e => setEventFilter(e.target.value)}
              className="bg-slate-800 border border-slate-700 text-slate-300 text-sm rounded-lg px-3 py-1.5 focus:outline-hidden focus:border-sky-500"
            >
              <option value="">All events</option>
              {ALL_EVENTS.map(e => (
                <option key={e} value={e}>{EVENT_LABELS[e]?.label ?? e}</option>
              ))}
            </select>
          </div>
          <button
            onClick={() => refetch()}
            disabled={isFetching}
            className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-slate-400 hover:text-slate-200 border border-slate-700 rounded-lg transition-colors disabled:opacity-50"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isFetching ? 'animate-spin' : ''}`} />
            Refresh
          </button>
        </div>
      }
    >

      {isLoading && (
        <div className="text-slate-400 text-sm py-8 text-center">Loading audit log…</div>
      )}
      {error && (
        <div className="text-red-400 text-sm py-8 text-center">
          Failed to load audit log: {error.message}
        </div>
      )}

      {!isLoading && !error && (
        <>
          <p className="text-xs text-slate-500 mb-3">
            Showing {entries.length} of {total} events
            {eventFilter ? ` filtered by "${EVENT_LABELS[eventFilter]?.label ?? eventFilter}"` : ''}
          </p>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-left text-xs text-slate-500 border-b border-slate-800">
                  <th className="pb-2 pr-4 font-medium">Time</th>
                  <th className="pb-2 pr-4 font-medium">Event</th>
                  <th className="pb-2 pr-4 font-medium">Actor</th>
                  <th className="pb-2 pr-4 font-medium">IP</th>
                  <th className="pb-2 font-medium">Target / detail</th>
                </tr>
              </thead>
              <tbody>
                {entries.length === 0 && (
                  <tr>
                    <td colSpan={5} className="py-8 text-center text-slate-500">
                      No events recorded yet
                    </td>
                  </tr>
                )}
                {entries.map(entry => {
                  const meta = EVENT_LABELS[entry.event_type] ?? { label: entry.event_type, color: 'text-slate-400' }
                  return (
                    <tr key={entry.id} className="border-b border-slate-800/50 hover:bg-slate-800/20 transition-colors">
                      <td className="py-2.5 pr-4 text-slate-500 whitespace-nowrap text-xs font-mono">
                        {formatDate(entry.created_at)}
                      </td>
                      <td className="py-2.5 pr-4 min-w-40">
                        <span className={`font-medium ${meta.color}`}>{meta.label}</span>
                      </td>
                      <td className="py-2.5 pr-4 text-slate-300 max-w-[180px] truncate">
                        {entry.actor_username ?? <span className="text-slate-600">—</span>}
                      </td>
                      <td className="py-2.5 pr-4 text-slate-500 font-mono text-xs">
                        {entry.actor_ip ?? '—'}
                      </td>
                      <td className="py-2.5 text-slate-400 max-w-[220px] truncate" title={entry.detail || ''}>
                        {entry.target_username ?? entry.detail ?? <span className="text-slate-600">—</span>}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </>
      )}
    </PanelShell>
  )
}

export default AuditLogPanel
