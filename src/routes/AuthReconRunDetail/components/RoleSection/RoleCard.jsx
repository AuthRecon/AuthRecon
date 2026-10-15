import React, { useState } from 'react'
import Card from '../../../../components/Card'
import Badge from '../../../../components/Badge'
import Button from '../../../../components/Button'
import authreconApi from '../../../../services/authreconApi'

function RoleCard({ runId, role }) {
  const [expanded, setExpanded] = useState(false)
  const [downloading, setDownloading] = useState(false)

  const normalizedStatus = (role.status || '').toLowerCase()
  const statusVariant = normalizedStatus === 'succeeded' ? 'success'
    : normalizedStatus === 'failed' ? 'error'
    : normalizedStatus === 'running' ? 'info'
    : 'default'
  const statusLabel = role.status
    ? role.status.replace(/_/g, ' ')
    : 'pending'

  const artifactCount = role.artifact_count ?? role.artifactCount ?? role.artifacts?.length ?? 0
  const screenshotCount = role.screenshot_count ?? role.screenshotCount ?? role.screenshots?.length ?? 0

  const artifactTypes = role.artifact_types || role.artifactTypes || {}

  const artifactsSummary = Object.entries(artifactTypes)
    .map(([type, count]) => `${type.toUpperCase()} × ${count}`)
    .join(' • ') || 'Awaiting capture'

  const downloadRoleBundle = async () => {
    if (!role.slug) {
      alert('Role slug not available')
      return
    }

    try {
      setDownloading(true)

      const response = await authreconApi.get(
        `runs/${runId}/artifacts/roles/${role.slug}/download`,
        { responseType: 'blob' }
      )

      const url = window.URL.createObjectURL(new Blob([response.data]))
      const link = document.createElement('a')
      link.href = url
      link.setAttribute('download', `${runId}-${role.slug}-bundle.zip`)
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(url)
    } catch (error) {
      console.error('Download bundle failed:', error)
      alert(`Failed to download bundle: ${error.message}`)
    } finally {
      setDownloading(false)
    }
  }

  return (
    <Card padding="md" className="hover:border-[var(--stroke-blue)] transition-colors">
      {/* Header */}
      <div className="flex items-start justify-between mb-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <h4 className="text-base font-semibold text-slate-50">
              {role.label || role.username || 'Role'}
            </h4>
            <Badge variant={statusVariant}>
              {statusLabel}
            </Badge>
          </div>
          <p className="text-sm text-slate-400 truncate">
            {role.username || '—'}
          </p>
        </div>
      </div>

      {/* Metadata Grid */}
      <div className="grid grid-cols-3 gap-3 mb-3">
        <div>
          <p className="text-xs text-slate-500 mb-1">Final URL</p>
          <p className="text-sm text-slate-300 truncate" title={role.finalUrl || role.final_url}>
            {role.finalUrl || role.final_url || '—'}
          </p>
        </div>
        <div>
          <p className="text-xs text-slate-500 mb-1">Artifacts</p>
          <p className="text-sm text-slate-300">{artifactCount}</p>
        </div>
        <div>
          <p className="text-xs text-slate-500 mb-1">Screenshots</p>
          <p className="text-sm text-slate-300">{screenshotCount}</p>
        </div>
      </div>

      {/* Expand/Collapse Button */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full py-2 px-3 rounded-lg bg-[var(--bg-1)] border border-[var(--stroke-dark)] hover:border-[var(--stroke-blue)] text-sm text-[var(--text-secondary)] hover:text-white transition-colors flex items-center justify-center gap-2 mb-3"
      >
        {expanded ? 'Collapse' : 'Expand Details'}
        <svg
          className={`w-4 h-4 transition-transform ${expanded ? 'rotate-180' : ''}`}
          fill="none"
          viewBox="0 0 24 24"
          stroke="currentColor"
          strokeWidth={2}
        >
          <path strokeLinecap="round" strokeLinejoin="round" d="M19 9l-7 7-7-7" />
        </svg>
      </button>

      {/* Expanded Details */}
      {expanded && (
        <div className="space-y-3 pt-3 border-t border-slate-800">
          <div>
            <p className="text-xs text-slate-500 mb-1">Flow</p>
            <p className="text-sm text-slate-300">
              {role.authType || role.auth_type || '—'}
            </p>
          </div>

          {role.tags && role.tags.length > 0 && (
            <div>
              <p className="text-xs text-slate-500 mb-1">Tags</p>
              <div className="flex flex-wrap gap-2">
                {role.tags.map((tag, idx) => (
                  <Badge key={idx} variant="info" className="text-xs">
                    {tag}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          <div>
            <p className="text-xs text-slate-500 mb-1">Artifacts by type</p>
            <p className="text-sm text-slate-300">
              {artifactsSummary}
            </p>
          </div>

          {role.error && (
            <div>
              <p className="text-xs text-rose-400 mb-1">Role error</p>
              <p className="text-sm text-rose-300">
                {role.error}
              </p>
            </div>
          )}
        </div>
      )}

      {/* Download Bundle Button */}
      {role.slug && (
        <div className="mt-3 pt-3 border-t border-slate-800">
          <Button
            variant="outline"
            size="sm"
            className="w-full"
            onClick={downloadRoleBundle}
            loading={downloading}
          >
            Download Bundle
          </Button>
        </div>
      )}
    </Card>
  )
}

export default RoleCard
