import React, { useState } from 'react'
import Card from '../../../../components/Card'
import Badge from '../../../../components/Badge'
import Button from '../../../../components/Button'
import authreconApi from '../../../../services/authreconApi'

const TYPE_LABELS = {
  side_file: 'Selenium script',
  scanner_import: 'Scanner import',
  har: 'HAR',
  html: 'HTML',
  screenshot: 'Screenshot',
  sitemap: 'Sitemap',
  log: 'Log',
}

// One-line "what is this for" for the per-tool export files.
const IMPORT_HINTS = {
  burp: 'Burp Suite: the authenticated request, ready to paste into Repeater.',
  curl: 'curl script that replays the authenticated request with the captured session.',
  postman: 'Postman collection with the authenticated request and session cookies.',
  zap: 'OWASP ZAP context: target scope and session for an authenticated ZAP scan.',
}
const importKind = (name = '') => (
  /burp_request/.test(name) ? 'burp'
    : /auth_request\.sh$/.test(name) ? 'curl'
      : /postman_collection/.test(name) ? 'postman'
        : /zap_context/.test(name) ? 'zap' : null
)

function ArtifactsSection({ runId, artifacts, runStatus }) {
  const [activeTab, setActiveTab] = useState('all')
  const [downloading, setDownloading] = useState({})

  if (!artifacts || artifacts.length === 0) {
    return (
      <Card padding="lg">
        <h3 className="text-lg font-semibold text-slate-50 mb-4">
          Artifacts
        </h3>
        <div className="py-8 text-center">
          <p className="text-sm text-slate-400">
            No artifacts captured for this run
          </p>
        </div>
      </Card>
    )
  }

  // Group artifacts by type
  const artifactsByType = artifacts.reduce((acc, artifact) => {
    const type = artifact.type || 'other'
    if (!acc[type]) acc[type] = []
    acc[type].push(artifact)
    return acc
  }, {})

  const tabs = [
    { id: 'all', label: 'All', count: artifacts.length },
    { id: 'screenshot', label: 'Screenshots', count: artifactsByType.screenshot?.length || 0 },
    { id: 'har', label: 'HAR', count: artifactsByType.har?.length || 0 },
    { id: 'html', label: 'HTML', count: artifactsByType.html?.length || 0 },
    { id: 'side_file', label: 'Scripts', count: artifactsByType.side_file?.length || 0 },
    { id: 'scanner_import', label: 'Scanner imports', count: artifactsByType.scanner_import?.length || 0 },
    { id: 'sitemap', label: 'Sitemap', count: artifactsByType.sitemap?.length || 0 },
    { id: 'log', label: 'Logs', count: artifactsByType.log?.length || 0 },
  ].filter(tab => tab.id === 'all' || tab.count > 0)

  const filteredArtifacts = activeTab === 'all'
    ? artifacts
    : artifactsByType[activeTab] || []

  const downloadArtifact = async (artifact) => {
    try {
      setDownloading(prev => ({ ...prev, [artifact.id]: true }))

      const response = await authreconApi.get(
        `runs/${runId}/artifacts/${artifact.id}/download`,
        { responseType: 'blob' }
      )

      // Create download link
      const url = window.URL.createObjectURL(new Blob([response.data]))
      const link = document.createElement('a')
      link.href = url
      link.setAttribute('download', artifact.name || artifact.filename || `artifact-${artifact.id}`)
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(url)
    } catch (error) {
      console.error('Download failed:', error)
      alert(`Failed to download: ${error.message}`)
    } finally {
      setDownloading(prev => ({ ...prev, [artifact.id]: false }))
    }
  }

  const downloadAll = async () => {
    try {
      setDownloading(prev => ({ ...prev, all: true }))

      const response = await authreconApi.get(
        `runs/${runId}/artifacts/download-all`,
        { responseType: 'blob' }
      )

      const url = window.URL.createObjectURL(new Blob([response.data]))
      const link = document.createElement('a')
      link.href = url
      link.setAttribute('download', `${runId}-artifacts.zip`)
      document.body.appendChild(link)
      link.click()
      link.remove()
      window.URL.revokeObjectURL(url)
    } catch (error) {
      console.error('Download all failed:', error)
      alert(`Failed to download all: ${error.message}`)
    } finally {
      setDownloading(prev => ({ ...prev, all: false }))
    }
  }

  const formatFileSize = (bytes) => {
    if (!bytes) return '—'
    if (bytes < 1024) return `${bytes} B`
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
    return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
  }

  return (
    <Card padding="lg">
      <div className="flex items-center justify-between mb-4 flex-wrap gap-3">
        <h3 className="text-lg font-semibold text-slate-50">
          Artifacts
        </h3>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={downloadAll}
            loading={downloading.all}
          >
            Download All
          </Button>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex flex-wrap gap-2 mb-4 border-b border-(--stroke-dark) pb-3">
        {tabs.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors border ${
              activeTab === tab.id
                ? 'bg-(--sidebar-active-bg) text-(--accent-blue) border-(--stroke-blue)'
                : 'bg-(--bg-1) text-(--text-secondary) border-(--stroke-dark) hover:border-(--stroke-blue)'
            }`}
          >
            {tab.label} {tab.count > 0 && `(${tab.count})`}
          </button>
        ))}
      </div>

      {/* Artifact List */}
      <div className="space-y-2 max-h-[70vh] overflow-y-auto scrollbar-thin">
        {filteredArtifacts.length > 0 ? (
          filteredArtifacts.map(artifact => (
            <div
              key={artifact.id}
              className="p-3 rounded-lg border border-(--stroke-dark) bg-(--bg-2) hover:border-(--stroke-blue) transition-colors"
            >
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <p className="text-sm text-slate-300 font-medium truncate">
                      {artifact.name || artifact.filename || artifact.type || 'Unknown'}
                    </p>
                    <Badge variant="default" className="text-xs">
                      {TYPE_LABELS[artifact.type] || artifact.type}
                    </Badge>
                  </div>
                  {(artifact.description || IMPORT_HINTS[importKind(artifact.name)]) && (
                    <p className="text-xs text-slate-400 mb-1">
                      {IMPORT_HINTS[importKind(artifact.name)] || artifact.description}
                    </p>
                  )}
                  <div className="flex flex-wrap items-center gap-3 text-xs text-slate-500">
                    {artifact.size_bytes && (
                      <span>{formatFileSize(artifact.size_bytes)}</span>
                    )}
                    {artifact.role_label && (
                      <span>Role: {artifact.role_label}</span>
                    )}
                    {!artifact.role_label && artifact.role_slug && (
                      <span>Role: {artifact.role_slug}</span>
                    )}
                    {artifact.created_at && (
                      <span>{new Date(artifact.created_at).toLocaleString()}</span>
                    )}
                  </div>
                </div>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => downloadArtifact(artifact)}
                  loading={downloading[artifact.id]}
                >
                  Download
                </Button>
              </div>
            </div>
          ))
        ) : (
          <div className="py-8 text-center">
            <p className="text-sm text-slate-400">
              No artifacts in this category
            </p>
          </div>
        )}
      </div>
    </Card>
  )
}

export default ArtifactsSection
