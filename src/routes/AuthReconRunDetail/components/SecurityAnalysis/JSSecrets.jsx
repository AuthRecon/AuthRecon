import React, { useState } from 'react'
import Card from '../../../../components/Card'
import Badge from '../../../../components/Badge'
import { FileCode, AlertTriangle, ChevronDown, ChevronUp, Eye, Info } from 'lucide-react'

function JSSecrets({ jsSecretsData }) {
  const [expandedFindings, setExpandedFindings] = useState(new Set())

  if (!jsSecretsData || !jsSecretsData.js_secrets) {
    return (
      <Card padding="lg" className="border-slate-700/50">
        <div className="text-center py-8">
          <p className="text-sm text-slate-400">No JavaScript secrets scan data available</p>
        </div>
      </Card>
    )
  }

  const jsSecretsAnalysis = jsSecretsData.js_secrets
  const findings = jsSecretsAnalysis.findings || []

  if (findings.length === 0) {
    // Display scanning stats to show the scanner actually ran
    const totalFiles = jsSecretsAnalysis.total_js_files || 0
    const totalLines = jsSecretsAnalysis.total_lines_scanned || 0
    const largestFiles = jsSecretsAnalysis.largest_files || []

    const formatNumber = (num) => num.toLocaleString()
    const formatBytes = (bytes) => {
      if (bytes < 1024) return `${bytes} B`
      if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
      return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
    }

    return (
      <Card padding="lg" className="border-slate-700/50">
        <div className="flex items-center gap-3 mb-4">
          <div className="p-3 bg-emerald-500/10 rounded-lg">
            <FileCode className="w-6 h-6 text-emerald-400" />
          </div>
          <div>
            <h3 className="text-lg font-semibold text-slate-50">JavaScript Secrets Scanner</h3>
            <p className="text-sm text-emerald-400 mt-1">✓ No secrets detected in JavaScript files</p>
          </div>
        </div>

        {totalFiles > 0 && (
          <div className="border-t border-slate-700/30 pt-4 mt-4 space-y-3">
            <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
              <div className="text-center p-3 bg-slate-800/30 rounded">
                <div className="text-2xl font-bold text-emerald-400">{formatNumber(totalLines)}</div>
                <div className="text-xs text-slate-400 mt-1">Lines Scanned</div>
              </div>
              <div className="text-center p-3 bg-slate-800/30 rounded">
                <div className="text-2xl font-bold text-emerald-400">{totalFiles}</div>
                <div className="text-xs text-slate-400 mt-1">Files Analyzed</div>
              </div>
              <div className="text-center p-3 bg-slate-800/30 rounded">
                <div className="text-2xl font-bold text-emerald-400">{jsSecretsAnalysis.security_score.toFixed(1)}</div>
                <div className="text-xs text-slate-400 mt-1">Security Score</div>
              </div>
            </div>

            {largestFiles.length > 0 && (
              <details className="group mt-4">
                <summary className="cursor-pointer text-sm text-slate-400 hover:text-slate-200 transition-colors list-none flex items-center gap-2">
                  <ChevronDown className="w-4 h-4 group-open:rotate-180 transition-transform" />
                  <span>Show Scanned Files ({largestFiles.length})</span>
                </summary>
                <div className="mt-3 space-y-2">
                  {largestFiles.map((file, idx) => (
                    <div key={idx} className="flex items-center justify-between text-xs bg-slate-800/20 rounded p-2">
                      <span className="text-slate-300 font-mono truncate flex-1 pr-4">{file.name}</span>
                      <div className="flex items-center gap-3 text-slate-400 flex-shrink-0">
                        <span>{formatNumber(file.lines)} lines</span>
                        <span className="text-slate-600">•</span>
                        <span>{formatBytes(file.size_bytes)}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </details>
            )}
          </div>
        )}
      </Card>
    )
  }

  // Use pre-calculated stats from backend or calculate as fallback
  const stats = {
    total: jsSecretsAnalysis.total_findings || findings.length,
    critical: jsSecretsAnalysis.critical_count || findings.filter(f => f.severity === 'CRITICAL').length,
    high: jsSecretsAnalysis.high_count || findings.filter(f => f.severity === 'HIGH').length,
    medium: jsSecretsAnalysis.medium_count || findings.filter(f => f.severity === 'MEDIUM').length,
    low: jsSecretsAnalysis.low_count || findings.filter(f => f.severity === 'LOW').length,
    preAuth: jsSecretsAnalysis.pre_auth_count || findings.filter(f => f.pre_auth).length,
    postAuth: jsSecretsAnalysis.post_auth_count || findings.filter(f => !f.pre_auth).length,
  }

  // Calculate risk level
  const getRiskLevel = () => {
    if (stats.critical > 0) return { level: 'CRITICAL', variant: 'error', text: 'Critical Risk' }
    if (stats.high > 0) return { level: 'HIGH', variant: 'warning', text: 'High Risk' }
    if (stats.medium > 0) return { level: 'MEDIUM', variant: 'info', text: 'Medium Risk' }
    return { level: 'LOW', variant: 'default', text: 'Low Risk' }
  }

  const riskLevel = getRiskLevel()

  const getSeverityVariant = (severity) => {
    switch (severity) {
      case 'CRITICAL': return 'error'
      case 'HIGH': return 'warning'
      case 'MEDIUM': return 'info'
      case 'LOW': return 'default'
      default: return 'default'
    }
  }

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'CRITICAL': return 'text-rose-400'
      case 'HIGH': return 'text-orange-400'
      case 'MEDIUM': return 'text-yellow-400'
      case 'LOW': return 'text-blue-400'
      default: return 'text-slate-400'
    }
  }

  const toggleFinding = (index) => {
    const newExpanded = new Set(expandedFindings)
    if (newExpanded.has(index)) {
      newExpanded.delete(index)
    } else {
      newExpanded.add(index)
    }
    setExpandedFindings(newExpanded)
  }

  const expandAll = () => {
    setExpandedFindings(new Set(findings.map((_, idx) => idx)))
  }

  const collapseAll = () => {
    setExpandedFindings(new Set())
  }

  return (
    <div className="space-y-4">
      {/* Layer 1: Executive Summary Card */}
      <Card padding="lg" className="border-rose-900/50 bg-rose-950/10">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-3">
            <div className={`p-3 ${riskLevel.level === 'CRITICAL' ? 'bg-rose-500/20' : 'bg-orange-500/20'} rounded-lg`}>
              <AlertTriangle className={`w-6 h-6 ${riskLevel.level === 'CRITICAL' ? 'text-rose-400' : 'text-orange-400'}`} />
            </div>
            <div>
              <h3 className="text-lg font-semibold text-slate-50">JavaScript Secrets Detected</h3>
              <p className="text-sm text-slate-400 mt-1">
                Found {stats.total} secret{stats.total !== 1 ? 's' : ''} in JavaScript files
              </p>
            </div>
          </div>
          <Badge variant={riskLevel.variant} size="lg">
            {riskLevel.text}
          </Badge>
        </div>

        {/* Stats Grid */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-4">
          {stats.critical > 0 && (
            <div className="text-center">
              <div className="text-2xl font-bold text-rose-400">{stats.critical}</div>
              <div className="text-xs text-slate-400">Critical</div>
            </div>
          )}
          {stats.high > 0 && (
            <div className="text-center">
              <div className="text-2xl font-bold text-orange-400">{stats.high}</div>
              <div className="text-xs text-slate-400">High</div>
            </div>
          )}
          {stats.medium > 0 && (
            <div className="text-center">
              <div className="text-2xl font-bold text-yellow-400">{stats.medium}</div>
              <div className="text-xs text-slate-400">Medium</div>
            </div>
          )}
          {stats.low > 0 && (
            <div className="text-center">
              <div className="text-2xl font-bold text-blue-400">{stats.low}</div>
              <div className="text-xs text-slate-400">Low</div>
            </div>
          )}
        </div>

        {/* Pre-Auth vs Post-Auth */}
        {stats.preAuth > 0 && (
          <div className="pt-4 border-t border-slate-700/30">
            <div className="flex items-center gap-2 text-sm">
              <Eye className="w-4 h-4 text-rose-400" />
              <span className="text-rose-400 font-medium">
                {stats.preAuth} secret{stats.preAuth !== 1 ? 's' : ''} exposed pre-authentication
              </span>
              <Info className="w-4 h-4 text-slate-500" title="Visible to attackers without logging in" />
            </div>
          </div>
        )}

        {/* Expand/Collapse Controls */}
        <div className="flex gap-2 mt-4 pt-4 border-t border-slate-700/30">
          <button
            onClick={expandAll}
            className="text-xs text-slate-400 hover:text-slate-200 transition-colors"
          >
            Expand All
          </button>
          <span className="text-xs text-slate-600">•</span>
          <button
            onClick={collapseAll}
            className="text-xs text-slate-400 hover:text-slate-200 transition-colors"
          >
            Collapse All
          </button>
        </div>
      </Card>

      {/* Layer 2 & 3: Finding Cards with Expandable Snippets */}
      <div className="space-y-3">
        {findings.map((finding, index) => {
          const isExpanded = expandedFindings.has(index)
          return (
            <Card
              key={index}
              padding="md"
              className={`border-slate-700/50 ${finding.severity === 'CRITICAL' ? 'border-rose-900/50 bg-rose-950/5' : ''}`}
            >
              {/* Finding Header (always visible) */}
              <div
                className="flex items-start justify-between gap-4 cursor-pointer"
                onClick={() => toggleFinding(index)}
              >
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-2">
                    <Badge variant={getSeverityVariant(finding.severity)} size="sm">
                      {finding.severity}
                    </Badge>
                    <Badge variant={finding.pre_auth ? 'error' : 'default'} size="sm">
                      {finding.pre_auth ? 'PRE-AUTH' : 'POST-AUTH'}
                    </Badge>
                    <Badge variant="default" size="sm">
                      {finding.confidence}
                    </Badge>
                  </div>
                  <h4 className={`text-sm font-semibold mb-1 ${getSeverityColor(finding.severity)}`}>
                    {finding.type}
                  </h4>
                  <p className="text-xs text-slate-400 mb-2">
                    {finding.file} <span className="text-slate-600">•</span> Line {finding.line}
                  </p>
                  <p className="text-sm text-slate-300">{finding.impact}</p>
                </div>
                <button className="flex-shrink-0 text-slate-400 hover:text-slate-200 transition-colors">
                  {isExpanded ? (
                    <ChevronUp className="w-5 h-5" />
                  ) : (
                    <ChevronDown className="w-5 h-5" />
                  )}
                </button>
              </div>

              {/* Layer 3: Code Snippet (expandable) */}
              {isExpanded && (
                <div className="mt-4 pt-4 border-t border-slate-700/30 space-y-3">
                  {/* Source Code Snippet */}
                  <div>
                    <div className="flex items-center gap-2 text-xs text-slate-400 mb-2">
                      <FileCode className="w-3 h-3" />
                      <span className="font-medium">Source Code Context</span>
                    </div>
                    <div className="bg-slate-950/50 rounded border border-slate-800 p-3 overflow-x-auto">
                      <pre className="text-xs text-slate-300 font-mono whitespace-pre">
                        {finding.snippet}
                      </pre>
                    </div>
                  </div>

                  {/* Layer 4: Raw Evidence */}
                  <details className="group">
                    <summary className="cursor-pointer text-xs text-slate-400 hover:text-slate-200 transition-colors list-none flex items-center gap-2">
                      <ChevronDown className="w-3 h-3 group-open:rotate-180 transition-transform" />
                      <span>Show Matched Value</span>
                    </summary>
                    <div className="mt-2 bg-slate-950/50 rounded border border-slate-800 p-3">
                      <div className="text-xs text-slate-400 mb-1">Matched Pattern:</div>
                      <code className="text-xs text-rose-300 font-mono break-all">
                        {finding.matched_value}
                      </code>
                    </div>
                  </details>

                  {/* Full URL */}
                  <details className="group">
                    <summary className="cursor-pointer text-xs text-slate-400 hover:text-slate-200 transition-colors list-none flex items-center gap-2">
                      <ChevronDown className="w-3 h-3 group-open:rotate-180 transition-transform" />
                      <span>Show Full URL</span>
                    </summary>
                    <div className="mt-2 bg-slate-950/50 rounded border border-slate-800 p-3">
                      <code className="text-xs text-slate-300 font-mono break-all">
                        {finding.url}
                      </code>
                    </div>
                  </details>
                </div>
              )}
            </Card>
          )
        })}
      </div>
    </div>
  )
}

export default JSSecrets
