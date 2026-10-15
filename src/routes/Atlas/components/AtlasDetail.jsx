import React from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  X,
  Server,
  Shield,
  AlertTriangle,
  Globe,
  Key,
  Clock,
  ExternalLink,
  CheckCircle,
  XCircle,
  Cookie,
  Lock,
  ShieldCheck,
  ShieldAlert,
} from 'lucide-react'
import { Link } from 'react-router-dom'
import Card from '../../../components/Card'
import Badge from '../../../components/Badge'
import { fetchNodeDetails } from '../../../services/atlas/providers'
import { SEVERITY_COLORS, AUTH_TYPE_COLORS } from '../../../services/atlas/types'

/**
 * Atlas Detail Component
 *
 * Enhanced detail panel showing node information based on provider/story.
 * Includes mini charts, security scores, and provider-specific details.
 */
function AtlasDetail({ node, story, onClose }) {
  if (!node) return null

  const providerId = story?.provider || 'authrecon'
  const nodeType = node.metadata?.type || 'unknown'

  // Fetch additional details
  const { data: details, isLoading } = useQuery({
    queryKey: ['atlas-node-details', providerId, node.id],
    queryFn: () => fetchNodeDetails(providerId, node.id),
    enabled: !!node.id,
    staleTime: 30000,
  })

  return (
    <div className="fixed inset-y-0 right-0 w-[420px] bg-slate-900 border-l border-slate-800/50 shadow-2xl overflow-hidden z-30 flex flex-col">
      {/* Header */}
      <div className="sticky top-0 bg-slate-900/95 backdrop-blur-xs border-b border-slate-800/50 p-4">
        <div className="flex items-start justify-between">
          <div className="flex items-start gap-3">
            <NodeIcon node={node} />
            <div>
              <h2 className="text-lg font-bold text-slate-200">{node.label}</h2>
              {node.subtitle && (
                <p className="text-sm text-slate-500">{node.subtitle}</p>
              )}
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-2 hover:bg-slate-800/50 rounded-lg transition-colors"
          >
            <X className="w-4 h-4 text-slate-400" />
          </button>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">
        {/* Score Card for targets */}
        {nodeType === 'target' && (
          <ScoreCard node={node} />
        )}

        {/* Overview */}
        <Card>
          <div className="p-4 space-y-3">
            <div className="flex items-center gap-2 text-sm">
              <Shield className="w-4 h-4 text-slate-400" />
              <span className="text-slate-400">Type:</span>
              <Badge variant="default">
                {nodeType.charAt(0).toUpperCase() + nodeType.slice(1)}
              </Badge>
            </div>

            {node.category && (
              <div className="flex items-center gap-2 text-sm">
                <Key className="w-4 h-4 text-slate-400" />
                <span className="text-slate-400">Category:</span>
                <Badge
                  variant="default"
                  style={{
                    backgroundColor: `${AUTH_TYPE_COLORS[node.category] || AUTH_TYPE_COLORS.unknown}20`,
                    color: AUTH_TYPE_COLORS[node.category] || AUTH_TYPE_COLORS.unknown,
                  }}
                >
                  {node.category.toUpperCase()}
                </Badge>
              </div>
            )}

            {node.severity && (
              <div className="flex items-center gap-2 text-sm">
                <AlertTriangle className="w-4 h-4 text-slate-400" />
                <span className="text-slate-400">Severity:</span>
                <Badge variant={severityToVariant(node.severity)}>
                  {node.severity}
                </Badge>
              </div>
            )}
          </div>
        </Card>

        {/* Provider-specific content */}
        {providerId === 'authrecon' && nodeType === 'target' && (
          <AuthReconTargetDetails node={node} details={details} isLoading={isLoading} />
        )}

        {providerId === 'authrecon' && nodeType === 'idp' && (
          <AuthReconIdPDetails node={node} />
        )}

      </div>
    </div>
  )
}

/**
 * Node icon based on type
 */
function NodeIcon({ node }) {
  const type = node.metadata?.type || 'unknown'
  const color = node.color || SEVERITY_COLORS[node.severity] || '#64748b'

  const icons = {
    target: Globe,
    idp: Key,
    asset: Server,
    unknown: Shield,
  }

  const Icon = icons[type] || icons.unknown

  return (
    <div
      className="p-2 rounded-lg"
      style={{ backgroundColor: `${color}20` }}
    >
      <Icon className="w-5 h-5" style={{ color }} />
    </div>
  )
}

/**
 * Security score card with visual indicator
 */
function ScoreCard({ node }) {
  const score = node.score || 0
  const severity = node.severity || 'info'
  const color = SEVERITY_COLORS[severity]

  // Score ring percentage (0-100)
  const circumference = 2 * Math.PI * 36
  const progress = (score / 100) * circumference

  return (
    <Card className="overflow-hidden">
      <div
        className="h-1"
        style={{ backgroundColor: color }}
      />
      <div className="p-4">
        <div className="flex items-center gap-4">
          {/* Score Ring */}
          <div className="relative w-20 h-20">
            <svg className="w-20 h-20 transform -rotate-90">
              {/* Background ring */}
              <circle
                cx="40"
                cy="40"
                r="36"
                fill="none"
                stroke="rgba(51, 65, 85, 0.5)"
                strokeWidth="6"
              />
              {/* Progress ring */}
              <circle
                cx="40"
                cy="40"
                r="36"
                fill="none"
                stroke={color}
                strokeWidth="6"
                strokeDasharray={`${progress} ${circumference}`}
                strokeLinecap="round"
              />
            </svg>
            <div className="absolute inset-0 flex items-center justify-center">
              <span className="text-2xl font-bold text-slate-200">{score}</span>
            </div>
          </div>

          {/* Score details */}
          <div className="flex-1">
            <div className="text-sm font-semibold text-slate-200 mb-1">
              Security Score
            </div>
            <div className="text-xs text-slate-500 mb-2">
              {score >= 80 && 'High risk - immediate attention needed'}
              {score >= 60 && score < 80 && 'Elevated risk - review recommended'}
              {score >= 40 && score < 60 && 'Moderate risk - monitor closely'}
              {score >= 20 && score < 40 && 'Low risk - acceptable posture'}
              {score < 20 && 'Minimal risk - good security posture'}
            </div>
            <Badge variant={severityToVariant(severity)}>
              {severity.toUpperCase()} RISK
            </Badge>
          </div>
        </div>
      </div>
    </Card>
  )
}

/**
 * AuthRecon target details
 */
function AuthReconTargetDetails({ node, details, isLoading }) {
  const metadata = node.metadata || {}
  const results = metadata.results || {}
  const allRuns = details?.allRuns || []

  return (
    <>
      {/* Scan Summary */}
      <div>
        <h3 className="text-sm font-semibold text-slate-300 mb-2">Scan Summary</h3>
        <Card>
          <div className="p-4 space-y-3">
            <div className="flex items-center justify-between text-sm">
              <span className="text-slate-400">Total Scans</span>
              <span className="text-slate-200 font-semibold">
                {metadata.runCount || 0}
              </span>
            </div>

            <div className="flex items-center justify-between text-sm">
              <span className="text-slate-400">Auth Types Detected</span>
              <div className="flex gap-1">
                {(metadata.authTypes || []).map((type) => (
                  <Badge
                    key={type}
                    variant="default"
                    className="text-xs"
                    style={{
                      backgroundColor: `${AUTH_TYPE_COLORS[type] || AUTH_TYPE_COLORS.unknown}20`,
                      color: AUTH_TYPE_COLORS[type] || AUTH_TYPE_COLORS.unknown,
                    }}
                  >
                    {type}
                  </Badge>
                ))}
              </div>
            </div>

            {metadata.latestRunDate && (
              <div className="flex items-center justify-between text-sm">
                <span className="text-slate-400">Last Scanned</span>
                <span className="text-slate-200">
                  {formatDate(metadata.latestRunDate)}
                </span>
              </div>
            )}

            {metadata.latestRunStatus && (
              <div className="flex items-center justify-between text-sm">
                <span className="text-slate-400">Last Status</span>
                <StatusBadge status={metadata.latestRunStatus} />
              </div>
            )}
          </div>
        </Card>
      </div>

      {/* Security Analysis */}
      {Object.keys(results).length > 0 && (
        <div>
          <h3 className="text-sm font-semibold text-slate-300 mb-2">
            Security Analysis
          </h3>
          <Card>
            <div className="p-4 space-y-3">
              {/* Cookies Analysis */}
              {results.cookies && (
                <SecurityItem
                  icon={Cookie}
                  label="Cookies"
                  items={[
                    {
                      label: 'Secure',
                      value: results.cookies.secure_count || 0,
                      good: true,
                    },
                    {
                      label: 'HttpOnly',
                      value: results.cookies.httponly_count || 0,
                      good: true,
                    },
                    {
                      label: 'SameSite',
                      value: results.cookies.samesite_count || 0,
                      good: true,
                    },
                  ]}
                />
              )}

              {/* Headers Analysis */}
              {results.security_headers && (
                <SecurityItem
                  icon={ShieldCheck}
                  label="Security Headers"
                  items={Object.entries(results.security_headers).map(([key, value]) => ({
                    label: key.replace(/_/g, ' '),
                    present: !!value,
                  }))}
                />
              )}

              {/* TLS Analysis */}
              {results.tls && (
                <SecurityItem
                  icon={Lock}
                  label="TLS Configuration"
                  items={[
                    { label: 'Version', value: results.tls.version },
                    { label: 'Cipher', value: results.tls.cipher_suite?.substring(0, 30) },
                  ]}
                />
              )}
            </div>
          </Card>
        </div>
      )}

      {/* Link to full run */}
      {metadata.latestRunId && (
        <Link
          to={`/authrecon/run/${metadata.latestRunId}`}
          className="flex items-center justify-center gap-2 px-4 py-3 bg-cyan-500/10 hover:bg-cyan-500/20 border border-cyan-500/30 rounded-lg text-cyan-400 text-sm font-medium transition-colors"
        >
          <ExternalLink className="w-4 h-4" />
          View Full Scan Results
        </Link>
      )}

      {/* Recent runs */}
      {allRuns.length > 1 && (
        <div>
          <h3 className="text-sm font-semibold text-slate-300 mb-2">
            Recent Scans
          </h3>
          <div className="space-y-2">
            {allRuns.slice(0, 5).map((run) => (
              <Link
                key={run.id}
                to={`/authrecon/run/${run.id}`}
                className="block"
              >
                <Card className="hover:border-cyan-500/30 transition-colors">
                  <div className="p-3 flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <StatusBadge status={run.status} small />
                      <span className="text-xs text-slate-400">
                        {formatDate(run.submitted_at)}
                      </span>
                    </div>
                    {run.results?.overall_security_score !== undefined && (
                      <span className="text-xs font-semibold text-slate-300">
                        Score: {run.results.overall_security_score}
                      </span>
                    )}
                  </div>
                </Card>
              </Link>
            ))}
          </div>
        </div>
      )}
    </>
  )
}

/**
 * AuthRecon IdP details
 */
function AuthReconIdPDetails({ node }) {
  const metadata = node.metadata || {}

  return (
    <div>
      <h3 className="text-sm font-semibold text-slate-300 mb-2">
        Identity Provider Details
      </h3>
      <Card>
        <div className="p-4 space-y-3">
          <div className="flex items-center justify-between text-sm">
            <span className="text-slate-400">Provider Name</span>
            <span className="text-slate-200 font-semibold">{metadata.name}</span>
          </div>

          <div className="flex items-center justify-between text-sm">
            <span className="text-slate-400">Auth Protocol</span>
            <Badge
              variant="default"
              style={{
                backgroundColor: `${AUTH_TYPE_COLORS[metadata.authType] || AUTH_TYPE_COLORS.unknown}20`,
                color: AUTH_TYPE_COLORS[metadata.authType] || AUTH_TYPE_COLORS.unknown,
              }}
            >
              {(metadata.authType || 'unknown').toUpperCase()}
            </Badge>
          </div>

          {metadata.url && (
            <div className="flex items-center justify-between text-sm">
              <span className="text-slate-400">Domain</span>
              <span className="text-slate-200 font-mono text-xs">{metadata.url}</span>
            </div>
          )}

          <div className="flex items-center justify-between text-sm">
            <span className="text-slate-400">Connected Targets</span>
            <span className="text-slate-200 font-semibold">
              {metadata.targetCount || 0}
            </span>
          </div>
        </div>
      </Card>

      {/* Connected targets list */}
      {metadata.targets && metadata.targets.length > 0 && (
        <div className="mt-4">
          <h3 className="text-sm font-semibold text-slate-300 mb-2">
            Connected Targets
          </h3>
          <Card>
            <div className="p-3 space-y-2">
              {metadata.targets.slice(0, 10).map((target) => (
                <div
                  key={target}
                  className="flex items-center gap-2 text-sm text-slate-400"
                >
                  <Globe className="w-3 h-3" />
                  <span className="font-mono text-xs">{target}</span>
                </div>
              ))}
              {metadata.targets.length > 10 && (
                <div className="text-xs text-slate-500">
                  +{metadata.targets.length - 10} more targets
                </div>
              )}
            </div>
          </Card>
        </div>
      )}
    </div>
  )
}

/**
 * Security analysis item
 */
function SecurityItem({ icon: Icon, label, items }) {
  return (
    <div className="border-t border-slate-800/50 pt-3 first:border-0 first:pt-0">
      <div className="flex items-center gap-2 mb-2">
        <Icon className="w-4 h-4 text-slate-400" />
        <span className="text-sm font-medium text-slate-300">{label}</span>
      </div>
      <div className="grid grid-cols-2 gap-2 ml-6">
        {items.map((item, i) => (
          <div key={i} className="flex items-center gap-1 text-xs">
            {item.present !== undefined ? (
              item.present ? (
                <CheckCircle className="w-3 h-3 text-green-500" />
              ) : (
                <XCircle className="w-3 h-3 text-slate-600" />
              )
            ) : item.good !== undefined ? (
              <span className={item.value > 0 ? 'text-green-400' : 'text-slate-500'}>
                {item.value}
              </span>
            ) : null}
            <span className="text-slate-400">
              {item.label}
              {item.value !== undefined && item.good === undefined && `: ${item.value}`}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

/**
 * Status badge component
 */
function StatusBadge({ status, small = false }) {
  const configs = {
    succeeded: { color: 'text-green-400', bg: 'bg-green-500/10', label: 'Success' },
    completed: { color: 'text-green-400', bg: 'bg-green-500/10', label: 'Success' },
    failed: { color: 'text-red-400', bg: 'bg-red-500/10', label: 'Failed' },
    running: { color: 'text-blue-400', bg: 'bg-blue-500/10', label: 'Running' },
    queued: { color: 'text-amber-400', bg: 'bg-amber-500/10', label: 'Queued' },
  }

  const config = configs[status] || { color: 'text-slate-400', bg: 'bg-slate-500/10', label: status }

  return (
    <span
      className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-full ${config.bg} ${config.color} ${
        small ? 'text-[10px]' : 'text-xs'
      }`}
    >
      {status === 'succeeded' || status === 'completed' ? (
        <CheckCircle className={small ? 'w-2.5 h-2.5' : 'w-3 h-3'} />
      ) : status === 'failed' ? (
        <XCircle className={small ? 'w-2.5 h-2.5' : 'w-3 h-3'} />
      ) : null}
      {config.label}
    </span>
  )
}

// Helper functions
function severityToVariant(severity) {
  const map = {
    critical: 'error',
    high: 'warning',
    medium: 'info',
    low: 'success',
    info: 'default',
  }
  return map[severity] || 'default'
}

function formatDate(dateString) {
  if (!dateString) return 'Unknown'
  const date = new Date(dateString)
  return date.toLocaleDateString(undefined, {
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  })
}

export default AtlasDetail
