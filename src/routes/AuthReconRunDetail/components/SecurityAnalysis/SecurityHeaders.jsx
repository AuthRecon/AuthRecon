import React from 'react'
import Card from '../../../../components/Card'
import Badge from '../../../../components/Badge'
import { Shield, Check, X, AlertTriangle, Server } from 'lucide-react'

function SecurityHeaders({ headersData }) {
  if (!headersData) {
    return (
      <Card padding="lg" className="border-slate-700/50">
        <div className="text-center py-8">
          <p className="text-sm text-slate-400">No security headers data available</p>
        </div>
      </Card>
    )
  }

  const {
    security = {},
    server,
    x_powered_by,
    framework_hints = [],
  } = headersData

  const {
    hsts,
    csp,
    x_frame_options,
    x_content_type_options,
    referrer_policy,
    cors,
    missing_headers = [],
    security_score,
    issues = [],
  } = security

  const getScoreVariant = (score) => {
    if (score >= 80) return 'success'
    if (score >= 60) return 'warning'
    return 'error'
  }

  return (
    <div className="space-y-4">
      {/* Score Card */}
      <Card padding="lg" className="border-slate-700/50">
        <div className="flex items-center justify-between mb-6">
          <div>
            <h3 className="text-lg font-semibold text-slate-50 mb-1">Security Headers Analysis</h3>
            <p className="text-sm text-slate-400">
              HTTP response header security posture
            </p>
          </div>
          <div className="text-right">
            <div className="text-3xl font-bold text-slate-50 mb-1">{Math.round(security_score)}/100</div>
            <Badge variant={getScoreVariant(security_score)}>
              {security_score >= 80 ? 'Good' : security_score >= 60 ? 'Fair' : 'Poor'}
            </Badge>
          </div>
        </div>

        {/* Server Info */}
        {(server || x_powered_by || framework_hints.length > 0) && (
          <div className="mb-6 pb-6 border-b border-slate-700/30">
            <div className="flex items-center gap-2 text-sm text-slate-400 mb-3">
              <Server className="w-4 h-4" />
              <span className="font-medium">Server Information</span>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {server && (
                <div>
                  <p className="text-xs text-slate-500 mb-1">Server</p>
                  <p className="text-sm text-slate-300">{server}</p>
                </div>
              )}
              {x_powered_by && (
                <div>
                  <p className="text-xs text-slate-500 mb-1">X-Powered-By</p>
                  <p className="text-sm text-slate-300">{x_powered_by}</p>
                </div>
              )}
              {framework_hints.length > 0 && (
                <div>
                  <p className="text-xs text-slate-500 mb-1">Framework Hints</p>
                  <div className="flex flex-wrap gap-1">
                    {framework_hints.map((hint, idx) => (
                      <Badge key={idx} variant="default" size="sm">
                        {hint}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}

        {/* Issues */}
        {issues.length > 0 && (
          <div className="space-y-2">
            <div className="flex items-center gap-2 text-sm text-slate-400 mb-3">
              <AlertTriangle className="w-4 h-4" />
              <span className="font-medium">Security Issues Found</span>
            </div>
            <div className="space-y-2">
              {issues.map((issue, idx) => (
                <div key={idx} className="flex items-start gap-2 text-sm">
                  <X className="w-4 h-4 text-rose-400 mt-0.5 shrink-0" />
                  <span className="text-slate-300">{issue}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </Card>

      {/* Headers Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        {/* HSTS */}
        <Card padding="md" className="border-slate-700/50">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              {hsts ? (
                <Check className="w-4 h-4 text-emerald-400" />
              ) : (
                <X className="w-4 h-4 text-rose-400" />
              )}
              <span className="text-sm font-medium text-slate-200">HSTS</span>
            </div>
            <Badge variant={hsts ? 'success' : 'error'} size="sm">
              {hsts ? 'Present' : 'Missing'}
            </Badge>
          </div>
          {hsts ? (
            <div className="space-y-1 text-xs text-slate-400">
              <div>Max-Age: {hsts.max_age_seconds}s</div>
              <div>Include Subdomains: {hsts.include_subdomains ? 'Yes' : 'No'}</div>
              <div>Preload: {hsts.preload ? 'Yes' : 'No'}</div>
            </div>
          ) : (
            <p className="text-xs text-slate-500">Strict-Transport-Security header not found</p>
          )}
        </Card>

        {/* CSP */}
        <Card padding="md" className="border-slate-700/50">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              {csp ? (
                <Check className="w-4 h-4 text-emerald-400" />
              ) : (
                <X className="w-4 h-4 text-rose-400" />
              )}
              <span className="text-sm font-medium text-slate-200">CSP</span>
            </div>
            <Badge variant={csp ? 'success' : 'error'} size="sm">
              {csp ? 'Present' : 'Missing'}
            </Badge>
          </div>
          {csp ? (
            <div className="space-y-1 text-xs text-slate-400">
              <div>Directives: {csp.directives?.length || 0}</div>
              {csp.has_unsafe_inline && (
                <div className="text-yellow-400">Contains unsafe-inline</div>
              )}
              {csp.has_unsafe_eval && (
                <div className="text-yellow-400">Contains unsafe-eval</div>
              )}
            </div>
          ) : (
            <p className="text-xs text-slate-500">Content-Security-Policy header not found</p>
          )}
        </Card>

        {/* X-Frame-Options */}
        <Card padding="md" className="border-slate-700/50">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              {x_frame_options ? (
                <Check className="w-4 h-4 text-emerald-400" />
              ) : (
                <X className="w-4 h-4 text-rose-400" />
              )}
              <span className="text-sm font-medium text-slate-200">X-Frame-Options</span>
            </div>
            <Badge variant={x_frame_options ? 'success' : 'error'} size="sm">
              {x_frame_options || 'Missing'}
            </Badge>
          </div>
          {x_frame_options ? (
            <p className="text-xs text-slate-400">Clickjacking protection enabled</p>
          ) : (
            <p className="text-xs text-slate-500">X-Frame-Options header not found</p>
          )}
        </Card>

        {/* X-Content-Type-Options */}
        <Card padding="md" className="border-slate-700/50">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              {x_content_type_options ? (
                <Check className="w-4 h-4 text-emerald-400" />
              ) : (
                <X className="w-4 h-4 text-rose-400" />
              )}
              <span className="text-sm font-medium text-slate-200">X-Content-Type-Options</span>
            </div>
            <Badge variant={x_content_type_options ? 'success' : 'error'} size="sm">
              {x_content_type_options || 'Missing'}
            </Badge>
          </div>
          {x_content_type_options ? (
            <p className="text-xs text-slate-400">MIME sniffing protection enabled</p>
          ) : (
            <p className="text-xs text-slate-500">X-Content-Type-Options header not found</p>
          )}
        </Card>

        {/* Referrer-Policy */}
        <Card padding="md" className="border-slate-700/50">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              {referrer_policy ? (
                <Check className="w-4 h-4 text-emerald-400" />
              ) : (
                <X className="w-4 h-4 text-rose-400" />
              )}
              <span className="text-sm font-medium text-slate-200">Referrer-Policy</span>
            </div>
            <Badge variant={referrer_policy ? 'success' : 'error'} size="sm">
              {referrer_policy || 'Missing'}
            </Badge>
          </div>
          {referrer_policy ? (
            <p className="text-xs text-slate-400">Referrer information controlled</p>
          ) : (
            <p className="text-xs text-slate-500">Referrer-Policy header not found</p>
          )}
        </Card>

        {/* CORS */}
        <Card padding="md" className="border-slate-700/50">
          <div className="flex items-center justify-between mb-3">
            <div className="flex items-center gap-2">
              {cors ? (
                <Check className="w-4 h-4 text-emerald-400" />
              ) : (
                <X className="w-4 h-4 text-slate-500" />
              )}
              <span className="text-sm font-medium text-slate-200">CORS</span>
            </div>
            <Badge variant={cors ? 'info' : 'default'} size="sm">
              {cors ? 'Configured' : 'Not Set'}
            </Badge>
          </div>
          {cors ? (
            <div className="space-y-1 text-xs text-slate-400">
              <div>Allow-Origin: {cors.allow_origin || '*'}</div>
              <div>Credentials: {cors.allow_credentials ? 'Yes' : 'No'}</div>
            </div>
          ) : (
            <p className="text-xs text-slate-500">CORS headers not configured</p>
          )}
        </Card>
      </div>

      {/* Missing Headers */}
      {missing_headers.length > 0 && (
        <Card padding="lg" className="border-rose-900/30 bg-rose-950/10">
          <div className="flex items-center gap-2 text-sm text-rose-400 mb-3">
            <AlertTriangle className="w-4 h-4" />
            <span className="font-medium">Missing Security Headers ({missing_headers.length})</span>
          </div>
          <div className="flex flex-wrap gap-2">
            {missing_headers.map((header, idx) => (
              <Badge key={idx} variant="error" size="sm">
                {header}
              </Badge>
            ))}
          </div>
        </Card>
      )}
    </div>
  )
}

export default SecurityHeaders
