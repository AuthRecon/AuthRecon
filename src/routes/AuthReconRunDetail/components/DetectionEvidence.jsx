import React from 'react'
import Card from '../../../components/Card'
import Badge from '../../../components/Badge'
import { describeDetectionError } from '../../../utils/detectionStatus'

function DetectionEvidence({ run }) {
  const detection = run.detected_auth || {}
  const authType = run.auth_type || detection.auth_type || 'unknown'
  const evidence = detection.evidence
  const detectionError = detection.error
  const detectionNotice = describeDetectionError(run)
  const finalUrl = run.final_url || detection.pre_login_url
  const pattern = run.pattern
  const llmPattern = run.llm_pattern
  const sessionCookies = run.session_cookies || []
  const displayCookies = sessionCookies.map(cookie => {
    if (typeof cookie === 'string') return cookie
    if (cookie && cookie.name) return cookie.name
    return '(unnamed cookie)'
  })

  return (
    <Card padding="lg">
      <h3 className="text-lg font-semibold text-slate-50 mb-4">
        Detection Evidence
      </h3>

      <div className="space-y-4">
        {/* Pre-run probe error on a run that didn't fail: small amber note */}
        {detectionNotice && detectionNotice.severity === 'warning' && (
          <div className="p-3 rounded-lg bg-amber-950/20 border border-amber-900/40">
            <p className="text-xs font-semibold text-amber-300">{detectionNotice.title}</p>
            <p className="mt-1 text-xs text-amber-200/80 font-mono break-all">{detectionNotice.detail}</p>
          </div>
        )}

        {/* Detection Error: red only when the run actually failed */}
        {detectionNotice && detectionNotice.severity === 'error' && (
          <div className="p-4 rounded-lg bg-red-950/30 border-2 border-red-900/50">
            <div className="flex items-start gap-3">
              <svg className="w-5 h-5 text-red-400 flex-shrink-0 mt-0.5" fill="currentColor" viewBox="0 0 20 20">
                <path fillRule="evenodd" d="M10 18a8 8 0 100-16 8 8 0 000 16zM8.707 7.293a1 1 0 00-1.414 1.414L8.586 10l-1.293 1.293a1 1 0 101.414 1.414L10 11.414l1.293 1.293a1 1 0 001.414-1.414L11.414 10l1.293-1.293a1 1 0 00-1.414-1.414L10 8.586 8.707 7.293z" clipRule="evenodd" />
              </svg>
              <div className="flex-1">
                <p className="text-sm font-semibold text-red-300 mb-2">Detection Failed</p>
                <p className="text-sm text-red-200 font-mono leading-relaxed">{detectionError}</p>
                {detectionError.includes('Connection refused') && (
                  <div className="mt-3 p-3 rounded bg-red-900/20 border border-red-800/30">
                    <p className="text-xs text-red-300 font-semibold mb-1">💡 Common Issue:</p>
                    <p className="text-xs text-red-200">
                      If targeting a local service like LoginLab, use the internal Docker network URL:
                      <br/>
                      <code className="text-red-300 bg-red-950/50 px-1 py-0.5 rounded">http://loginlab:5000/...</code> instead of <code className="text-red-300 bg-red-950/50 px-1 py-0.5 rounded">http://localhost:5100/...</code>
                    </p>
                  </div>
                )}
              </div>
            </div>
          </div>
        )}

        {/* Auth Type */}
        <div>
          <p className="text-sm text-slate-500 mb-2">Authentication Type</p>
          <Badge variant={authType === 'unknown' ? 'warning' : 'form_based'} className="text-base">
            {authType.replace(/_/g, ' ')}
          </Badge>
        </div>

        {/* Pattern */}
        {pattern && (
          <div>
            <p className="text-sm text-slate-500 mb-2">Detected Pattern</p>
            <div className="p-3 rounded-lg bg-slate-900/50 border border-slate-800">
              <p className="text-sm text-slate-300 font-mono">{pattern}</p>
            </div>
          </div>
        )}

        {/* LLM Pattern Analysis */}
        {llmPattern && (
          <div>
            <p className="text-sm text-slate-500 mb-2">Pattern Analysis (LLM)</p>
            <div className="p-3 rounded-lg bg-[var(--sidebar-active-bg)] border border-[var(--stroke-blue)]">
              <p className="text-sm text-[var(--text-primary)]">{llmPattern}</p>
            </div>
          </div>
        )}

        {/* Evidence */}
        {evidence && (
          <div>
            <p className="text-sm text-slate-500 mb-2">Evidence</p>
            <div className="p-3 rounded-lg bg-slate-900/50 border border-slate-800">
              <p className="text-sm text-slate-300">{evidence}</p>
            </div>
          </div>
        )}

        {/* Final URL */}
        {finalUrl && (
          <div>
            <p className="text-sm text-slate-500 mb-2">Final URL</p>
            <div className="p-3 rounded-lg bg-slate-900/50 border border-slate-800">
              <p className="text-sm text-slate-300 font-mono break-all">{finalUrl}</p>
            </div>
          </div>
        )}

        {/* Session Cookies */}
        {sessionCookies && sessionCookies.length > 0 && (
          <div>
            <p className="text-sm text-slate-500 mb-2">Session Cookies ({sessionCookies.length})</p>
            <div className="flex flex-wrap gap-2">
              {displayCookies.map((cookie, idx) => (
                <Badge key={idx} variant="success">
                  {cookie}
                </Badge>
              ))}
            </div>
          </div>
        )}

        {/* No Detection Data */}
        {!authType && !pattern && !evidence && sessionCookies.length === 0 && (
          <div className="py-4 text-center">
            <p className="text-sm text-slate-400">
              Detection details not available for this run
            </p>
          </div>
        )}
      </div>
    </Card>
  )
}

export default DetectionEvidence
