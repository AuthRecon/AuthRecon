import React from 'react'
import Card from '../../../components/Card'
import Badge from '../../../components/Badge'

/**
 * Shows every AI-suggested auth pattern recorded against this run — not
 * just whichever one succeeded (that at-a-glance summary lives in
 * DetectionEvidence's "Pattern Analysis (LLM)" card). This is the full
 * "to what extent was AI used, and with what content" view: every
 * suggestion's auth type, selectors, confidence, and reasoning, including
 * ones that were never acted on or that were tried and failed.
 *
 * Only rendered when run.ai_suggestions is non-empty, so a normal run
 * that never needed AI assistance shows nothing extra at all.
 */
function AIAssistance({ run }) {
  const suggestions = run.ai_suggestions || []
  if (suggestions.length === 0) return null

  return (
    <Card padding="lg" className="border-(--stroke-blue)">
      <div className="flex items-center gap-2 mb-4">
        <h3 className="text-lg font-semibold text-slate-50">AI Assistance</h3>
        <Badge variant="info" size="sm">{suggestions.length} suggestion{suggestions.length !== 1 ? 's' : ''}</Badge>
      </div>
      <p className="text-sm text-slate-400 mb-4">
        Selector suggestions recorded for this run when the rule-based pattern library
        couldn't confidently classify the login flow. The suggesting model never saw a
        real credential value — only sanitized page HTML — and the credential injection
        itself was always done by AuthRecon's own deterministic code, not the model.
      </p>

      <div className="space-y-3">
        {suggestions.map((s, idx) => (
          <div
            key={idx}
            className="p-4 rounded-lg bg-(--sidebar-active-bg) border border-(--stroke-blue)"
          >
            <div className="flex flex-wrap items-center gap-2 mb-2">
              <Badge variant="sky">{(s.auth_type || 'unknown').replace(/_/g, ' ')}</Badge>
              {typeof s.confidence === 'number' && (
                <Badge variant={s.confidence >= 0.7 ? 'success' : 'warning'} size="sm">
                  {Math.round(s.confidence * 100)}% confidence
                </Badge>
              )}
              {s.submitted_at && (
                <span className="text-xs text-slate-500 ml-auto">
                  {new Date(s.submitted_at).toLocaleString()}
                </span>
              )}
            </div>

            {s.reasoning && (
              <p className="text-sm text-(--text-primary) mb-3">{s.reasoning}</p>
            )}

            <div className="grid grid-cols-1 sm:grid-cols-3 gap-2 text-xs font-mono">
              {s.username_selector && (
                <div className="p-2 rounded-sm bg-slate-900/50 border border-slate-800">
                  <span className="text-slate-500 block mb-1">username</span>
                  <span className="text-slate-300 break-all">{s.username_selector}</span>
                </div>
              )}
              {s.password_selector && (
                <div className="p-2 rounded-sm bg-slate-900/50 border border-slate-800">
                  <span className="text-slate-500 block mb-1">password</span>
                  <span className="text-slate-300 break-all">{s.password_selector}</span>
                </div>
              )}
              {s.submit_selector && (
                <div className="p-2 rounded-sm bg-slate-900/50 border border-slate-800">
                  <span className="text-slate-500 block mb-1">submit</span>
                  <span className="text-slate-300 break-all">{s.submit_selector}</span>
                </div>
              )}
            </div>
          </div>
        ))}
      </div>
    </Card>
  )
}

export default AIAssistance
