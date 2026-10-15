import React from 'react'
import Card from '../../../../components/Card'
import { FileText } from 'lucide-react'

/**
 * AuthFlowSummary Component
 *
 * Displays a human-readable narrative summary of the authentication flow,
 * generated from HAR analysis, detection results, and run data.
 *
 * This makes AuthRecon's intelligence immediately understandable without
 * requiring manual HAR forensics or timeline analysis.
 */
function AuthFlowSummary({ flowSummary }) {
  // Don't render if no summary available
  if (!flowSummary) {
    return null
  }

  return (
    <Card padding="lg">
      <div className="flex items-start gap-3 mb-4">
        <div className="p-2 rounded-lg bg-slate-800/50">
          <FileText className="w-5 h-5 text-(--accent-blue)" style={{ color: 'var(--accent-blue)' }} />
        </div>
        <div>
          <h3 className="text-lg font-semibold text-slate-50">
            Authentication Flow Summary
          </h3>
          <p className="text-sm text-slate-400 mt-0.5">
            Automatically generated analysis of how this application authenticates
          </p>
        </div>
      </div>

      <div className="prose prose-invert prose-sm max-w-none">
        <p className="text-slate-300 leading-relaxed whitespace-pre-wrap font-mono text-sm">
          {flowSummary}
        </p>
      </div>
    </Card>
  )
}

export default AuthFlowSummary
