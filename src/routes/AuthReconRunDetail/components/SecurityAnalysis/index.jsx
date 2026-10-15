import React from 'react'
import Card from '../../../../components/Card'
import Badge from '../../../../components/Badge'
import { Shield, Cookie, FileText, FileCode } from 'lucide-react'
import CookieAnalysis from './CookieAnalysis'
import SecurityHeaders from './SecurityHeaders'
import JSSecrets from './JSSecrets'

function SecurityAnalysis({ securityContext }) {
  if (!securityContext) {
    return (
      <Card padding="lg" className="border-slate-700/50">
        <div className="text-center py-12">
          <Shield className="w-16 h-16 text-slate-600 mx-auto mb-4" />
          <h3 className="text-lg font-semibold text-slate-300 mb-2">
            No Security Context Available
          </h3>
          <p className="text-sm text-slate-500">
            Security analysis data was not captured for this run.
          </p>
          <p className="text-xs text-slate-600 mt-2">
            (Available in AuthRecon v1.1+)
          </p>
        </div>
      </Card>
    )
  }

  const {
    cookies,
    security_headers,
    overall_security_score,
    extraction_version,
  } = securityContext

  const getScoreVariant = (score) => {
    if (score >= 80) return 'success'
    if (score >= 60) return 'warning'
    return 'error'
  }

  const getScoreColor = (score) => {
    if (score >= 80) return 'text-emerald-400'
    if (score >= 60) return 'text-yellow-400'
    return 'text-rose-400'
  }

  const cookieScore = cookies?.security_score || 0
  const headerScore = security_headers?.security?.security_score || 0

  return (
    <div className="space-y-6">
      {/* Overall Security Score */}
      <Card padding="lg" className="border-slate-700/50 bg-linear-to-br from-slate-800/30 to-slate-900/20">
        <div className="flex items-center justify-between mb-6">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <Shield className="w-6 h-6" style={{ color: 'var(--accent-blue)' }} />
              <h3 className="text-xl font-semibold text-slate-50">Overall Security Score</h3>
            </div>
            <p className="text-sm text-slate-400">
              Weighted analysis of cookies (40%) and security headers (60%)
            </p>
          </div>
          <div className="text-right">
            <div className={`text-5xl font-bold ${getScoreColor(overall_security_score)} mb-2`}>
              {Math.round(overall_security_score)}
            </div>
            <Badge variant={getScoreVariant(overall_security_score)} size="lg">
              {overall_security_score >= 80 ? 'Secure' : overall_security_score >= 60 ? 'Fair' : 'Needs Work'}
            </Badge>
          </div>
        </div>

        {/* Score Breakdown */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 pt-6 border-t border-slate-700/30">
          <div className="flex items-center justify-between p-4 bg-slate-800/30 rounded-lg">
            <div className="flex items-center gap-3">
              <Cookie className="w-5 h-5 text-slate-400" />
              <div>
                <p className="text-sm font-medium text-slate-200">Cookie Security</p>
                <p className="text-xs text-slate-500">40% weight</p>
              </div>
            </div>
            <div className="text-right">
              <div className={`text-2xl font-bold ${getScoreColor(cookieScore)}`}>
                {Math.round(cookieScore)}
              </div>
              <p className="text-xs text-slate-500">/100</p>
            </div>
          </div>

          <div className="flex items-center justify-between p-4 bg-slate-800/30 rounded-lg">
            <div className="flex items-center gap-3">
              <FileText className="w-5 h-5 text-slate-400" />
              <div>
                <p className="text-sm font-medium text-slate-200">Security Headers</p>
                <p className="text-xs text-slate-500">60% weight</p>
              </div>
            </div>
            <div className="text-right">
              <div className={`text-2xl font-bold ${getScoreColor(headerScore)}`}>
                {Math.round(headerScore)}
              </div>
              <p className="text-xs text-slate-500">/100</p>
            </div>
          </div>
        </div>

        {/* Extraction Version */}
        {extraction_version && (
          <div className="mt-4 pt-4 border-t border-slate-700/30">
            <p className="text-xs text-slate-500">
              Extraction Version: {extraction_version}
            </p>
          </div>
        )}
      </Card>

      {/* Cookie Analysis Section */}
      <div className="space-y-3">
        <div className="flex items-center gap-3">
          <Cookie className="w-5 h-5" style={{ color: 'var(--accent-blue)' }} />
          <h3 className="text-lg font-semibold text-slate-50">Cookie Analysis</h3>
        </div>
        <CookieAnalysis cookieData={cookies} />
      </div>

      {/* Security Headers Section */}
      <div className="space-y-3">
        <div className="flex items-center gap-3">
          <FileText className="w-5 h-5" style={{ color: 'var(--accent-blue)' }} />
          <h3 className="text-lg font-semibold text-slate-50">Security Headers</h3>
        </div>
        <SecurityHeaders headersData={security_headers} />
      </div>

      {/* JavaScript Secrets Section */}
      <div className="space-y-3">
        <div className="flex items-center gap-3">
          <FileCode className="w-5 h-5" style={{ color: 'var(--accent-blue)' }} />
          <h3 className="text-lg font-semibold text-slate-50">JavaScript Secrets Scanner</h3>
        </div>
        <JSSecrets jsSecretsData={securityContext} />
      </div>
    </div>
  )
}

export default SecurityAnalysis
