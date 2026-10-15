import React from 'react'
import Card from '../../../../components/Card'
import Badge from '../../../../components/Badge'

function TechFingerprint({ techFingerprint, jsFrameworks }) {
  if (!techFingerprint && (!jsFrameworks || jsFrameworks.length === 0)) {
    return null // Don't show if no tech data
  }

  const fp = techFingerprint || {}
  const allFrameworks = jsFrameworks || fp.js_frameworks || []

  const hasTechData = fp.server || fp.powered_by || allFrameworks.length > 0 ||
                      (fp.js_libraries && fp.js_libraries.length > 0) ||
                      (fp.cms && fp.cms.length > 0) ||
                      (fp.security_headers && fp.security_headers.length > 0)

  if (!hasTechData) {
    return null
  }

  const renderSection = (title, items, variant = 'default') => {
    if (!items || items.length === 0) return null

    return (
      <div>
        <p className="text-sm text-slate-500 mb-2">{title} ({items.length})</p>
        <div className="flex flex-wrap gap-2">
          {items.map((item, idx) => (
            <Badge key={idx} variant={variant}>
              {item}
            </Badge>
          ))}
        </div>
      </div>
    )
  }

  return (
    <Card padding="lg">
      <h3 className="text-lg font-semibold text-slate-50 mb-4">
        Technology Fingerprint
      </h3>

      <div className="space-y-4">
        {/* Server Info */}
        {fp.server && (
          <div>
            <p className="text-sm text-slate-500 mb-2">Web Server</p>
            <div className="p-3 rounded-lg bg-slate-900/50 border border-slate-800">
              <p className="text-sm text-slate-300 font-mono">{fp.server}</p>
            </div>
          </div>
        )}

        {/* Powered By */}
        {fp.powered_by && (
          <div>
            <p className="text-sm text-slate-500 mb-2">Powered By</p>
            <div className="p-3 rounded-lg bg-slate-900/50 border border-slate-800">
              <p className="text-sm text-slate-300 font-mono">{fp.powered_by}</p>
            </div>
          </div>
        )}

        {/* JavaScript Frameworks */}
        {renderSection('JavaScript Frameworks', allFrameworks, 'info')}

        {/* JavaScript Libraries */}
        {renderSection('JavaScript Libraries', fp.js_libraries, 'default')}

        {/* CMS */}
        {renderSection('Content Management System', fp.cms, 'success')}

        {/* Meta Generators */}
        {renderSection('Meta Generators', fp.meta_generators, 'default')}

        {/* Security Headers */}
        {fp.security_headers && fp.security_headers.length > 0 && (
          <div>
            <p className="text-sm text-slate-500 mb-2">Security Headers ({fp.security_headers.length})</p>
            <div className="flex flex-wrap gap-2">
              {fp.security_headers.map((header, idx) => (
                <Badge key={idx} variant="success">
                  {header}
                </Badge>
              ))}
            </div>
          </div>
        )}

        {/* Cookies */}
        {renderSection('Cookies', fp.cookies, 'default')}

        {/* Auth Cookies */}
        {fp.auth_cookies && fp.auth_cookies.length > 0 && (
          <div>
            <p className="text-sm text-slate-500 mb-2">Authentication Cookies ({fp.auth_cookies.length})</p>
            <div className="flex flex-wrap gap-2">
              {fp.auth_cookies.map((cookie, idx) => (
                <Badge key={idx} variant="info">
                  {cookie}
                </Badge>
              ))}
            </div>
          </div>
        )}

        {/* Observations */}
        {fp.observations && fp.observations.length > 0 && (
          <div>
            <p className="text-sm text-slate-500 mb-2">Observations</p>
            <div className="space-y-2">
              {fp.observations.map((obs, idx) => (
                <div key={idx} className="p-3 rounded-lg bg-slate-900/50 border border-slate-800">
                  <p className="text-sm text-slate-300">{obs}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Headers (if available) */}
        {fp.headers && Object.keys(fp.headers).length > 0 && (
          <div>
            <p className="text-sm text-slate-500 mb-2">HTTP Headers</p>
            <div className="space-y-1 max-h-60 overflow-y-auto scrollbar-thin">
              {Object.entries(fp.headers).map(([key, value]) => (
                <div key={key} className="flex items-start gap-2 text-xs">
                  <span className="text-(--accent-blue) font-mono font-medium min-w-[140px]">{key}:</span>
                  <span className="text-slate-400 font-mono flex-1 break-all">{value}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </Card>
  )
}

export default TechFingerprint
