import React, { useState } from 'react'
import { AlertTriangle, CheckCircle2, Copy, Info, XCircle } from 'lucide-react'
import { copyText } from '../../../utils/copyText'

// Scan readiness (backend: services/scan_readiness.py): a grade for how well
// this login will scan, and starting settings named as they appear in the WAS
// scan configuration. A starting point: the scan-export analyzer refines it.

const GRADE = {
  good: { label: 'Good scan candidate', cls: 'border-emerald-500/40 bg-emerald-500/10 text-emerald-200' },
  caution: { label: 'Usable, with caveats', cls: 'border-amber-500/40 bg-amber-500/10 text-amber-200' },
  poor: { label: 'Likely to scan poorly', cls: 'border-rose-500/40 bg-rose-500/10 text-rose-200' },
}

const ICON = {
  ok: <CheckCircle2 className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />,
  warn: <AlertTriangle className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />,
  bad: <XCircle className="w-4 h-4 text-rose-400 shrink-0 mt-0.5" />,
  info: <Info className="w-4 h-4 text-slate-400 shrink-0 mt-0.5" />,
}

function CopyBlock({ label, lines, hint }) {
  const [copied, setCopied] = useState(false)
  if (!lines?.length) return null
  const text = lines.join('\n')
  return (
    <div className="space-y-1">
      <div className="flex items-center justify-between gap-2">
        <p className="text-xs uppercase tracking-wide text-slate-500">{label}</p>
        <button
          type="button"
          onClick={async () => { if (await copyText(text)) { setCopied(true); setTimeout(() => setCopied(false), 1500) } }}
          className="p-1.5 rounded-lg border border-(--stroke-dark) text-slate-400 hover:text-(--accent-blue)"
          title={`Copy ${label.toLowerCase()}`}
        >
          {copied ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
        </button>
      </div>
      <pre className="px-3 py-2 rounded-lg bg-(--bg-1) border border-(--stroke-dark) text-sm text-slate-200 font-mono whitespace-pre-wrap break-all">{text}</pre>
      {hint && <p className="text-xs text-slate-500">{hint}</p>}
    </div>
  )
}

function SettingRows({ title, rows }) {
  if (!rows?.length) return null
  return (
    <div className="space-y-1">
      <p className="text-xs uppercase tracking-wide text-slate-500">{title}</p>
      <ul className="space-y-1 text-sm">
        {rows.map(r => (
          <li key={r.setting} className="text-slate-300">
            <span className="text-slate-100">{r.setting}</span>: <span className="font-mono text-(--accent-blue)">{r.value}</span>
            <span className="text-slate-500"> ({r.why})</span>
          </li>
        ))}
      </ul>
    </div>
  )
}

function ScanReadiness({ readiness }) {
  if (!readiness) return null
  const grade = GRADE[readiness.grade] || GRADE.caution
  const s = readiness.settings || {}
  const scope = s.scope || {}
  const session = s.session || {}
  const sessionRows = [
    session.cookie && { setting: 'Cookie', value: session.cookie, why: 'the session cookie; lets the scanner skip token checks' },
    session.header && { setting: 'Header', value: session.header, why: 'API calls carry a bearer token in this header' },
  ].filter(Boolean)
  const exclusions = (scope.exclude_regex || []).map(e => e.regex)

  return (
    <div className="mt-6 pt-5 border-t border-(--stroke-dark) space-y-4">
      <div>
        <p className="text-xs uppercase tracking-widest text-(--accent-blue)">Scan readiness</p>
        <div className={`mt-2 px-3 py-2 rounded-lg border text-sm ${grade.cls}`}>
          <span className="font-semibold">{grade.label}.</span> {readiness.summary}
        </div>
      </div>

      {readiness.checks?.length > 0 && (
        <ul className="space-y-2">
          {readiness.checks.map(c => (
            <li key={c.id} className="flex gap-2 text-sm">
              {ICON[c.status] || ICON.info}
              <div>
                <p className="text-slate-200">{c.title}</p>
                <p className="text-slate-400">{c.detail}</p>
              </div>
            </li>
          ))}
        </ul>
      )}

      <div className="space-y-4">
        <p className="text-xs uppercase tracking-widest text-(--accent-blue)">Starting scan settings</p>
        <CopyBlock label="Scope › Regex for Excluded URLs (add to the default “logout”)" lines={exclusions}
          hint={(scope.exclude_regex || []).map(e => `${e.regex}: ${e.why}`).join(' · ')} />
        <CopyBlock label="Scope › List of URLs" lines={scope.include_urls}
          hint="Seed the crawl with the post-login landing page." />
        {scope.additional_targets?.length > 0 && (
          <SettingRows title="Other hosts the app called (scan separately if they are its API)"
            rows={scope.additional_targets.map(t => ({ setting: t.host, value: `${t.requests} requests`, why: 'skipped as not_in_domain' }))} />
        )}
        <SettingRows title="Advanced › Session Settings" rows={sessionRows} />
        <SettingRows title="Advanced › Performance" rows={s.performance} />
        <SettingRows title="Advanced › Selenium Settings" rows={s.selenium} />
        <p className="text-xs text-slate-500">
          A starting point from one login: a scan can hit things a login never shows. Upload the scan's export to
          the Scan Analyzer afterwards to tune it.
        </p>
      </div>
    </div>
  )
}

export default ScanReadiness
