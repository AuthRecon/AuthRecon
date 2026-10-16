import React, { useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, CheckCircle2, Copy, FileArchive, Info, RefreshCw, Trash2, Upload, XCircle } from 'lucide-react'
import Header from '../../components/Header'
import Card from '../../components/Card'
import Button from '../../components/Button'
import Badge from '../../components/Badge'
import { copyText } from '../../utils/copyText'
import { deleteScanExport, listScanExports, reanalyzeScanExport, uploadScanExport } from '../../services/scanExportsApi'

const EXPORTS_KEY = ['scan-exports']
const ACCEPT = '.zip,.json,.nessus,.csv,.xml,.har'

function formatBytes(n) {
  if (!n && n !== 0) return '—'
  const units = ['B', 'KB', 'MB', 'GB']
  let i = 0
  let v = n
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1 }
  return `${v.toFixed(i ? 1 : 0)} ${units[i]}`
}

const SEVERITY = {
  critical: { icon: <XCircle className="w-5 h-5 text-rose-400 shrink-0" />, cls: 'border-rose-500/40' },
  warning: { icon: <AlertTriangle className="w-5 h-5 text-amber-400 shrink-0" />, cls: 'border-amber-500/30' },
  info: { icon: <Info className="w-5 h-5 text-slate-400 shrink-0" />, cls: 'border-(--stroke-dark)' },
  ok: { icon: <CheckCircle2 className="w-5 h-5 text-emerald-400 shrink-0" />, cls: 'border-emerald-500/30' },
}

// The order sections appear in the WAS scan configuration.
const SECTIONS = ['Credentials', 'Scope', 'General', 'Limits', 'Performance', 'HTTP Settings', 'Selenium Settings']

function Fact({ label, value, tone }) {
  return (
    <div className="px-3 py-2 rounded-lg bg-(--bg-1) border border-(--stroke-dark)">
      <p className="text-xs uppercase tracking-wide text-slate-500">{label}</p>
      <p className={`text-sm font-semibold ${tone || 'text-slate-100'}`}>{value}</p>
    </div>
  )
}

function CopyButton({ text, label }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      type="button"
      onClick={async () => { if (await copyText(text)) { setCopied(true); setTimeout(() => setCopied(false), 1500) } }}
      className="p-1.5 rounded-lg border border-(--stroke-dark) text-slate-400 hover:text-(--accent-blue)"
      title={`Copy ${label}`}
    >
      {copied ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
    </button>
  )
}

function SettingsToChange({ settings }) {
  const sections = SECTIONS.filter(s => settings?.[s]?.length)
  if (!sections.length) return null
  return (
    <Card padding="lg" className="space-y-4">
      <div>
        <p className="text-xs uppercase tracking-widest text-(--accent-blue)">Settings to change</p>
        <p className="text-sm text-slate-400">Named as in the WAS scan configuration. Change, re-scan, and upload the new export to compare.</p>
      </div>
      {sections.map(section => {
        const rows = settings[section]
        const exclusions = rows.filter(r => r.setting === 'Regex for Excluded URLs').map(r => r.value)
        const others = rows.filter(r => r.setting !== 'Regex for Excluded URLs')
        return (
          <div key={section} className="space-y-2">
            <p className="text-sm font-semibold text-slate-200">{section}</p>
            {exclusions.length > 0 && (
              <div className="space-y-1">
                <div className="flex items-center justify-between">
                  <p className="text-xs text-slate-500">Regex for Excluded URLs (add these lines)</p>
                  <CopyButton text={exclusions.join('\n')} label="exclusions" />
                </div>
                <pre className="px-3 py-2 rounded-lg bg-(--bg-1) border border-(--stroke-dark) text-sm text-slate-200 font-mono whitespace-pre-wrap break-all">{exclusions.join('\n')}</pre>
              </div>
            )}
            {others.length > 0 && (
              <ul className="space-y-1 text-sm">
                {others.map(r => (
                  <li key={`${r.setting}-${r.value}`} className="text-slate-300">
                    <span className="text-slate-100">{r.setting}</span>:{' '}
                    {r.current != null && <span className="font-mono text-slate-500 line-through mr-1">{r.current}</span>}
                    <span className="font-mono text-(--accent-blue)">{r.value}</span>
                    <span className="text-slate-500"> ({r.why})</span>
                  </li>
                ))}
              </ul>
            )}
          </div>
        )
      })}
    </Card>
  )
}

function Analysis({ exp }) {
  const queryClient = useQueryClient()
  const reanalyze = useMutation({
    mutationFn: () => reanalyzeScanExport(exp.id),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: EXPORTS_KEY }),
  })
  const a = exp.summary?.analysis
  const facts = a?.facts || {}
  const auth = facts.authentication
  const reasons = Object.entries(facts.sitemap_reasons || {})

  return (
    <div className="space-y-4">
      <Card padding="lg" className="space-y-4">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0">
            <p className="text-xs uppercase tracking-widest text-(--accent-blue)">Analysis</p>
            <h3 className="text-lg font-semibold text-slate-50 truncate">{exp.filename}</h3>
          </div>
          <Button size="sm" variant="outline" icon={RefreshCw} onClick={() => reanalyze.mutate()} loading={reanalyze.isPending}
            title="Re-read the stored export with the current analyzer">
            Re-analyze
          </Button>
        </div>
        {!a ? (
          <p className="text-sm text-slate-400">This export was uploaded before the analyzer existed. Click Re-analyze.</p>
        ) : !a.recognised ? (
          <div className="text-sm text-slate-300 space-y-1">
            <p>No WAS findings, sitemap or scan traffic were recognised in this upload.</p>
            <p className="text-slate-500">
              Upload the scan's JSON export (it includes the scan settings) and/or its debug .zip.
              Files read: {(facts.files_read || []).join(', ') || 'none'}
              {facts.files_skipped?.length > 0 && `; skipped: ${facts.files_skipped.join(', ')}`}.
            </p>
          </div>
        ) : (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
            <Fact label="Authentication" value={auth === 'failed' ? 'Failed' : auth === 'succeeded' ? 'Succeeded' : 'Unknown'}
              tone={auth === 'failed' ? 'text-rose-300' : auth === 'succeeded' ? 'text-emerald-300' : undefined} />
            <Fact label="Findings read" value={facts.findings ?? 0} />
            <Fact label="Sitemap URLs" value={facts.sitemap_urls ?? 0} />
            <Fact label="Scan requests (debug)" value={facts.http?.requests ?? '—'} />
          </div>
        )}
        {reasons.length > 0 && (
          <p className="text-xs text-slate-500">
            Sitemap: {reasons.map(([r, n]) => `${r} ${n}`).join(' · ')}
          </p>
        )}
      </Card>

      {a?.recommendations?.length > 0 && (
        <Card padding="lg" className="space-y-3">
          <p className="text-xs uppercase tracking-widest text-(--accent-blue)">What happened</p>
          {a.recommendations.map(r => {
            const sev = SEVERITY[r.severity] || SEVERITY.info
            return (
              <div key={r.id} className={`p-3 rounded-lg border bg-(--bg-2) ${sev.cls}`}>
                <div className="flex gap-3">
                  {sev.icon}
                  <div className="min-w-0 space-y-1">
                    <p className="text-sm font-semibold text-slate-100">{r.title}</p>
                    <p className="text-sm text-slate-400">{r.detail}</p>
                    {r.evidence?.length > 0 && (
                      <p className="text-xs text-slate-500 font-mono break-all">{r.evidence.join(' · ')}</p>
                    )}
                  </div>
                </div>
              </div>
            )
          })}
        </Card>
      )}

      {a && <SettingsToChange settings={a.settings} />}
    </div>
  )
}

/**
 * Scan Analyzer: upload a Tenable WAS scan's debug .zip and/or its JSON export
 * (or .nessus / CSV); deterministic rules (backend services/scan_analysis.py)
 * explain what went wrong and which settings to change. No AI needed; a
 * connected MCP client can read the same analysis.
 */
function ScanAnalyzer() {
  const queryClient = useQueryClient()
  const fileInput = useRef(null)
  const [uploadError, setUploadError] = useState(null)
  const [selected, setSelected] = useState(null)

  const { data: exports = [], isLoading } = useQuery({ queryKey: EXPORTS_KEY, queryFn: listScanExports })
  const upload = useMutation({
    mutationFn: uploadScanExport,
    onSuccess: (created) => {
      setUploadError(null)
      setSelected(created?.id || null)
      queryClient.invalidateQueries({ queryKey: EXPORTS_KEY })
    },
    onError: (err) => setUploadError(err.response?.data?.detail || 'Upload failed'),
  })
  const remove = useMutation({
    mutationFn: deleteScanExport,
    onSuccess: () => queryClient.invalidateQueries({ queryKey: EXPORTS_KEY }),
  })

  const onPick = (e) => {
    const file = e.target.files?.[0]
    if (file) upload.mutate(file)
    e.target.value = ''
  }
  const current = exports.find(x => x.id === selected) || exports[0]

  return (
    <div className="flex-1 overflow-y-auto">
      <Header title="Scan Analyzer" subtitle="Find out why a Tenable WAS scan went wrong, and what to change (preview)" />
      <div className="p-6 space-y-6 max-w-6xl mx-auto">
        <div className="px-4 py-3 rounded-lg border border-amber-500/40 bg-amber-500/10 text-sm text-amber-200">
          <span className="font-semibold">Preview, under light development.</span> The analyzer is built from Tenable's
          documented plugins and has not yet been tuned on many real exports. Treat its suggestions as a checklist to
          review, not settings to apply blindly.
        </div>
        <Card padding="lg" className="space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h3 className="text-lg font-semibold text-slate-50">Scan exports</h3>
              <p className="text-sm text-slate-400">
                Upload the scan's debug <code>.zip</code> and/or its <code>.json</code> export (it includes the scan settings,
                so suggestions show current → new). <code>.nessus</code> and <code>.csv</code> work too. Up to 200 MB.
              </p>
            </div>
            <div>
              <input ref={fileInput} type="file" accept={ACCEPT} className="hidden" onChange={onPick} />
              <Button onClick={() => fileInput.current?.click()} disabled={upload.isPending}>
                <Upload className="w-4 h-4 mr-2" />
                {upload.isPending ? 'Uploading…' : 'Upload export'}
              </Button>
            </div>
          </div>
          {uploadError && <p className="text-sm text-rose-300">{uploadError}</p>}

          {isLoading ? (
            <p className="text-sm text-slate-400">Loading…</p>
          ) : exports.length === 0 ? (
            <p className="text-sm text-slate-500 py-6 text-center">No exports uploaded yet.</p>
          ) : (
            <ul className="divide-y divide-slate-800">
              {exports.map((e) => {
                const recs = e.summary?.analysis?.recommendations || []
                const critical = recs.filter(r => r.severity === 'critical').length
                const warnings = recs.filter(r => r.severity === 'warning').length
                return (
                  <li key={e.id} className={`py-3 flex items-center gap-4 cursor-pointer ${current?.id === e.id ? 'bg-(--bg-2)' : ''}`}
                    onClick={() => setSelected(e.id)}>
                    <FileArchive className="w-5 h-5 text-slate-400 shrink-0 ml-2" />
                    <div className="flex-1 min-w-0">
                      <p className="text-sm text-slate-100 truncate">{e.filename}</p>
                      <p className="text-xs text-slate-500">
                        {new Date(e.created_at).toLocaleString()} · {formatBytes(e.size_bytes)}
                      </p>
                    </div>
                    {critical > 0 && <Badge variant="error">{critical} critical</Badge>}
                    {warnings > 0 && <Badge variant="warning">{warnings} warnings</Badge>}
                    {!critical && !warnings && <Badge variant={e.status === 'parsed' ? 'success' : 'default'}>{e.status}</Badge>}
                    <button
                      type="button"
                      className="p-2 text-slate-500 hover:text-rose-300"
                      title="Delete export"
                      onClick={(ev) => { ev.stopPropagation(); if (window.confirm(`Delete ${e.filename}?`)) remove.mutate(e.id) }}
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </li>
                )
              })}
            </ul>
          )}
          <p className="text-xs text-slate-500">
            Exports are encrypted at rest. The analysis never includes plugin output or query strings, so it is safe to
            share with an AI client over MCP (get_scan_export_summary); no AI is needed to use it.
          </p>
        </Card>

        {current && <Analysis exp={current} />}
      </div>
    </div>
  )
}

export default ScanAnalyzer
