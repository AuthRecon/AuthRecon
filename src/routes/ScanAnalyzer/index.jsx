import React, { useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { FileArchive, PlugZap, Trash2, Upload } from 'lucide-react'
import Header from '../../components/Header'
import Card from '../../components/Card'
import Button from '../../components/Button'
import Badge from '../../components/Badge'
import { useAiStatus } from '../../services/useAiStatus'
import { deleteScanExport, listScanExports, uploadScanExport } from '../../services/scanExportsApi'

const EXPORTS_KEY = ['scan-exports']

function formatBytes(n) {
  if (!n && n !== 0) return '—'
  const units = ['B', 'KB', 'MB', 'GB']
  let i = 0
  let v = n
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1 }
  return `${v.toFixed(i ? 1 : 0)} ${units[i]}`
}

/**
 * Scan Analyzer (working name) — SCAFFOLD.
 *
 * Upload a Tenable WAS scan export; a connected AI client (over MCP) reads the
 * parsed summary via list_scan_exports / get_scan_export_summary to help fix
 * scan problems such as timeouts, needed exclusions and scan breakdowns.
 * TODO(scan-analyzer): show parsed findings and the AI's suggestions here.
 */
function ScanAnalyzer() {
  const queryClient = useQueryClient()
  const fileInput = useRef(null)
  const [uploadError, setUploadError] = useState(null)
  const { data: ai } = useAiStatus()
  const aiReady = Boolean(ai?.mcp_enabled)

  const { data: exports = [], isLoading } = useQuery({ queryKey: EXPORTS_KEY, queryFn: listScanExports })
  const upload = useMutation({
    mutationFn: uploadScanExport,
    onSuccess: () => { setUploadError(null); queryClient.invalidateQueries({ queryKey: EXPORTS_KEY }) },
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

  return (
    <div className="flex-1 overflow-y-auto">
      <Header title="Scan Analyzer" subtitle="Tenable WAS scan export analysis (preview)" />
      <div className="p-6 space-y-6 max-w-6xl mx-auto">
        <Card padding="lg">
          <div className="flex items-start gap-3">
            <PlugZap className={`w-5 h-5 mt-0.5 ${aiReady ? 'text-emerald-400' : 'text-slate-500'}`} />
            <div className="text-sm">
              {aiReady ? (
                <p className="text-slate-200">
                  An AI client can connect. Upload an export, then ask your AI client to analyze it: it uses the
                  <code className="mx-1">list_scan_exports</code> and <code className="mx-1">get_scan_export_summary</code> MCP tools.
                </p>
              ) : (
                <p className="text-slate-300">
                  This feature works through a connected AI client (MCP). Uploads are stored now, but analysis needs an
                  AI client: <Link to="/settings?tab=ai" className="text-[var(--accent-blue)] hover:underline">Settings › AI &amp; MCP</Link>.
                </p>
              )}
              <p className="text-xs text-slate-500 mt-1">
                Exports are encrypted at rest and never handed to the AI as a raw file; it only sees the parsed summary.
              </p>
            </div>
          </div>
        </Card>

        <Card padding="lg" className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-lg font-semibold text-slate-50">Scan exports</h3>
              <p className="text-sm text-slate-400">Upload a Tenable WAS scan export (.zip, up to 200 MB).</p>
            </div>
            <div>
              <input ref={fileInput} type="file" accept=".zip,application/zip" className="hidden" onChange={onPick} />
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
              {exports.map((e) => (
                <li key={e.id} className="py-3 flex items-center gap-4">
                  <FileArchive className="w-5 h-5 text-slate-400 flex-shrink-0" />
                  <div className="flex-1 min-w-0">
                    <p className="text-sm text-slate-100 truncate">{e.filename}</p>
                    <p className="text-xs text-slate-500">
                      {new Date(e.created_at).toLocaleString()} · {formatBytes(e.size_bytes)}
                      {e.summary?.file_count != null && ` · ${e.summary.file_count} files`}
                    </p>
                  </div>
                  <Badge variant={e.status === 'parsed' ? 'success' : e.status === 'failed' ? 'error' : 'default'}>
                    {e.status}
                  </Badge>
                  <button
                    type="button"
                    className="p-2 text-slate-500 hover:text-rose-300"
                    title="Delete export"
                    onClick={() => { if (window.confirm(`Delete ${e.filename}?`)) remove.mutate(e.id) }}
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </li>
              ))}
            </ul>
          )}
        </Card>
      </div>
    </div>
  )
}

export default ScanAnalyzer
