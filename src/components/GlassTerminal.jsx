import React, { useEffect, useRef, useState } from 'react'
import { Copy, Minimize2, Maximize2 } from 'lucide-react'

const logColor = (line = '') => {
  if (/error|fail/i.test(line)) return 'text-rose-300'
  if (/success|ok/i.test(line)) return 'text-emerald-300'
  if (/action|request|post|get/i.test(line)) return 'text-sky-200'
  return 'text-slate-300'
}

function GlassTerminal({
  logs = [],
  expanded = false,
  onToggleExpand = () => {},
  onClose = () => {},
}) {
  const [autoScroll, setAutoScroll] = useState(true)
  const scrollRef = useRef(null)

  useEffect(() => {
    if (autoScroll && scrollRef.current) {
      scrollRef.current.scrollTop = scrollRef.current.scrollHeight
    }
  }, [logs, autoScroll])

  const copyLogs = async () => {
    try {
      await navigator.clipboard.writeText(logs.join('\n'))
    } catch (error) {
      console.error('Failed to copy logs', error)
    }
  }

  return (
    <div
      className={`fixed right-8 z-40 rounded-3xl border border-sky-500/40 bg-slate-950/90 backdrop-blur-2xl shadow-2xl transition-all duration-300 ${
        expanded ? 'bottom-8 w-[90vw] left-1/2 -translate-x-1/2 h-[40vh]' : 'bottom-8 w-96'
      }`}
    >
      <div className="flex items-center justify-between px-4 py-3 border-b border-slate-800/60 text-xs text-slate-300">
        <div className="flex items-center gap-3">
          <span className="font-semibold tracking-wide">Glass Terminal</span>
          <label className="flex items-center gap-1 text-[11px] text-slate-400">
            <input
              type="checkbox"
              checked={autoScroll}
              onChange={(e) => setAutoScroll(e.target.checked)}
              className="rounded bg-slate-900 text-sky-500 focus:ring-sky-500 focus:ring-offset-slate-900"
            />
            Follow output
          </label>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={copyLogs}
            className="p-1 rounded-full hover:bg-slate-800 text-slate-400 hover:text-slate-100"
            title="Copy all logs"
          >
            <Copy className="w-4 h-4" />
          </button>
          <button
            onClick={onToggleExpand}
            className="p-1 rounded-full hover:bg-slate-800 text-slate-400 hover:text-slate-100"
            title={expanded ? 'Collapse terminal' : 'Expand terminal'}
          >
            {expanded ? <Minimize2 className="w-4 h-4" /> : <Maximize2 className="w-4 h-4" />}
          </button>
          <button
            onClick={onClose}
            className="px-2 py-1 rounded-full border border-slate-700/70 hover:text-slate-50"
          >
            Close
          </button>
        </div>
      </div>

      <div
        ref={scrollRef}
        className="p-4 font-mono text-[11px] text-slate-200 max-h-[60vh] overflow-y-auto space-y-1"
      >
        {logs.length === 0 && (
          <p className="text-slate-500 italic text-xs">No log output captured yet.</p>
        )}
        {logs.slice(-50).map((line, idx) => (
          <div key={`${line}-${idx}`} className={logColor(line)}>
            {line}
          </div>
        ))}
      </div>
    </div>
  )
}

export default GlassTerminal
