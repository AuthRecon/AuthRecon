import React from 'react'
import { AlertCircle, CheckCircle, Info, AlertTriangle } from 'lucide-react'

/**
 * Alert Component
 *
 * Displays contextual alert messages with different variants
 */
function Alert({ children, variant = 'default', className = '' }) {
  const variants = {
    default: {
      container: 'bg-slate-800/50 border-slate-700/50 text-slate-300',
      icon: <Info className="w-4 h-4 text-slate-400" />
    },
    success: {
      container: 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300',
      icon: <CheckCircle className="w-4 h-4 text-emerald-400" />
    },
    error: {
      container: 'bg-rose-500/10 border-rose-500/30 text-rose-300',
      icon: <AlertCircle className="w-4 h-4 text-rose-400" />
    },
    warning: {
      container: 'bg-amber-500/10 border-amber-500/30 text-amber-300',
      icon: <AlertTriangle className="w-4 h-4 text-amber-400" />
    },
    info: {
      container: 'bg-blue-500/10 border-blue-500/30 text-blue-300',
      icon: <Info className="w-4 h-4 text-blue-400" />
    }
  }

  const style = variants[variant] || variants.default

  return (
    <div
      className={`flex items-start gap-3 px-4 py-3 rounded-lg border ${style.container} ${className}`}
      role="alert"
    >
      <div className="flex-shrink-0 mt-0.5">{style.icon}</div>
      <div className="flex-1 text-sm">{children}</div>
    </div>
  )
}

export default Alert
