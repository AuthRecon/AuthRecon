import React from 'react'
import { AlertTriangle, FlaskConical, Clock, X } from 'lucide-react'
import { useLoginLabStatus, useDisableLoginLab } from '../hooks/useLoginLabStatus'
import useAuthStore from '../store/authStore'

/**
 * LoginLab Status Banner
 * Shows a warning banner when LoginLab training environment is active
 */
function LoginLabBanner() {
  const { user } = useAuthStore()
  const { data: status, isLoading } = useLoginLabStatus()
  const disableMutation = useDisableLoginLab()

  // Don't show banner if loading, not active, or service unavailable
  if (isLoading || !status?.active) {
    return null
  }

  const remainingMinutes = Math.ceil((status.remaining_seconds || 0) / 60)
  const isAdmin = user?.is_admin

  const handleDisable = async () => {
    if (window.confirm('Are you sure you want to disable LoginLab? Any active training sessions will be interrupted.')) {
      await disableMutation.mutateAsync()
    }
  }

  return (
    <div className="bg-amber-500/10 border-b border-amber-500/30 px-4 py-2">
      <div className="flex items-center justify-between max-w-(--breakpoint-2xl) mx-auto">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2 text-amber-400">
            <FlaskConical className="w-4 h-4" />
            <AlertTriangle className="w-4 h-4" />
          </div>
          <div className="text-sm">
            <span className="font-semibold text-amber-300">LoginLab Active</span>
            <span className="text-amber-200/80 ml-2">
              Practice login targets are running
            </span>
          </div>
        </div>

        <div className="flex items-center gap-4">
          <div className="flex items-center gap-2 text-amber-300/70 text-xs">
            <Clock className="w-3.5 h-3.5" />
            <span>Auto-disable in {remainingMinutes} min</span>
            {status.enabled_by && (
              <span className="text-amber-300/50">
                (enabled by {status.enabled_by})
              </span>
            )}
          </div>

          {isAdmin && (
            <button
              onClick={handleDisable}
              disabled={disableMutation.isPending}
              className="flex items-center gap-1.5 px-2.5 py-1 text-xs font-medium text-amber-100 bg-amber-500/20 hover:bg-amber-500/30 border border-amber-500/40 rounded-md transition-colors disabled:opacity-50"
            >
              <X className="w-3.5 h-3.5" />
              {disableMutation.isPending ? 'Disabling...' : 'Disable Now'}
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

export default LoginLabBanner
