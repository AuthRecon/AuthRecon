import React, { useState } from 'react'
import { X, AlertTriangle, Trash2, Shield } from 'lucide-react'
import Button from '../../../components/Button'
import { useDeletePortalUser } from '../../../services/usePortalUsers'
import useAuthStore from '../../../store/authStore'

function UserDeleteModal({ user, onClose }) {
  const currentUser = useAuthStore((state) => state.user)
  const isCurrentUser = currentUser?.id === user.id

  const [confirmEmail, setConfirmEmail] = useState('')
  const [error, setError] = useState(null)

  const deleteUserMutation = useDeletePortalUser()

  const canDelete = confirmEmail.toLowerCase() === user.username.toLowerCase()

  const handleDelete = async () => {
    if (!canDelete) return

    try {
      await deleteUserMutation.mutateAsync(user.id)
      onClose()
    } catch (error) {
      setError(error.response?.data?.detail || 'Failed to delete user')
    }
  }

  // Should never happen due to UI protection, but just in case
  if (isCurrentUser) {
    return (
      <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
        <div className="bg-slate-900 border border-slate-800/80 rounded-2xl shadow-2xl w-full max-w-md mx-4">
          <div className="px-6 py-4 border-b border-slate-800/80">
            <h2 className="text-xl font-semibold text-slate-50">Cannot Delete User</h2>
          </div>
          <div className="p-6">
            <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-sm flex items-start gap-2 mb-6">
              <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
              <span>You cannot delete your own account.</span>
            </div>
            <Button variant="secondary" onClick={onClose} className="w-full">
              Close
            </Button>
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-800/80 rounded-2xl shadow-2xl w-full max-w-md mx-4">
        <div className="px-6 py-4 border-b border-slate-800/80 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-red-500/10 border border-red-500/30">
              <Trash2 className="w-5 h-5 text-red-400" />
            </div>
            <h2 className="text-xl font-semibold text-slate-50">Delete User</h2>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-lg hover:bg-slate-800/50 text-slate-400 hover:text-slate-200 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="p-6 space-y-4">
          <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-sm flex items-start gap-2">
            <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
            <div>
              <p className="font-medium mb-1">This action cannot be undone</p>
              <p className="text-red-400/80">
                Deleting this user will permanently remove their account and all associated credentials.
              </p>
            </div>
          </div>

          <div className="space-y-2">
            <div className="flex items-center justify-between text-sm">
              <span className="text-slate-400">Email:</span>
              <span className="text-slate-50 font-medium">{user.username}</span>
            </div>
            {user.full_name && (
              <div className="flex items-center justify-between text-sm">
                <span className="text-slate-400">Name:</span>
                <span className="text-slate-50">{user.full_name}</span>
              </div>
            )}
            {user.is_admin && (
              <div className="flex items-center justify-between text-sm">
                <span className="text-slate-400">Role:</span>
                <span className="inline-flex items-center gap-1 text-[var(--accent-blue)]">
                  <Shield className="w-3 h-3" />
                  Administrator
                </span>
              </div>
            )}
          </div>

          <div className="pt-2">
            <label className="block text-sm font-medium text-slate-300 mb-2">
              Type the user's email address to confirm:
            </label>
            <input
              type="text"
              value={confirmEmail}
              onChange={(e) => setConfirmEmail(e.target.value)}
              placeholder={user.username}
              className="w-full px-4 py-2.5 bg-slate-800/50 border border-slate-700/50 rounded-xl text-slate-50 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-red-500/20 focus:border-red-500/30 transition-all"
              autoFocus
            />
            {confirmEmail && !canDelete && (
              <p className="mt-1.5 text-xs text-red-400">
                Email does not match
              </p>
            )}
            {canDelete && (
              <p className="mt-1.5 text-xs text-green-400">
                Email confirmed
              </p>
            )}
          </div>

          {error && (
            <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-sm flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
              <span>{error}</span>
            </div>
          )}

          <div className="flex items-center gap-3 pt-2">
            <Button
              variant="secondary"
              onClick={onClose}
              disabled={deleteUserMutation.isPending}
              className="flex-1"
            >
              Cancel
            </Button>
            <button
              onClick={handleDelete}
              disabled={!canDelete || deleteUserMutation.isPending}
              className="flex-1 px-4 py-2.5 rounded-xl font-medium bg-red-500/10 border border-red-500/30 text-red-400 hover:bg-red-500/20 hover:border-red-500/50 disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:bg-red-500/10 disabled:hover:border-red-500/30 transition-all flex items-center justify-center gap-2"
            >
              <Trash2 className="w-4 h-4" />
              {deleteUserMutation.isPending ? 'Deleting...' : 'Delete User'}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

export default UserDeleteModal
