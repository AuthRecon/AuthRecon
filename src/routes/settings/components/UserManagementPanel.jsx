import React, { useState } from 'react'
import { UserPlus, Shield, ShieldOff, User as UserIcon, Mail, Calendar, Edit2, Trash2 } from 'lucide-react'
import Card from '../../../components/Card'
import Button from '../../../components/Button'
import PanelShell from './PanelShell'
import { usePortalUsers } from '../../../services/usePortalUsers'
import UserCreateModal from './UserCreateModal'
import UserEditModal from './UserEditModal'
import UserDeleteModal from './UserDeleteModal'
import useAuthStore from '../../../store/authStore'
import api from '../../../services/api'

function UserManagementPanel() {
  const { data: users = [], isLoading, error } = usePortalUsers()
  const currentUser = useAuthStore((state) => state.user)
  const [showCreateModal, setShowCreateModal] = useState(false)
  const [editingUser, setEditingUser] = useState(null)
  const [deletingUser, setDeletingUser] = useState(null)

  const formatDate = (dateString) => {
    if (!dateString) return 'Never'
    const date = new Date(dateString)
    return date.toLocaleDateString('en-US', {
      year: 'numeric',
      month: 'short',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit'
    })
  }

  if (isLoading) {
    return (
      <Card padding="lg">
        <div className="flex items-center justify-center py-12">
          <div className="text-slate-400">Loading users...</div>
        </div>
      </Card>
    )
  }

  if (error) {
    return (
      <Card padding="lg">
        <div className="flex items-center justify-center py-12">
          <div className="text-red-400">Failed to load users: {error.message}</div>
        </div>
      </Card>
    )
  }

  return (
    <>
      <PanelShell
        eyebrow="Administration"
        title="Users"
        description="Operator accounts and who is an administrator. Deactivating or demoting a user takes effect immediately."
        actions={
          <Button variant="primary" icon={UserPlus} onClick={() => setShowCreateModal(true)}>
            Add user
          </Button>
        }
      >

        <div className="space-y-3">
          {users.length === 0 ? (
            <div className="text-center py-12 text-slate-400">
              No users found. Create your first user to get started.
            </div>
          ) : (
            users.map((user) => {
              const isCurrentUser = currentUser?.id === user.id

              return (
                <div
                  key={user.id}
                  className="p-4 rounded-2xl border border-slate-800/80 bg-slate-900/30 hover:bg-slate-900/50 transition-colors"
                >
                  <div className="flex items-start justify-between">
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-3 mb-2">
                        <div className="flex items-center gap-2">
                          <Mail className="w-4 h-4 text-slate-400" />
                          <span className="text-slate-50 font-medium truncate">
                            {user.username}
                          </span>
                        </div>

                        {user.is_admin && (
                          <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md bg-[rgba(41,199,255,0.1)] border border-[rgba(41,199,255,0.3)] text-xs text-(--accent-blue)">
                            <Shield className="w-3 h-3" />
                            Admin
                          </span>
                        )}

                        {!user.is_active && (
                          <span className="inline-flex items-center px-2 py-0.5 rounded-md bg-slate-800/50 border border-slate-700/50 text-xs text-slate-500">
                            Inactive
                          </span>
                        )}

                        {isCurrentUser && (
                          <span className="inline-flex items-center px-2 py-0.5 rounded-md bg-green-500/10 border border-green-500/30 text-xs text-green-400">
                            You
                          </span>
                        )}
                      </div>

                      <div className="grid grid-cols-1 md:grid-cols-3 gap-3 text-sm">
                        <div className="flex items-center gap-2 text-slate-400">
                          <UserIcon className="w-3.5 h-3.5" />
                          <span>{user.full_name || 'No name set'}</span>
                        </div>

                        <div className="flex items-center gap-2 text-slate-400">
                          <Calendar className="w-3.5 h-3.5" />
                          <span>Last login: {formatDate(user.last_login_at)}</span>
                        </div>

                        <div className="flex items-center gap-2 text-slate-400">
                          <Calendar className="w-3.5 h-3.5" />
                          <span>Created: {formatDate(user.created_at)}</span>
                        </div>
                      </div>
                    </div>

                    <div className="flex items-center gap-2 ml-4">
                      <button
                        onClick={() => setEditingUser(user)}
                        className="p-2 rounded-lg border border-slate-700/50 bg-slate-800/50 hover:bg-slate-800 hover:border-[rgba(41,199,255,0.3)] text-slate-400 hover:text-(--accent-blue) transition-all"
                        title="Edit user"
                      >
                        <Edit2 className="w-4 h-4" />
                      </button>

                      <button
                        onClick={async () => {
                          if (!window.confirm(`Turn off two-factor authentication for ${user.username}? They can sign in with their password and set it up again. Use this when they have lost their phone and backup codes.`)) return
                          try {
                            await api.post(`/api/auth/mfa/reset/${user.id}`)
                            alert(`Two-factor authentication is off for ${user.username}.`)
                          } catch (err) {
                            alert(err.response?.data?.detail || 'Could not reset two-factor authentication')
                          }
                        }}
                        disabled={isCurrentUser}
                        className="p-2 rounded-lg border border-slate-700/50 bg-slate-800/50 hover:bg-amber-500/10 hover:border-amber-500/30 text-slate-400 hover:text-amber-300 transition-all disabled:opacity-50 disabled:cursor-not-allowed"
                        title={isCurrentUser ? "Use Settings › Account for your own two-factor" : "Reset two-factor authentication"}
                      >
                        <ShieldOff className="w-4 h-4" />
                      </button>

                      <button
                        onClick={() => setDeletingUser(user)}
                        disabled={isCurrentUser}
                        className="p-2 rounded-lg border border-slate-700/50 bg-slate-800/50 hover:bg-red-500/10 hover:border-red-500/30 text-slate-400 hover:text-red-400 transition-all disabled:opacity-50 disabled:cursor-not-allowed disabled:hover:bg-slate-800/50 disabled:hover:border-slate-700/50 disabled:hover:text-slate-400"
                        title={isCurrentUser ? "Cannot delete yourself" : "Delete user"}
                      >
                        <Trash2 className="w-4 h-4" />
                      </button>
                    </div>
                  </div>
                </div>
              )
            })
          )}
        </div>
      </PanelShell>

      {showCreateModal && (
        <UserCreateModal onClose={() => setShowCreateModal(false)} />
      )}

      {editingUser && (
        <UserEditModal
          user={editingUser}
          onClose={() => setEditingUser(null)}
        />
      )}

      {deletingUser && (
        <UserDeleteModal
          user={deletingUser}
          onClose={() => setDeletingUser(null)}
        />
      )}
    </>
  )
}

export default UserManagementPanel
