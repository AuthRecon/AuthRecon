import React from 'react'
import useAuthStore from '../../../store/authStore'

const tabs = [
  { id: 'account', label: 'Account', description: 'Profile & password' },
  { id: 'ai', label: 'AI & MCP', description: 'Connect an AI client' },
  { id: 'license', label: 'Licensing', description: 'License key & entitlement' },
  { id: 'users', label: 'User Management', description: 'Operators & access' },
  { id: 'loginlab', label: 'LoginLab', description: 'Training environment', adminOnly: true },
  { id: 'auditlog', label: 'Audit Log', description: 'Security event history', adminOnly: true },
]

function ConnectorTabs({ activeTab, onChange }) {
  const { user } = useAuthStore()
  const isAdmin = user?.is_admin

  // Filter tabs based on admin status
  const visibleTabs = tabs.filter(tab => !tab.adminOnly || isAdmin)
  return (
    <nav className="flex flex-col gap-2" aria-label="Settings navigation">
      {visibleTabs.map((tab) => {
        const isActive = activeTab === tab.id
        return (
          <button
            key={tab.id}
            className={`text-left px-4 py-3 rounded-2xl transition-all border ${
              isActive
                ? 'bg-[rgba(41,199,255,0.1)] border-[rgba(41,199,255,0.4)] shadow-glow text-slate-50'
                : 'bg-slate-900/40 border-slate-800/50 text-slate-400 hover:text-slate-200'
            }`}
            onClick={() => onChange(tab.id)}
          >
            <p className="text-sm font-semibold">{tab.label}</p>
            <p className="text-xs text-slate-500">{tab.description}</p>
          </button>
        )
      })}
    </nav>
  )
}

export default ConnectorTabs
