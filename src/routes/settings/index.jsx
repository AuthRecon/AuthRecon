import React from 'react'
import { useSearchParams } from 'react-router-dom'
import ConnectorTabs from './components/ConnectorTabs'
import AiMcpPanel from './components/AiMcpPanel'
import UserManagementPanel from './components/UserManagementPanel'
import LoginLabPanel from './components/LoginLabPanel'
import { AccountPanel } from './components/AccountPanel'
import AuditLogPanel from './components/AuditLogPanel'
import useAuthStore from '../../store/authStore'
import Header from '../../components/Header'

function SettingsPage() {
  // The tab lives in the URL so links like /settings?tab=ai (header AI chip,
  // Account › Manage keys) work even when Settings is already open.
  const [searchParams, setSearchParams] = useSearchParams()
  const activeTab = searchParams.get('tab') || 'account'
  const setActiveTab = (tab) => setSearchParams({ tab })
  const { user } = useAuthStore()
  const isAdmin = user?.is_admin

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      <Header title="Settings" subtitle="Your account, AI clients, users and security" />
      <div className="flex-1 flex overflow-hidden">
      <aside className="w-72 border-r border-(--stroke-dark) p-6 overflow-y-auto">
        <ConnectorTabs activeTab={activeTab} onChange={setActiveTab} />
      </aside>
      <main className="flex-1 overflow-y-auto p-6 space-y-6">
        {activeTab === 'account' && (
          <AccountPanel />
        )}
        {activeTab === 'ai' && (
          <AiMcpPanel />
        )}
        {activeTab === 'users' && (
          <UserManagementPanel />
        )}
        {activeTab === 'loginlab' && isAdmin && (
          <LoginLabPanel />
        )}
        {activeTab === 'auditlog' && isAdmin && (
          <AuditLogPanel />
        )}
      </main>
      </div>
    </div>
  )
}

export default SettingsPage
