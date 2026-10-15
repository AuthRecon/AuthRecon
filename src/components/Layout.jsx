import React, { useState, useEffect } from 'react'
import { Link, useLocation } from 'react-router-dom'
import {
  LayoutDashboard,
  Shield,
  Globe,
  Network,
  Settings,
  LogOut,
  ChevronLeft,
  ChevronRight,
  FileSearch
} from 'lucide-react'
import useAuthStore from '../store/authStore'
import Footer from './Footer'
import VERSION from '../config/version'
import LoginLabBanner from './LoginLabBanner'
import SecurityNotice from './SecurityNotice'

/**
 * Main Layout Component
 * Provides the app shell with sidebar navigation and content area
 */
function Layout({ children }) {
  const location = useLocation()
  const { user, logout } = useAuthStore()
  const [isSidebarCollapsed, setIsSidebarCollapsed] = useState(() => {
    // Load saved preference from localStorage
    const saved = localStorage.getItem('sidebarCollapsed')
    return saved === 'true'
  })

  // Save sidebar state to localStorage
  useEffect(() => {
    localStorage.setItem('sidebarCollapsed', isSidebarCollapsed.toString())
  }, [isSidebarCollapsed])

  const toggleSidebar = () => {
    setIsSidebarCollapsed(!isSidebarCollapsed)
  }

  const navigation = [
    {
      name: 'Portal',
      path: '/',
      icon: LayoutDashboard,
      description: 'Security tools dashboard'
    },
    {
      name: 'AuthRecon',
      path: '/authrecon',
      icon: Shield,
      description: 'Authentication reconnaissance'
    },
    {
      name: 'Network Tools',
      path: '/network-tools',
      icon: Network,
      description: 'Diagnostic utilities'
    },
    {
      name: 'Atlas',
      path: '/atlas',
      icon: Globe,
      description: 'Asset intelligence map'
    },
    {
      // Working name; the feature is MCP-only (needs a connected AI client).
      name: 'Scan Analyzer',
      path: '/scan-analyzer',
      icon: FileSearch,
      description: 'Tenable WAS scan export analysis'
    },
  ]

  const isActive = (path) => {
    if (path === '/') {
      return location.pathname === '/'
    }
    return location.pathname.startsWith(path)
  }

  const handleLogout = async () => {
    await logout()
    window.location.href = '/login'
  }

  return (
    <>
    <div className="app-shell">
      {/* Sidebar */}
      <aside className={`flex flex-col sidebar transition-all duration-300 ${isSidebarCollapsed ? 'w-20' : 'w-72'}`}>
        {/* Logo / Brand */}
        <div className="p-6 border-b border-(--stroke-dark) relative">
          <div className={`flex items-center ${isSidebarCollapsed ? 'justify-center' : 'gap-3'}`}>
            <div className="p-2 rounded-sm" style={{ background: 'rgba(0,170,255,0.12)' }}>
              <Shield className="w-6 h-6 text-(--accent-blue)" />
            </div>
            {!isSidebarCollapsed && (
              <div>
                <h1 className="text-lg font-bold text-(--text-primary)">AuthRecon</h1>
                <p className="text-xs text-(--text-muted)">v{VERSION.toString()}</p>
              </div>
            )}
          </div>
          {/* Collapse Toggle Button */}
          <button
            onClick={toggleSidebar}
            className="absolute -right-3 top-8 p-1.5 rounded-full bg-(--bg-secondary) border border-(--stroke-dark) hover:bg-(--bg-tertiary) hover:border-(--accent-blue)/30 transition-all z-10"
            title={isSidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          >
            {isSidebarCollapsed ? (
              <ChevronRight className="w-4 h-4 text-(--text-secondary)" />
            ) : (
              <ChevronLeft className="w-4 h-4 text-(--text-secondary)" />
            )}
          </button>
        </div>

        {/* Navigation */}
        <nav className="flex-1 p-4 space-y-2 overflow-y-auto scrollbar-thin">
          {navigation.map((item) => {
            const Icon = item.icon
            const active = isActive(item.path)

            return (
              <Link
                key={item.path}
                to={item.path}
                className={`item block px-4 py-3 rounded-xl transition-all duration-200 border ${active ? 'active' : 'border-transparent'} ${isSidebarCollapsed ? 'flex justify-center' : ''}`}
                title={isSidebarCollapsed ? item.name : ''}
              >
                <div className={`flex items-center ${isSidebarCollapsed ? '' : 'gap-3'}`}>
                  <Icon
                    className={`w-5 h-5 ${active ? 'text-(--accent-blue)' : 'text-slate-400 group-hover:text-slate-200'}`}
                  />
                  {!isSidebarCollapsed && (
                    <div className="flex-1 min-w-0">
                      <div className={`font-medium text-sm ${active ? 'text-(--accent-blue-strong)' : 'text-(--text-secondary) group-hover:text-white'}`}>
                        {item.name}
                      </div>
                      <div className="text-xs text-(--text-muted) truncate">
                        {item.description}
                      </div>
                    </div>
                  )}
                </div>
              </Link>
            )
          })}

          {/* Settings Link */}
          <Link
            to="/settings"
            className={`item block px-4 py-3 rounded-xl transition-all duration-200 border ${isActive('/settings') ? 'active' : 'border-transparent'} ${isSidebarCollapsed ? 'flex justify-center' : ''}`}
            title={isSidebarCollapsed ? 'Settings' : ''}
          >
            <div className={`flex items-center ${isSidebarCollapsed ? '' : 'gap-3'}`}>
              <Settings
                className={`w-5 h-5 ${isActive('/settings') ? 'text-(--accent-blue)' : 'text-slate-400 group-hover:text-slate-200'}`}
              />
              {!isSidebarCollapsed && (
                <div className="flex-1 min-w-0">
                  <div className={`font-medium text-sm ${isActive('/settings') ? 'text-(--accent-blue-strong)' : 'text-(--text-secondary) group-hover:text-white'}`}>
                    Settings
                  </div>
                  <div className="text-xs text-(--text-muted) truncate">
                    Configuration
                  </div>
                </div>
              )}
            </div>
          </Link>
        </nav>

        {/* User Info */}
        <div className="p-4 border-t border-(--stroke-dark)">
          <div className={`flex items-center px-4 py-3 bg-white/5 rounded-xl ${isSidebarCollapsed ? 'flex-col gap-2' : 'gap-3'}`}>
            <div className="w-10 h-10 rounded-sm flex items-center justify-center font-semibold shrink-0 bg-linear-to-br from-[#1ab9ff] to-[#008ec7] text-white">
              {user?.username?.[0]?.toUpperCase() || 'U'}
            </div>
            {!isSidebarCollapsed && (
              <>
                <div className="flex-1 min-w-0">
                  <div className="text-sm font-medium text-(--text-primary) truncate">
                    {user?.username || 'User'}
                  </div>
                  <div className="text-xs text-(--text-muted)">
                    {user?.role || 'Operator'}
                  </div>
                </div>
                <button
                  onClick={handleLogout}
                  className="p-2 hover:bg-slate-700/50 rounded-lg transition-colors"
                  title="Logout"
                >
                  <LogOut className="w-4 h-4 text-slate-400 hover:text-rose-400" />
                </button>
              </>
            )}
            {isSidebarCollapsed && (
              <button
                onClick={handleLogout}
                className="p-1.5 hover:bg-slate-700/50 rounded-lg transition-colors"
                title="Logout"
              >
                <LogOut className="w-3.5 h-3.5 text-slate-400 hover:text-rose-400" />
              </button>
            )}
          </div>
        </div>
      </aside>

      {/* Main Content Area */}
      <main className="flex-1 flex flex-col overflow-hidden">
        {/* LoginLab Warning Banner */}
        <LoginLabBanner />

        <div className="flex-1 overflow-hidden">
          {children}
        </div>
        <Footer />
      </main>
      <SecurityNotice />
    </div>
    </>
  )
}

export default Layout
