import React from 'react'
import { Navigate, Outlet, useLocation } from 'react-router-dom'
import useAuthStore from '../store/authStore'
import Layout from './Layout'

/**
 * AuthGuard Component
 * Protects routes that require authentication
 * Wraps protected routes with Layout component
 */
function AuthGuard() {
  const user = useAuthStore((state) => state.user)
  const hasHydrated = useAuthStore((state) => state.hasHydrated)
  const location = useLocation()

  if (!hasHydrated) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-linear-to-br from-slate-950 via-slate-900 to-slate-950">
        <div className="text-center">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-sky-500/10 rounded-2xl mb-4">
            <div className="w-8 h-8 border-4 border-sky-500/30 border-t-sky-500 rounded-full animate-spin" />
          </div>
          <p className="text-slate-400">Preparing your session...</p>
        </div>
      </div>
    )
  }

  if (!user) {
    // Redirect to login if not authenticated
    return <Navigate to="/login" replace />
  }

  // Admins who must set up two-factor first: the server only answers the MFA
  // endpoints for this session, so keep them on the setup page until it is on.
  let mustEnrol = false
  try { mustEnrol = localStorage.getItem('mfa_enroll') === '1' } catch { /* storage blocked */ }
  if (mustEnrol && !(location.pathname === '/settings' && location.search.includes('tab=account'))) {
    return <Navigate to="/settings?tab=account" replace />
  }

  // Render Layout with nested routes
  return (
    <Layout>
      <Outlet />
    </Layout>
  )
}

export default AuthGuard
