import React, { useEffect, useState } from 'react'
import { Routes, Route, Navigate, useNavigate, useLocation } from 'react-router-dom'
import useAuthStore from './store/authStore'
import AuthGuard from './components/AuthGuard'
import Login from './routes/Login'
import Setup from './routes/Setup'
import Dashboard from './routes/Dashboard'
import AuthRecon from './routes/AuthRecon'
import AuthReconLaunch from './routes/AuthReconLaunch'
import AuthReconRunDetail from './routes/AuthReconRunDetail/index'
import SettingsPage from './routes/settings'
import NetworkTools from './routes/NetworkTools'
import Atlas from './routes/Atlas'
import ScanAnalyzer from './routes/ScanAnalyzer'
import api from './services/api'

/**
 * Main App Component
 * Defines routing structure and initializes auth state
 */
function App() {
  const initialize = useAuthStore((state) => state.initialize)
  const [isInitialized, setIsInitialized] = useState(null) // null = loading, true/false = loaded
  const navigate = useNavigate()
  const location = useLocation()

  // Check portal initialization status
  useEffect(() => {
    const checkInitialization = async () => {
      try {
        const { data } = await api.get('/api/auth/status')
        setIsInitialized(Boolean(data.initialized))

        // If portal needs setup and we're not already on /setup, redirect
        if (!data.initialized && location.pathname !== '/setup') {
          navigate('/setup', { replace: true })
        }

        // If setup already complete and user is on setup route, push to dashboard
        if (data.initialized && location.pathname === '/setup') {
          navigate('/', { replace: true })
        }
      } catch (error) {
        console.error('Failed to check initialization status:', error)
        // Assume initialized if we can't check (fail open)
        setIsInitialized(true)
      }
    }

    checkInitialization()
  }, [navigate, location.pathname])

  // Initialize auth state on mount
  useEffect(() => {
    initialize()
  }, [initialize])

  // Show loading while checking initialization
  if (isInitialized === null) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-linear-to-br from-slate-900 via-slate-800 to-slate-900">
        <div className="text-center">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-sky-500/10 rounded-2xl mb-4">
            <div className="w-8 h-8 border-4 border-sky-500/30 border-t-sky-500 rounded-full animate-spin" />
          </div>
          <p className="text-slate-400">Loading AuthRecon Suite...</p>
        </div>
      </div>
    )
  }

  return (
    <Routes>
      {/* Public Routes */}
      <Route path="/setup" element={<Setup />} />
      <Route path="/login" element={<Login />} />

      {/* Protected Routes - Wrapped with AuthGuard */}
      <Route element={<AuthGuard />}>
        <Route path="/" element={<Dashboard />} />

        <Route path="/authrecon" element={<AuthRecon />} />
        <Route path="/authrecon/launch" element={<AuthReconLaunch />} />
        <Route path="/authrecon/run/:runId" element={<AuthReconRunDetail />} />
        <Route path="/settings/*" element={<SettingsPage />} />

        <Route path="/network-tools" element={<NetworkTools />} />
        <Route path="/atlas" element={<Atlas />} />
        <Route path="/scan-analyzer" element={<ScanAnalyzer />} />
      </Route>

      {/* Catch all - redirect to dashboard */}
      <Route path="*" element={<Navigate to="/" replace />} />
    </Routes>
  )
}

export default App
