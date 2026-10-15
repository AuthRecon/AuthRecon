import React, { useState, useEffect } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, User, Lock, AlertCircle } from 'lucide-react'
import useAuthStore from '../store/authStore'
import Button from '../components/Button'
import Input from '../components/Input'
import Card from '../components/Card'
import api from '../services/api'
import VERSION from '../config/version'

/**
 * Login Page
 * Authentication form
 */
function Login() {
  const navigate = useNavigate()
  const { login, isLoading, error: authError } = useAuthStore()

  const [formData, setFormData] = useState({
    username: '',
    password: '',
  })
  const [errors, setErrors] = useState({})
  const [checkingSetup, setCheckingSetup] = useState(true)

  // Check if system needs setup on mount
  useEffect(() => {
    const checkSetupStatus = async () => {
      try {
        const response = await api.get('/api/auth/status')
        if (response.data?.needs_setup) {
          navigate('/setup')
        }
      } catch (error) {
        console.error('Failed to check setup status:', error)
      } finally {
        setCheckingSetup(false)
      }
    }

    checkSetupStatus()
  }, [navigate])

  // Show loading while checking setup status
  if (checkingSetup) {
    return (
      <div className="min-h-screen flex items-center justify-center p-4 bg-linear-to-br from-slate-950 via-slate-900 to-slate-950">
        <Card className="w-full max-w-md" padding="lg">
          <div className="text-center">
            <Shield className="w-12 h-12 text-blue-500 mx-auto mb-4 animate-pulse" />
            <p className="text-slate-400">Loading...</p>
          </div>
        </Card>
      </div>
    )
  }

  const handleChange = (e) => {
    const { name, value } = e.target
    setFormData((prev) => ({ ...prev, [name]: value }))
    // Clear error for this field
    if (errors[name]) {
      setErrors((prev) => ({ ...prev, [name]: null }))
    }
  }

  const validate = () => {
    const newErrors = {}
    if (!formData.username.trim()) {
      newErrors.username = 'Username is required'
    }
    if (!formData.password) {
      newErrors.password = 'Password is required'
    }
    return newErrors
  }

  const handleSubmit = async (e) => {
    e.preventDefault()

    // Validate
    const newErrors = validate()
    if (Object.keys(newErrors).length > 0) {
      setErrors(newErrors)
      return
    }

    try {
      await login(formData.username, formData.password)
      // Redirect to dashboard on success
      navigate('/')
    } catch (error) {
      // Error is handled by the store
      console.error('Login failed:', error)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-4 bg-linear-to-br from-slate-950 via-slate-900 to-slate-950">
      <Card className="w-full max-w-md" padding="lg">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-blue-500/10 rounded-2xl mb-4">
            <Shield className="w-8 h-8 text-blue-500" />
          </div>
          <h1 className="text-3xl font-bold gradient-text mb-2">
            AuthRecon Suite
          </h1>
          <p className="text-slate-400">Sign in to continue</p>
        </div>

        {/* Error Alert */}
        {authError && (
          <div className="mb-6 p-4 bg-rose-500/10 border border-rose-500/30 rounded-xl flex items-start gap-3">
            <AlertCircle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
            <div className="flex-1">
              <p className="text-sm font-medium text-rose-400">Login Failed</p>
              <p className="text-sm text-rose-300/80 mt-1">{authError}</p>
            </div>
          </div>
        )}

        {/* Login Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          <Input
            label="Username"
            name="username"
            type="text"
            placeholder="Enter your username"
            icon={User}
            value={formData.username}
            onChange={handleChange}
            error={errors.username}
            required
            autoComplete="username"
            autoFocus
          />

          <Input
            label="Password"
            name="password"
            type="password"
            placeholder="Enter your password"
            icon={Lock}
            value={formData.password}
            onChange={handleChange}
            error={errors.password}
            required
            autoComplete="current-password"
          />

          <Button
            type="submit"
            variant="primary"
            size="lg"
            loading={isLoading}
            className="w-full"
          >
            {isLoading ? 'Signing in...' : 'Sign In'}
          </Button>
        </form>

        {/* Footer */}
        <div className="mt-6 pt-6 border-t border-slate-700/50 text-center">
          <p className="text-xs text-slate-500">
            AuthRecon Suite v{VERSION.toString()}
          </p>
        </div>
      </Card>
    </div>
  )
}

export default Login
