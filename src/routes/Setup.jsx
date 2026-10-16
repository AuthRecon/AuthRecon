import React, { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { Shield, User, Lock, CheckCircle, AlertCircle } from 'lucide-react'
import useAuthStore from '../store/authStore'
import Button from '../components/Button'
import Input from '../components/Input'
import Card from '../components/Card'
import api from '../services/api'
import VERSION from '../config/version'

/**
 * Setup Page
 * First-time portal initialization - creates admin user
 */
const PASSWORD_STRENGTH_STYLES = {
  weak: {
    text: 'text-rose-400',
    bar: 'bg-rose-500',
  },
  medium: {
    text: 'text-amber-400',
    bar: 'bg-amber-500',
  },
  strong: {
    text: 'text-emerald-400',
    bar: 'bg-emerald-500',
  },
}

function Setup() {
  const navigate = useNavigate()
  const setSession = useAuthStore((state) => state.setSession)

  const [formData, setFormData] = useState({
    username: '',
    password: '',
    passwordConfirm: '',
  })
  const [errors, setErrors] = useState({})
  const [isLoading, setIsLoading] = useState(false)
  const [apiError, setApiError] = useState(null)

  const handleChange = (e) => {
    const { name, value } = e.target
    setFormData((prev) => ({ ...prev, [name]: value }))
    // Clear error for this field
    if (errors[name]) {
      setErrors((prev) => ({ ...prev, [name]: null }))
    }
    if (apiError) {
      setApiError(null)
    }
  }

  // Password strength indicator
  const getPasswordStrength = (password) => {
    if (!password) return { label: '', variant: null, percent: 0 }

    let strength = 0
    if (password.length >= 12) strength += 25
    if (password.length >= 16) strength += 15
    if (/[a-z]/.test(password)) strength += 15
    if (/[A-Z]/.test(password)) strength += 15
    if (/[0-9]/.test(password)) strength += 15
    if (/[^a-zA-Z0-9]/.test(password)) strength += 15

    if (strength < 40) return { label: 'Weak', variant: 'weak', percent: strength }
    if (strength < 70) return { label: 'Medium', variant: 'medium', percent: strength }
    return { label: 'Strong', variant: 'strong', percent: strength }
  }

  const passwordStrength = getPasswordStrength(formData.password)
  const passwordStrengthStyle = passwordStrength.variant
    ? PASSWORD_STRENGTH_STYLES[passwordStrength.variant]
    : null

  const validate = () => {
    const newErrors = {}

    // Username validation (email format)
    if (!formData.username.trim()) {
      newErrors.username = 'Email is required'
    } else if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(formData.username)) {
      newErrors.username = 'Must be a valid email address'
    }

    // Password validation
    if (!formData.password) {
      newErrors.password = 'Password is required'
    } else if (formData.password.length < 12) {
      newErrors.password = 'Password must be at least 12 characters'
    } else if (!/[A-Z]/.test(formData.password) || !/[0-9]/.test(formData.password) || !/[^A-Za-z0-9]/.test(formData.password)) {
      newErrors.password = 'Password must include uppercase, a number, and a special character'
    }

    // Password confirmation
    if (!formData.passwordConfirm) {
      newErrors.passwordConfirm = 'Please confirm your password'
    } else if (formData.password !== formData.passwordConfirm) {
      newErrors.passwordConfirm = 'Passwords do not match'
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

    setIsLoading(true)
    setApiError(null)

    try {
      // Call setup API endpoint
      const response = await api.post('/api/auth/setup', {
        username: formData.username,
        password: formData.password,
      })

      const data = response.data

      if (!data?.user) {
        throw new Error('Setup response missing authentication data')
      }

      // The portal set the session cookie; record who signed in
      setSession(data.user)

      // Redirect to dashboard
      navigate('/')
    } catch (error) {
      console.error('Setup failed:', error)
      setApiError(error.message || 'Failed to initialize portal')
    } finally {
      setIsLoading(false)
    }
  }

  return (
    <div className="min-h-screen flex items-center justify-center p-4 bg-linear-to-br from-slate-950 via-slate-900 to-slate-950">
      <Card className="w-full max-w-md" padding="lg">
        {/* Logo */}
        <div className="text-center mb-8">
          <div className="inline-flex items-center justify-center w-16 h-16 bg-sky-500/10 rounded-2xl mb-4">
            <Shield className="w-8 h-8 text-sky-500" />
          </div>
          <h1 className="text-3xl font-bold gradient-text mb-2">
            Initialize AuthRecon Suite
          </h1>
          <p className="text-slate-400">Create the first administrator account</p>
        </div>

        {/* Error Alert */}
        {apiError && (
          <div className="mb-6 p-4 bg-rose-500/10 border border-rose-500/30 rounded-xl flex items-start gap-3">
            <AlertCircle className="w-5 h-5 text-rose-400 shrink-0 mt-0.5" />
            <div className="flex-1">
              <p className="text-sm font-medium text-rose-400">Setup Failed</p>
              <p className="text-sm text-rose-300/80 mt-1">{apiError}</p>
            </div>
          </div>
        )}

        {/* Setup Form */}
        <form onSubmit={handleSubmit} className="space-y-4">
          <Input
            label="Admin Email"
            name="username"
            type="email"
            placeholder="admin@example.com"
            icon={User}
            value={formData.username}
            onChange={handleChange}
            error={errors.username}
            required
            autoComplete="email"
            autoFocus
          />

          <div>
            <Input
              label="Password"
              name="password"
              type="password"
              placeholder="Minimum 10 characters"
              icon={Lock}
              value={formData.password}
              onChange={handleChange}
              error={errors.password}
              required
              autoComplete="new-password"
            />

            {/* Password Strength Indicator */}
            {formData.password && (
              <div className="mt-2 space-y-1">
                <div className="flex items-center justify-between text-xs">
                  <span className="text-slate-500">Password strength</span>
                  <span className={`font-medium ${passwordStrengthStyle?.text || 'text-slate-500'}`}>
                    {passwordStrength.label}
                  </span>
                </div>
                <div className="h-1.5 bg-slate-800 rounded-full overflow-hidden">
                  <div
                    className={`h-full transition-all duration-300 ${passwordStrengthStyle?.bar || 'bg-slate-600'}`}
                    style={{ width: `${passwordStrength.percent}%` }}
                  />
                </div>
              </div>
            )}
          </div>

          <Input
            label="Confirm Password"
            name="passwordConfirm"
            type="password"
            placeholder="Re-enter password"
            icon={CheckCircle}
            value={formData.passwordConfirm}
            onChange={handleChange}
            error={errors.passwordConfirm}
            required
            autoComplete="new-password"
          />

          <Button
            type="submit"
            variant="primary"
            size="lg"
            loading={isLoading}
            className="w-full"
          >
            {isLoading ? 'Creating Admin...' : 'Create Admin Account'}
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

export default Setup
