import React, { useState } from 'react'
import { X, User, Lock, Shield, Eye, EyeOff, CheckCircle2, XCircle, AlertTriangle } from 'lucide-react'
import Button from '../../../components/Button'
import { useUpdatePortalUser } from '../../../services/usePortalUsers'
import useAuthStore from '../../../store/authStore'

function UserEditModal({ user, onClose }) {
  const currentUser = useAuthStore((state) => state.user)
  const isCurrentUser = currentUser?.id === user.id

  const [formData, setFormData] = useState({
    full_name: user.full_name || '',
    password: '',
    confirmPassword: '',
    is_admin: user.is_admin,
    is_active: user.is_active,
    changePassword: false,
  })

  const [showPassword, setShowPassword] = useState(false)
  const [showConfirmPassword, setShowConfirmPassword] = useState(false)
  const [errors, setErrors] = useState({})

  const updateUserMutation = useUpdatePortalUser()

  const validatePassword = (password) => {
    return password.length >= 8
  }

  const getPasswordStrength = (password) => {
    if (!password) return null
    if (password.length < 8) return { label: 'Too short', color: 'text-red-400' }

    let strength = 0
    if (password.length >= 12) strength++
    if (/[a-z]/.test(password)) strength++
    if (/[A-Z]/.test(password)) strength++
    if (/[0-9]/.test(password)) strength++
    if (/[^a-zA-Z0-9]/.test(password)) strength++

    if (strength <= 2) return { label: 'Weak', color: 'text-yellow-400' }
    if (strength <= 4) return { label: 'Good', color: 'text-blue-400' }
    return { label: 'Strong', color: 'text-green-400' }
  }

  const validateForm = () => {
    const newErrors = {}

    if (formData.changePassword) {
      if (!formData.password) {
        newErrors.password = 'Password is required'
      } else if (!validatePassword(formData.password)) {
        newErrors.password = 'Password must be at least 8 characters'
      }

      if (!formData.confirmPassword) {
        newErrors.confirmPassword = 'Please confirm password'
      } else if (formData.password !== formData.confirmPassword) {
        newErrors.confirmPassword = 'Passwords do not match'
      }
    }

    // Client-side self-protection checks
    if (isCurrentUser && !formData.is_admin) {
      newErrors.is_admin = 'Cannot remove your own admin privileges'
    }

    if (isCurrentUser && !formData.is_active) {
      newErrors.is_active = 'Cannot deactivate your own account'
    }

    setErrors(newErrors)
    return Object.keys(newErrors).length === 0
  }

  const handleSubmit = async (e) => {
    e.preventDefault()

    if (!validateForm()) return

    try {
      const updateData = {
        full_name: formData.full_name || undefined,
        is_admin: formData.is_admin,
        is_active: formData.is_active,
      }

      if (formData.changePassword && formData.password) {
        updateData.password = formData.password
      }

      await updateUserMutation.mutateAsync({
        userId: user.id,
        data: updateData,
      })
      onClose()
    } catch (error) {
      setErrors({
        submit: error.response?.data?.detail || 'Failed to update user'
      })
    }
  }

  const handleChange = (field, value) => {
    setFormData((prev) => ({ ...prev, [field]: value }))
    // Clear error for this field when user starts typing
    if (errors[field]) {
      setErrors((prev) => {
        const newErrors = { ...prev }
        delete newErrors[field]
        return newErrors
      })
    }
  }

  const passwordStrength = formData.changePassword ? getPasswordStrength(formData.password) : null

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-slate-900 border border-slate-800/80 rounded-2xl shadow-2xl w-full max-w-lg mx-4 max-h-[90vh] overflow-y-auto">
        <div className="sticky top-0 bg-slate-900 border-b border-slate-800/80 px-6 py-4 flex items-center justify-between">
          <div>
            <h2 className="text-xl font-semibold text-slate-50">Edit User</h2>
            <p className="text-sm text-slate-400 mt-0.5">{user.username}</p>
          </div>
          <button
            onClick={onClose}
            className="p-2 rounded-lg hover:bg-slate-800/50 text-slate-400 hover:text-slate-200 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-5">
          {errors.submit && (
            <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-sm flex items-start gap-2">
              <XCircle className="w-4 h-4 mt-0.5 flex-shrink-0" />
              <span>{errors.submit}</span>
            </div>
          )}

          {isCurrentUser && (
            <div className="p-4 rounded-xl bg-blue-500/10 border border-blue-500/30 text-blue-400 text-sm flex items-start gap-2">
              <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
              <span>You are editing your own account. Some restrictions apply.</span>
            </div>
          )}

          <div>
            <label className="block text-sm font-medium text-slate-300 mb-2">
              <User className="w-4 h-4 inline mr-1.5" />
              Full Name
            </label>
            <input
              type="text"
              value={formData.full_name}
              onChange={(e) => handleChange('full_name', e.target.value)}
              className="w-full px-4 py-2.5 bg-slate-800/50 border border-slate-700/50 rounded-xl text-slate-50 placeholder-slate-500 focus:outline-none focus:ring-2 focus:ring-[rgba(41,199,255,0.2)] focus:border-[rgba(41,199,255,0.3)] transition-all"
              placeholder="John Doe"
            />
          </div>

          <div className="space-y-3">
            <label className="flex items-center gap-3 cursor-pointer group">
              <div className="relative">
                <input
                  type="checkbox"
                  checked={formData.changePassword}
                  onChange={(e) => handleChange('changePassword', e.target.checked)}
                  className="peer sr-only"
                />
                <div className="w-5 h-5 border-2 border-slate-700 rounded bg-slate-800/50 peer-checked:bg-[rgba(41,199,255,0.1)] peer-checked:border-[rgba(41,199,255,0.5)] transition-all" />
                <CheckCircle2 className="absolute inset-0 w-5 h-5 text-[var(--accent-blue)] opacity-0 peer-checked:opacity-100 transition-opacity" />
              </div>
              <div className="flex items-center gap-2">
                <Lock className="w-4 h-4 text-slate-400 group-hover:text-[var(--accent-blue)] transition-colors" />
                <span className="text-sm text-slate-300">Change password</span>
              </div>
            </label>

            {formData.changePassword && (
              <div className="space-y-4 pl-8 pt-2">
                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-2">
                    New Password <span className="text-red-400">*</span>
                  </label>
                  <div className="relative">
                    <input
                      type={showPassword ? 'text' : 'password'}
                      value={formData.password}
                      onChange={(e) => handleChange('password', e.target.value)}
                      className={`w-full px-4 py-2.5 pr-12 bg-slate-800/50 border rounded-xl text-slate-50 placeholder-slate-500 focus:outline-none focus:ring-2 transition-all ${
                        errors.password
                          ? 'border-red-500/50 focus:ring-red-500/20'
                          : 'border-slate-700/50 focus:ring-[rgba(41,199,255,0.2)] focus:border-[rgba(41,199,255,0.3)]'
                      }`}
                      placeholder="Minimum 8 characters"
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200 transition-colors"
                    >
                      {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                  {passwordStrength && (
                    <p className={`mt-1.5 text-xs ${passwordStrength.color}`}>
                      Strength: {passwordStrength.label}
                    </p>
                  )}
                  {errors.password && (
                    <p className="mt-1.5 text-xs text-red-400">{errors.password}</p>
                  )}
                </div>

                <div>
                  <label className="block text-sm font-medium text-slate-300 mb-2">
                    Confirm New Password <span className="text-red-400">*</span>
                  </label>
                  <div className="relative">
                    <input
                      type={showConfirmPassword ? 'text' : 'password'}
                      value={formData.confirmPassword}
                      onChange={(e) => handleChange('confirmPassword', e.target.value)}
                      className={`w-full px-4 py-2.5 pr-12 bg-slate-800/50 border rounded-xl text-slate-50 placeholder-slate-500 focus:outline-none focus:ring-2 transition-all ${
                        errors.confirmPassword
                          ? 'border-red-500/50 focus:ring-red-500/20'
                          : 'border-slate-700/50 focus:ring-[rgba(41,199,255,0.2)] focus:border-[rgba(41,199,255,0.3)]'
                      }`}
                      placeholder="Re-enter password"
                    />
                    <button
                      type="button"
                      onClick={() => setShowConfirmPassword(!showConfirmPassword)}
                      className="absolute right-3 top-1/2 -translate-y-1/2 text-slate-400 hover:text-slate-200 transition-colors"
                    >
                      {showConfirmPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                  {formData.confirmPassword && formData.password === formData.confirmPassword && (
                    <p className="mt-1.5 text-xs text-green-400 flex items-center gap-1">
                      <CheckCircle2 className="w-3 h-3" />
                      Passwords match
                    </p>
                  )}
                  {errors.confirmPassword && (
                    <p className="mt-1.5 text-xs text-red-400">{errors.confirmPassword}</p>
                  )}
                </div>
              </div>
            )}
          </div>

          <div className="space-y-3 pt-2">
            <label className="flex items-center gap-3 cursor-pointer group">
              <div className="relative">
                <input
                  type="checkbox"
                  checked={formData.is_admin}
                  onChange={(e) => handleChange('is_admin', e.target.checked)}
                  disabled={isCurrentUser}
                  className="peer sr-only"
                />
                <div className={`w-5 h-5 border-2 border-slate-700 rounded bg-slate-800/50 peer-checked:bg-[rgba(41,199,255,0.1)] peer-checked:border-[rgba(41,199,255,0.5)] transition-all ${
                  isCurrentUser ? 'opacity-50 cursor-not-allowed' : ''
                }`} />
                <CheckCircle2 className="absolute inset-0 w-5 h-5 text-[var(--accent-blue)] opacity-0 peer-checked:opacity-100 transition-opacity" />
              </div>
              <div className="flex items-center gap-2">
                <Shield className="w-4 h-4 text-slate-400 group-hover:text-[var(--accent-blue)] transition-colors" />
                <span className="text-sm text-slate-300">Admin privileges</span>
                {isCurrentUser && (
                  <span className="text-xs text-slate-500">(cannot change for yourself)</span>
                )}
              </div>
            </label>
            {errors.is_admin && (
              <p className="text-xs text-red-400 pl-8">{errors.is_admin}</p>
            )}

            <label className="flex items-center gap-3 cursor-pointer group">
              <div className="relative">
                <input
                  type="checkbox"
                  checked={formData.is_active}
                  onChange={(e) => handleChange('is_active', e.target.checked)}
                  disabled={isCurrentUser}
                  className="peer sr-only"
                />
                <div className={`w-5 h-5 border-2 border-slate-700 rounded bg-slate-800/50 peer-checked:bg-[rgba(41,199,255,0.1)] peer-checked:border-[rgba(41,199,255,0.5)] transition-all ${
                  isCurrentUser ? 'opacity-50 cursor-not-allowed' : ''
                }`} />
                <CheckCircle2 className="absolute inset-0 w-5 h-5 text-[var(--accent-blue)] opacity-0 peer-checked:opacity-100 transition-opacity" />
              </div>
              <span className="text-sm text-slate-300">
                Active account
                {isCurrentUser && (
                  <span className="text-xs text-slate-500 ml-2">(cannot change for yourself)</span>
                )}
              </span>
            </label>
            {errors.is_active && (
              <p className="text-xs text-red-400 pl-8">{errors.is_active}</p>
            )}
          </div>

          <div className="flex items-center gap-3 pt-4">
            <Button
              type="submit"
              variant="primary"
              disabled={updateUserMutation.isPending}
              className="flex-1"
            >
              {updateUserMutation.isPending ? 'Saving...' : 'Save Changes'}
            </Button>
            <Button
              type="button"
              variant="secondary"
              onClick={onClose}
              disabled={updateUserMutation.isPending}
            >
              Cancel
            </Button>
          </div>
        </form>
      </div>
    </div>
  )
}

export default UserEditModal
