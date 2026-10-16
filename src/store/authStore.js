import { create } from 'zustand'
import { authService } from '../services/auth'
import { clearSessionStorage } from '../services/sessionKeys'

/**
 * Authentication store using Zustand
 * Manages user authentication state globally
 */
const useAuthStore = create((set, get) => ({
  // State (the session token is an HttpOnly cookie; `user` means signed in)
  user: null,
  isLoading: false,
  error: null,
  hasHydrated: false,

  // Actions
  /**
   * Initialize auth state from localStorage
   */
  initialize: () => {
    // Older versions kept tokens in localStorage; drop them.
    for (const key of ['auth_token', 'authrecon_access_token', 'authrecon_access_expires_at']) {
      localStorage.removeItem(key)
    }
    const user = localStorage.getItem('user')

    if (user) {
      try {
        set({
          user: JSON.parse(user),
          hasHydrated: true,
        })
      } catch (error) {
        console.error('Failed to parse user data:', error)
        clearSessionStorage()
        set({
          user: null,
          hasHydrated: true,
        })
      }
    } else {
      set({
        user: null,
        hasHydrated: true,
      })
    }
  },

  /**
   * Record who signed in (the portal has already set the session cookie)
   * @param {object} user
   */
  setSession: (user) => {
    localStorage.setItem('user', JSON.stringify(user))

    set({
      user,
      error: null,
      hasHydrated: true,
    })
  },

  /**
   * Login user
   * @param {string} username
   * @param {string} password
   */
  login: async (username, password) => {
    set({ isLoading: true, error: null })

    try {
      const data = await authService.login(username, password)
      if (data.mfa_required) {
        set({ isLoading: false, error: null })
        return data // Login.jsx asks for the code next
      }

      // Update session + state
      get().setSession(data.user)
      set({
        isLoading: false,
        error: null,
      })

      return data
    } catch (error) {
      const errorMessage = error.response?.data?.detail || 'Login failed'
      set({
        error: errorMessage,
        isLoading: false,
      })
      throw error
    }
  },

  /**
   * Second login step (two-factor code)
   */
  verifyMfa: async (mfaToken, code) => {
    set({ isLoading: true, error: null })
    try {
      const data = await authService.verifyMfa(mfaToken, code)
      get().setSession(data.user)
      set({ isLoading: false, error: null })
      return data
    } catch (error) {
      set({ error: error.response?.data?.detail || 'Verification failed', isLoading: false })
      throw error
    }
  },

  /**
   * Logout user
   */
  logout: async () => {
    try {
      await authService.logout()
    } finally {
      // Clear state
      set({
        user: null,
        error: null,
        hasHydrated: true,
      })
    }
  },

  /**
   * Clear error
   */
  clearError: () => {
    set({ error: null })
  },

  /**
   * Check if user is authenticated
   */
  isAuthenticated: () => {
    return !!get().user
  },
}))

export default useAuthStore
