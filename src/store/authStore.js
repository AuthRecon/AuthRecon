import { create } from 'zustand'
import { authService } from '../services/auth'
import { clearSessionStorage } from '../services/sessionKeys'

/**
 * Authentication store using Zustand
 * Manages user authentication state globally
 */
const useAuthStore = create((set, get) => ({
  // State
  user: null,
  token: null,
  isLoading: false,
  error: null,
  hasHydrated: false,

  // Actions
  /**
   * Initialize auth state from localStorage
   */
  initialize: () => {
    const token = localStorage.getItem('auth_token')
    const user = localStorage.getItem('user')

    if (token && user) {
      try {
        set({
          token,
          user: JSON.parse(user),
          hasHydrated: true,
        })
      } catch (error) {
        console.error('Failed to parse user data:', error)
        clearSessionStorage()
        set({
          user: null,
          token: null,
          hasHydrated: true,
        })
      }
    } else {
      set({
        user: null,
        token: null,
        hasHydrated: true,
      })
    }
  },

  /**
   * Persist authenticated session details
   * @param {object} user
   * @param {string} token
   */
  setSession: (user, token) => {
    localStorage.setItem('auth_token', token)
    localStorage.setItem('user', JSON.stringify(user))

    set({
      user,
      token,
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

      // Update session + state
      get().setSession(data.user, data.token)
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
   * Logout user
   */
  logout: async () => {
    try {
      await authService.logout()
    } finally {
      // Clear state
      set({
        user: null,
        token: null,
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
    return !!get().token
  },
}))

export default useAuthStore
