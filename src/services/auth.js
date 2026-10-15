import api from './api'
import { clearSessionStorage } from './sessionKeys'

/**
 * Authentication service
 */
export const authService = {
  /**
   * Login with username and password
   * @param {string} username
   * @param {string} password
   * @returns {Promise<{user: object, token: string}>}
   */
  async login(username, password) {
    try {
      const response = await api.post('/api/auth/login', {
        username,
        password,
      })

      // Store token and user info in localStorage
      const { token, user } = response.data
      localStorage.setItem('auth_token', token)
      localStorage.setItem('user', JSON.stringify(user))

      return response.data
    } finally {
      // Never reuse a previous user's AuthRecon token on this browser.
      localStorage.removeItem('authrecon_access_token')
      localStorage.removeItem('authrecon_access_expires_at')
    }
  },

  /**
   * Logout current user
   */
  async logout() {
    try {
      await api.post('/api/auth/logout')
    } catch (error) {
      console.error('Logout error:', error)
    } finally {
      clearSessionStorage()
    }
  },

  /**
   * Check if user is authenticated
   * @returns {boolean}
   */
  isAuthenticated() {
    return !!localStorage.getItem('auth_token')
  },
}
