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
   * @returns {Promise<{user: object}>}
   */
  async login(username, password) {
    try {
      const response = await api.post('/api/auth/login', {
        username,
        password,
      })

      // Two-factor accounts: no session yet, the code step comes next (verifyMfa).
      if (response.data.mfa_required) return response.data

      // The session itself is an HttpOnly cookie; keep only who signed in.
      localStorage.setItem('user', JSON.stringify(response.data.user))
      // Admins who must set up two-factor first: the session only reaches the
      // MFA endpoints until they do (AuthGuard sends them to the setup page).
      if (response.data.mfa_enrollment_required) localStorage.setItem('mfa_enroll', '1')
      else localStorage.removeItem('mfa_enroll')

      return response.data
    } finally {
      // A new session gets its own AuthRecon session (the portal also drops the old cookie).
      localStorage.removeItem('authrecon_session_expires_at')
    }
  },

  /**
   * Second login step: exchange the password step's mfa_token and a code
   * (authenticator or backup code) for a session.
   */
  async verifyMfa(mfaToken, code) {
    const response = await api.post('/api/auth/mfa/verify', { mfa_token: mfaToken, code })
    localStorage.setItem('user', JSON.stringify(response.data.user))
    localStorage.removeItem('mfa_enroll')
    localStorage.removeItem('authrecon_session_expires_at')
    return response.data
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
    return !!localStorage.getItem('user')
  },
}
