import axios from 'axios'
import { SESSION_CHECK_PATH, shouldLogout } from '../utils/sessionGuard'
import { clearSessionStorage } from './sessionKeys'

// Base API configuration
const API_BASE_URL = import.meta.env.VITE_API_URL || 'http://localhost:9000'

// The session is an HttpOnly cookie set by the portal: page scripts never see
// a token. Cookie-authenticated requests must carry X-Requested-With (CSRF).
export const SESSION_REQUEST = {
  withCredentials: true,
  headers: { 'X-Requested-With': 'AuthRecon' },
}

// Create axios instance
const api = axios.create({
  baseURL: API_BASE_URL,
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
    ...SESSION_REQUEST.headers,
  },
  timeout: 30000, // 30 seconds
})

function logout() {
  clearSessionStorage()
  window.location.href = '/login'
}

// Is the session cookie still accepted? Uses a bare axios call so this check
// can't recurse through the interceptor below.
async function sessionStillValid() {
  try {
    await axios.get(`${API_BASE_URL}${SESSION_CHECK_PATH}`, { ...SESSION_REQUEST, timeout: 10000 })
    return true
  } catch (err) {
    // Only a definite 401 means the session is gone; network errors etc. don't.
    return err.response?.status !== 401
  }
}

// Response interceptor: Handle errors globally
api.interceptors.response.use(
  (response) => response,
  async (error) => {
    // 401: log out only if the session itself is invalid. A single endpoint
    // rejecting a valid token must surface as an error, not a logout.
    if (await shouldLogout({
      status: error.response?.status,
      url: error.config?.url,
      pathname: window.location.pathname,
      checkSession: sessionStillValid,
    })) {
      logout()
    }

    // Handle network errors
    if (!error.response) {
      console.error('Network error:', error.message)
    }

    return Promise.reject(error)
  }
)

export default api
