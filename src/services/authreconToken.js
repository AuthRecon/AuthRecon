import api from './api'

// AuthRecon's API token is an HttpOnly cookie (ar_api) the portal sets on
// POST /api/auth/authrecon-session and turns into the Authorization header when
// proxying /apps/authrecon/api. Only its expiry is kept here, to know when to
// ask again.
const AUTHRECON_SESSION_EXPIRES_KEY = 'authrecon_session_expires_at'
const EXPIRY_BUFFER_MS = 60 * 1000 // renew 1 minute before expiry

const sessionIsFresh = () => {
  const expiresAt = new Date(localStorage.getItem(AUTHRECON_SESSION_EXPIRES_KEY) || '').getTime()
  return !Number.isNaN(expiresAt) && Date.now() < expiresAt - EXPIRY_BUFFER_MS
}

export const clearAuthReconSession = () => {
  localStorage.removeItem(AUTHRECON_SESSION_EXPIRES_KEY)
}

let pending = null

export const ensureAuthReconSession = async () => {
  if (sessionIsFresh()) return
  if (!pending) {
    pending = api
      .post('/api/auth/authrecon-session')
      .then((response) => {
        localStorage.setItem(AUTHRECON_SESSION_EXPIRES_KEY, response.data?.expires_at || '')
      })
      .finally(() => {
        pending = null
      })
  }
  await pending
}
