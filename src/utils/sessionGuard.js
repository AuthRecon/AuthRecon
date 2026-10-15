// Decide whether a failed portal API call should end the session.
//
// Only a 401 can end it, and only once the session itself is confirmed
// invalid: one endpoint rejecting a valid token (a bug, or a route that
// doesn't accept bearer auth) must show an error, not log the user out.

export const SESSION_CHECK_PATH = '/api/auth/me'
const PUBLIC_PATHS = ['/login', '/setup']
const AUTH_CALLS = [SESSION_CHECK_PATH, '/api/auth/login']

/**
 * @param {{status?: number, url?: string, pathname: string, checkSession: () => Promise<boolean>}} args
 * @returns {Promise<boolean>} true if the user should be logged out
 */
export async function shouldLogout({ status, url = '', pathname, checkSession }) {
  if (status !== 401) return false
  if (PUBLIC_PATHS.some((p) => pathname.startsWith(p))) return false
  if (AUTH_CALLS.some((p) => url.includes(p))) return true
  return !(await checkSession())
}
