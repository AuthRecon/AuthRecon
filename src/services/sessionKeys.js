// Everything a signed-in user leaves in localStorage (no tokens: the session
// is an HttpOnly cookie). Cleared together on login, logout and session expiry.
// Also clears the token keys older versions stored. No imports: api.js and
// authreconToken.js both use this, so it must not create an import cycle.
export const SESSION_KEYS = [
  'auth_token',
  'user',
  'authrecon_access_token',
  'authrecon_access_expires_at',
  'authrecon_session_expires_at',
  'mfa_enroll',
]

export function clearSessionStorage() {
  for (const key of SESSION_KEYS) {
    localStorage.removeItem(key)
  }
}
