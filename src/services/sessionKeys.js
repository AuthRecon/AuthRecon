// Everything a signed-in user leaves in localStorage. Cleared together on
// login, logout and session expiry so the next user on the same browser never
// inherits the previous user's AuthRecon token. No imports: api.js and
// authreconToken.js both use this, so it must not create an import cycle.
export const SESSION_KEYS = [
  'auth_token',
  'user',
  'authrecon_access_token',
  'authrecon_access_expires_at',
]

export function clearSessionStorage() {
  for (const key of SESSION_KEYS) {
    localStorage.removeItem(key)
  }
}
