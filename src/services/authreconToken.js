import axios from 'axios'
import api from './api'
import config from '../config'

const AUTHRECON_ACCESS_TOKEN_KEY = 'authrecon_access_token'
const AUTHRECON_ACCESS_EXPIRES_KEY = 'authrecon_access_expires_at'
const TOKEN_EXPIRY_BUFFER_MS = 60 * 1000 // refresh 1 minute before expiry

const sanitizeBaseUrl = (value) => {
  if (!value) return ''
  return value.replace(/\/+$/, '')
}

const AUTHRECON_BASE_URL = sanitizeBaseUrl(config.api.authrecon) || 'http://localhost:9000/apps/authrecon/api/v1'

const authClient = axios.create({
  baseURL: AUTHRECON_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 30000,
})

const getStoredToken = () => {
  const token = localStorage.getItem(AUTHRECON_ACCESS_TOKEN_KEY)
  const expiresAt = localStorage.getItem(AUTHRECON_ACCESS_EXPIRES_KEY)
  if (!token || !expiresAt) {
    return null
  }
  const expires = new Date(expiresAt).getTime()
  if (Number.isNaN(expires)) {
    return null
  }
  if (Date.now() >= expires - TOKEN_EXPIRY_BUFFER_MS) {
    return null
  }
  return { token, expiresAt }
}

const storeToken = (token, expiresAt) => {
  if (token) {
    localStorage.setItem(AUTHRECON_ACCESS_TOKEN_KEY, token)
  } else {
    localStorage.removeItem(AUTHRECON_ACCESS_TOKEN_KEY)
  }
  if (expiresAt) {
    localStorage.setItem(AUTHRECON_ACCESS_EXPIRES_KEY, expiresAt)
  } else {
    localStorage.removeItem(AUTHRECON_ACCESS_EXPIRES_KEY)
  }
}

export const clearAuthReconToken = () => {
  storeToken(null, null)
}

let acquiringTokenPromise = null

const fetchNewAccessToken = async () => {
  // Step 1: ask portal for a service token scoped to AuthRecon
  const serviceResponse = await api.post('/api/tools/auth_recon/service-token')
  const portalToken = serviceResponse.data?.token
  if (!portalToken) {
    throw new Error('Portal did not return a service token for AuthRecon')
  }

  // Step 2: exchange for AuthRecon API access token
  // NOTE: Must use 'api' (portal client with auth headers), not 'authClient'
  // because the portal proxy requires portal authentication
  const authResponse = await api.post('/apps/authrecon/api/v1/auth/portal-login', {
    token: portalToken,
  })

  const accessToken = authResponse.data?.access_token
  const expiresAt = authResponse.data?.expires_at
  if (!accessToken) {
    throw new Error('AuthRecon API did not return an access token')
  }

  storeToken(accessToken, expiresAt || '')
  return accessToken
}

export const ensureAuthReconAccessToken = async () => {
  const existing = getStoredToken()
  if (existing) {
    return existing.token
  }

  if (!acquiringTokenPromise) {
    acquiringTokenPromise = fetchNewAccessToken().finally(() => {
      acquiringTokenPromise = null
    })
  }

  return acquiringTokenPromise
}
