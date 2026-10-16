import axios from 'axios'
import config from '../config'
import { SESSION_REQUEST } from './api'
import { ensureAuthReconSession, clearAuthReconSession } from './authreconToken'

const sanitizeBaseUrl = (value) => {
  if (!value) return ''
  return value.replace(/\/+$/, '')
}

const AUTHRECON_API_BASE_URL = sanitizeBaseUrl(config.api.authrecon) || 'http://localhost:9000/apps/authrecon/api/v1'

// Cookies only (see authreconToken.js): the portal adds the AuthRecon token.
const authreconApi = axios.create({
  baseURL: AUTHRECON_API_BASE_URL,
  withCredentials: true,
  headers: {
    'Content-Type': 'application/json',
    ...SESSION_REQUEST.headers,
  },
  timeout: 30000,
})

authreconApi.interceptors.request.use(
  async (requestConfig) => {
    await ensureAuthReconSession()

    if (typeof requestConfig.url === 'string' && requestConfig.url.startsWith('/')) {
      requestConfig.url = requestConfig.url.slice(1)
    }
    return requestConfig
  },
  (error) => Promise.reject(error),
)

authreconApi.interceptors.response.use(
  (response) => response,
  (error) => {
    // The AuthRecon cookie expired or was replaced: renew it once and retry.
    if (error.response?.status === 401 && error.config && !error.config._authreconRetry) {
      clearAuthReconSession()
      return authreconApi({ ...error.config, _authreconRetry: true })
    }
    if (!error.response) {
      console.error('AuthRecon API network error:', error.message)
    }
    return Promise.reject(error)
  },
)

export default authreconApi
