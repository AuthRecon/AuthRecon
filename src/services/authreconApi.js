import axios from 'axios'
import config from '../config'
import { ensureAuthReconAccessToken, clearAuthReconToken } from './authreconToken'

const sanitizeBaseUrl = (value) => {
  if (!value) return ''
  return value.replace(/\/+$/, '')
}

const AUTHRECON_API_BASE_URL = sanitizeBaseUrl(config.api.authrecon) || 'http://localhost:9000/apps/authrecon/api/v1'

const authreconApi = axios.create({
  baseURL: AUTHRECON_API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
  timeout: 30000,
})

authreconApi.interceptors.request.use(
  async (requestConfig) => {
    // Get AuthRecon token for the backend
    const authreconToken = await ensureAuthReconAccessToken()
    if (authreconToken) {
      requestConfig.headers.Authorization = `Bearer ${authreconToken}`
    }

    // ALSO need portal token for the proxy auth check
    // The portal proxy requires portal auth before forwarding
    const portalToken = localStorage.getItem('auth_token')
    if (portalToken) {
      // Send portal token in custom header that proxy can check
      requestConfig.headers['X-Portal-Token'] = `Bearer ${portalToken}`
    }

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
    if (error.response?.status === 401) {
      clearAuthReconToken()
    }
    if (!error.response) {
      console.error('AuthRecon API network error:', error.message)
    }
    return Promise.reject(error)
  },
)

export default authreconApi
