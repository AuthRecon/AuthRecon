import api from './api'

const licenseApi = {
  getStatus: () => api.get('/api/license/status'),
  refresh: (payload = {}) => api.post('/api/license/check', payload),
}

export default licenseApi
