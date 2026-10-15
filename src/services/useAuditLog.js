import { useQuery } from '@tanstack/react-query'
import api from './api'

export function useAuditLog({ limit = 100, offset = 0, eventType } = {}) {
  return useQuery({
    queryKey: ['portal', 'audit-log', { limit, offset, eventType }],
    queryFn: async () => {
      const params = { limit, offset }
      if (eventType) params.event_type = eventType
      const response = await api.get('/api/admin/audit-log', { params })
      return response.data
    },
    refetchInterval: 30000,
  })
}
