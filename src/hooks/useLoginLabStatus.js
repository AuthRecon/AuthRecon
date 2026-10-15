import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api from '../services/api'

/**
 * Hook to fetch and manage LoginLab status
 */
export function useLoginLabStatus() {
  return useQuery({
    queryKey: ['loginlab-status'],
    queryFn: async () => {
      const response = await api.get('/api/loginlab/status')
      return response.data
    },
    refetchInterval: 30000, // Refetch every 30 seconds to track countdown
    staleTime: 10000,
  })
}

/**
 * Hook to enable LoginLab
 */
export function useEnableLoginLab() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async (durationMinutes = 30) => {
      const response = await api.post(`/api/loginlab/enable?duration_minutes=${durationMinutes}`)
      return response.data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['loginlab-status'] })
    },
  })
}

/**
 * Hook to disable LoginLab
 */
export function useDisableLoginLab() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async () => {
      const response = await api.post('/api/loginlab/disable')
      return response.data
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['loginlab-status'] })
    },
  })
}

export default useLoginLabStatus
