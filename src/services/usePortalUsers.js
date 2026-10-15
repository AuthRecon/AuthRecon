import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import api from './api'

/**
 * Fetch all users from Portal (admin only)
 */
export function usePortalUsers() {
  return useQuery({
    queryKey: ['portal', 'users'],
    queryFn: async () => {
      const response = await api.get('/api/users')
      return response.data
    },
  })
}

/**
 * Create a new user in Portal (admin only)
 */
export function useCreatePortalUser() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async (userData) => {
      const response = await api.post('/api/users', userData)
      return response.data
    },
    onSuccess: () => {
      queryClient.invalidateQueries(['portal', 'users'])
    },
  })
}

/**
 * Update an existing user in Portal (admin only)
 */
export function useUpdatePortalUser() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async ({ userId, data }) => {
      const response = await api.patch(`/api/users/${userId}`, data)
      return response.data
    },
    onSuccess: () => {
      queryClient.invalidateQueries(['portal', 'users'])
    },
  })
}

/**
 * Delete a user from Portal (admin only)
 */
export function useDeletePortalUser() {
  const queryClient = useQueryClient()

  return useMutation({
    mutationFn: async (userId) => {
      await api.delete(`/api/users/${userId}`)
    },
    onSuccess: () => {
      queryClient.invalidateQueries(['portal', 'users'])
    },
  })
}

/**
 * Change own password (requires current password)
 */
export function useChangeOwnPassword() {
  return useMutation({
    mutationFn: async (payload) => {
      await api.post('/api/users/me/change-password', payload)
    },
  })
}

/**
 * Reset user password (admin only, no current password required)
 */
export function useResetUserPassword() {
  return useMutation({
    mutationFn: async ({ userId, newPassword }) => {
      await api.post(`/api/users/${userId}/reset-password`, {
        new_password: newPassword,
      })
    },
  })
}
