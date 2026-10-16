import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import authreconApi from './authreconApi'

// AuthRecon never runs an LLM itself: AI = an external client (Claude Desktop,
// Claude Code, ...) connected to AuthRecon's MCP endpoint with the user's own
// API key. This reports that connection, the admin on/off switch, and the
// per-user "use AI suggestions" preference.
export const AI_STATUS_KEY = ['ai-status']
const API_ACCESS_KEY = ['ai-api-access']

export function useAiStatus(options = {}) {
  return useQuery({
    queryKey: AI_STATUS_KEY,
    queryFn: async () => (await authreconApi.get('ai/status')).data,
    refetchInterval: 30_000,
    refetchOnWindowFocus: false,
    ...options,
  })
}

function useAiMutation(fn, extraKeys = []) {
  const queryClient = useQueryClient()
  return useMutation({
    mutationFn: fn,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: AI_STATUS_KEY })
      extraKeys.forEach((queryKey) => queryClient.invalidateQueries({ queryKey }))
    },
  })
}

export function useUpdateAiPreferences() {
  return useAiMutation(async (prefs) => (await authreconApi.put('ai/preferences', prefs)).data)
}

export function useSetMcpEnabled() {
  return useAiMutation(async (enabled) => (await authreconApi.put('ai/mcp', { enabled })).data)
}

// Admin: runs an AI client starts wait for a person to approve them.
export function useSetMcpApproval() {
  return useAiMutation(async (enabled) => (await authreconApi.put('ai/mcp/approval', { enabled })).data)
}

// Admin: which users may create API/MCP keys.
export function useApiAccess(enabled) {
  return useQuery({
    queryKey: API_ACCESS_KEY,
    queryFn: async () => (await authreconApi.get('ai/api-access')).data,
    enabled,
  })
}

export function useSetApiAccess() {
  return useAiMutation(
    async ({ portalUserId, enabled }) =>
      (await authreconApi.put(`ai/api-access/${encodeURIComponent(portalUserId)}`, { enabled })).data,
    [API_ACCESS_KEY],
  )
}
