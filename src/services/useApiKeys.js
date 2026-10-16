import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import authreconApi from './authreconApi';
import { AI_STATUS_KEY } from './useAiStatus';

// Uses the authenticated AuthRecon client (portal proxy + bearer token).
const invalidate = (queryClient) => {
  queryClient.invalidateQueries({ queryKey: ['api-keys'] });
  queryClient.invalidateQueries({ queryKey: AI_STATUS_KEY });
};

export function useApiKeys() {
  return useQuery({
    queryKey: ['api-keys'],
    queryFn: async () => (await authreconApi.get('api-keys')).data,
  });
}

export function useCreateApiKey() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async ({ name, expires_days, scope = 'full' }) =>
      (await authreconApi.post('api-keys', { name, expires_days, scope })).data,
    onSuccess: () => invalidate(queryClient),
  });
}

export function useRevokeApiKey() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (keyId) => (await authreconApi.delete(`api-keys/${keyId}`)).data,
    onSuccess: () => invalidate(queryClient),
  });
}
