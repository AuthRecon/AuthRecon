/**
 * Atlas Data Providers Registry
 *
 * Central registry for all data providers.
 * Allows easy addition of new data sources.
 */

import authReconProvider from './authReconProvider'

/**
 * Available providers
 */
const providers = {
  authrecon: authReconProvider,
}

/**
 * Get a provider by ID
 * @param {string} providerId - Provider identifier
 * @returns {Object|null} Provider instance
 */
export const getProvider = (providerId) => {
  return providers[providerId] || null
}

/**
 * Get all available providers
 * @returns {Object[]} Array of provider info
 */
export const getAllProviders = () => {
  return Object.values(providers).map((p) => ({
    id: p.id,
    name: p.name,
    description: p.description,
  }))
}

/**
 * Fetch data from a provider
 * @param {string} providerId - Provider identifier
 * @returns {Promise<Object>} Normalized Atlas data
 */
export const fetchProviderData = async (providerId) => {
  const provider = getProvider(providerId)
  if (!provider) {
    throw new Error(`Unknown provider: ${providerId}`)
  }
  return provider.getData()
}

/**
 * Fetch node details from a provider
 * @param {string} providerId - Provider identifier
 * @param {string} nodeId - Node identifier
 * @returns {Promise<Object>} Node details
 */
export const fetchNodeDetails = async (providerId, nodeId) => {
  const provider = getProvider(providerId)
  if (!provider) {
    throw new Error(`Unknown provider: ${providerId}`)
  }
  return provider.getNodeDetails(nodeId)
}

export default {
  getProvider,
  getAllProviders,
  fetchProviderData,
  fetchNodeDetails,
  providers,
}
