/**
 * Application configuration
 * Centralized config for API endpoints and feature flags
 */

const config = {
  // API Base URLs
  api: {
    base: import.meta.env.VITE_API_URL || 'http://localhost:9000',
    portal: import.meta.env.VITE_PORTAL_API || 'http://localhost:9000',
    authrecon: import.meta.env.VITE_AUTHRECON_API || 'http://localhost:9000/apps/authrecon/api/v1',
  },

  // WebSocket URLs (if needed)
  ws: {
    base: import.meta.env.VITE_WS_URL || 'ws://localhost:9000/ws',
  },

  // Feature flags
  features: {
    atlas: true,
    authrecon: true,
  },

  // App metadata
  app: {
    name: 'AuthRecon Suite',
    environment: import.meta.env.MODE || 'development',
  },
}

export default config
