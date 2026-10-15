/**
 * Atlas Data Types
 *
 * Common data shapes for normalized visualization data.
 * Uses JSDoc for TypeScript-style type hints without build-time dependencies.
 */

/**
 * @typedef {Object} AtlasNode
 * @property {string} id - Unique node identifier
 * @property {string} label - Display name
 * @property {string} [subtitle] - Secondary text (IP, URL, etc.)
 * @property {number} score - 0-100 for sizing/coloring
 * @property {'critical'|'high'|'medium'|'low'|'info'} severity - Severity level
 * @property {string} category - For grouping (auth_type, asset_type, etc.)
 * @property {Object} metadata - Source-specific data
 * @property {string} [color] - Optional color override
 */

/**
 * @typedef {Object} AtlasEdge
 * @property {string} source - Source node ID
 * @property {string} target - Target node ID
 * @property {number} strength - 0-1 for line thickness
 * @property {string} [label] - Relationship type
 * @property {string} [color] - Optional color override
 */

/**
 * @typedef {Object} AtlasData
 * @property {AtlasNode[]} nodes - Array of nodes
 * @property {AtlasEdge[]} edges - Array of edges
 * @property {Object} [metadata] - Provider-specific metadata
 */

/**
 * @typedef {Object} LegendItem
 * @property {string} label - Legend item label
 * @property {string} color - Color value
 * @property {'circle'|'line'|'gradient'} type - Legend item type
 * @property {string} [description] - Optional description
 */

/**
 * @typedef {Object} StoryConfig
 * @property {string} id - Story identifier
 * @property {string} name - Display name
 * @property {string} description - Story description
 * @property {string} provider - Provider ID to use
 * @property {Object} nodeConfig - Node sizing and coloring rules
 * @property {Object} edgeConfig - Edge relationship rules
 * @property {LegendItem[]} legend - Legend items for this story
 * @property {Object} colorPalette - Colors for this story
 */

/**
 * Severity levels with corresponding colors
 */
export const SEVERITY_COLORS = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
  info: '#3b82f6',
}

/**
 * Auth type accent colors
 */
export const AUTH_TYPE_COLORS = {
  oauth: '#8b5cf6',
  saml: '#06b6d4',
  form: '#ec4899',
  ldap: '#14b8a6',
  basic: '#6366f1',
  api_key: '#f59e0b',
  unknown: '#64748b',
}

/**
 * Node gradient classes for Tailwind
 */
export const NODE_GRADIENTS = [
  'from-sky-500 to-sky-600',
  'from-blue-500 to-cyan-500',
  'from-emerald-500 to-teal-500',
  'from-amber-500 to-orange-500',
]

/**
 * Get severity from a numeric score (0-100)
 * @param {number} score - Score from 0-100
 * @returns {'critical'|'high'|'medium'|'low'|'info'}
 */
export const scoreToSeverity = (score) => {
  if (score >= 80) return 'critical'
  if (score >= 60) return 'high'
  if (score >= 40) return 'medium'
  if (score >= 20) return 'low'
  return 'info'
}

/**
 * Get color from severity level
 * @param {string} severity - Severity level
 * @returns {string} Hex color
 */
export const severityToColor = (severity) => {
  return SEVERITY_COLORS[severity] || SEVERITY_COLORS.info
}

/**
 * Get color from auth type
 * @param {string} authType - Auth type
 * @returns {string} Hex color
 */
export const authTypeToColor = (authType) => {
  const normalized = (authType || 'unknown').toLowerCase().replace(/[^a-z_]/g, '_')
  return AUTH_TYPE_COLORS[normalized] || AUTH_TYPE_COLORS.unknown
}

/**
 * Convert a security score (0-100 where lower is better) to a display score
 * AuthRecon scores: 0 = most secure, 100 = least secure
 * Display: we invert so higher = better for intuitive display
 * @param {number} rawScore - Raw score from 0-100 (lower = better)
 * @returns {number} Display score 0-100 (higher = better)
 */
export const invertSecurityScore = (rawScore) => {
  return 100 - (rawScore || 0)
}

export default {
  SEVERITY_COLORS,
  AUTH_TYPE_COLORS,
  NODE_GRADIENTS,
  scoreToSeverity,
  severityToColor,
  authTypeToColor,
  invertSecurityScore,
}
