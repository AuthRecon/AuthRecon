/**
 * AuthRecon Targets Story
 *
 * Visualizes scan targets as nodes with identity provider relationships.
 * Primary story for AuthRecon data showing the authentication landscape.
 */

import { SEVERITY_COLORS, AUTH_TYPE_COLORS } from '../../../services/atlas/types'

const authReconTargetsStory = {
  id: 'authrecon-targets',
  name: 'Target Network',
  description: 'Scan targets with identity provider relationships',
  provider: 'authrecon',
  icon: 'Network',

  // Node configuration
  nodeConfig: {
    // Size based on scan count (runs targeting this domain)
    sizeField: 'metadata.runCount',
    sizeMin: 24,
    sizeMax: 60,
    sizeScale: 'sqrt', // 'linear' | 'sqrt' | 'log'

    // Color based on security score
    colorField: 'score',
    colorScale: 'severity', // Use severity-based coloring

    // Show ring indicator for recent scans
    showRing: true,
    ringField: 'score',

    // Glow effect for high-severity nodes
    glowThreshold: 60, // Score above which to show glow
    glowColor: 'severity', // Use severity color for glow

    // Label configuration
    labelField: 'label',
    subtitleField: 'subtitle',

    // Node type differentiation
    shapeByCategory: {
      target: 'circle',
      idp: 'hexagon',
    },
  },

  // Edge configuration
  edgeConfig: {
    // Show edges between targets and IdPs
    showEdges: true,

    // Thickness based on connection strength
    thicknessField: 'strength',
    thicknessMin: 1,
    thicknessMax: 4,

    // Gradient edges
    gradient: true,

    // Animated edges for active connections
    animated: false,

    // Label configuration
    showLabels: false, // Can get cluttered
  },

  // Layout configuration
  layoutConfig: {
    type: 'force', // 'force' | 'radial' | 'cluster'
    forceStrength: -400,
    collisionRadius: 1.5, // Multiplier of node radius
    centerStrength: 0.1,

    // Clustering options
    clusterBy: 'category', // Group by auth type
    clusterPadding: 40,
  },

  // Color palette for this story
  colorPalette: {
    // Severity colors for score-based coloring
    severity: SEVERITY_COLORS,

    // Auth type colors for category-based coloring
    authTypes: AUTH_TYPE_COLORS,

    // Background and UI colors
    background: 'rgba(15, 23, 42, 0.3)', // slate-900/30
    gridLines: 'rgba(51, 65, 85, 0.3)', // slate-700/30
    text: '#94a3b8', // slate-400
    textHighlight: '#f1f5f9', // slate-100

    // Node gradients (CSS gradient strings for SVG)
    nodeGradients: {
      critical: ['#dc2626', '#ef4444'], // red-600 to red-500
      high: ['#ea580c', '#f97316'], // orange-600 to orange-500
      medium: ['#ca8a04', '#eab308'], // yellow-600 to yellow-500
      low: ['#16a34a', '#22c55e'], // green-600 to green-500
      info: ['#2563eb', '#3b82f6'], // blue-600 to blue-500
    },

    // Edge gradients
    edgeDefault: '#475569', // slate-600
  },

  // Legend configuration
  legend: [
    {
      type: 'gradient',
      label: 'Security Score',
      colors: ['#22c55e', '#eab308', '#ef4444'],
      labels: ['Secure', 'Medium', 'At Risk'],
    },
    {
      type: 'divider',
    },
    {
      type: 'circle',
      label: 'OAuth',
      color: AUTH_TYPE_COLORS.oauth,
    },
    {
      type: 'circle',
      label: 'SAML',
      color: AUTH_TYPE_COLORS.saml,
    },
    {
      type: 'circle',
      label: 'Form',
      color: AUTH_TYPE_COLORS.form,
    },
    {
      type: 'circle',
      label: 'LDAP',
      color: AUTH_TYPE_COLORS.ldap,
    },
    {
      type: 'divider',
    },
    {
      type: 'size',
      label: 'Node Size',
      description: 'Scan count',
    },
  ],

  // Filters available for this story
  filters: [
    {
      id: 'authType',
      label: 'Auth Type',
      type: 'multiselect',
      field: 'category',
      options: [
        { value: 'oauth', label: 'OAuth' },
        { value: 'saml', label: 'SAML' },
        { value: 'form', label: 'Form' },
        { value: 'ldap', label: 'LDAP' },
        { value: 'basic', label: 'Basic' },
        { value: 'api_key', label: 'API Key' },
      ],
    },
    {
      id: 'scoreRange',
      label: 'Security Score',
      type: 'range',
      field: 'score',
      min: 0,
      max: 100,
    },
    {
      id: 'nodeType',
      label: 'Node Type',
      type: 'multiselect',
      field: 'metadata.type',
      options: [
        { value: 'target', label: 'Targets' },
        { value: 'idp', label: 'Identity Providers' },
      ],
    },
  ],
}

export default authReconTargetsStory
