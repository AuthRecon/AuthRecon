/**
 * Security Posture Story
 *
 * Focuses on security scores, highlighting at-risk targets.
 * Emphasizes the security health of the authentication landscape.
 */

import { SEVERITY_COLORS, AUTH_TYPE_COLORS } from '../../../services/atlas/types'

const securityPostureStory = {
  id: 'security-posture',
  name: 'Security Posture',
  description: 'Security health overview with risk highlighting',
  provider: 'authrecon',
  icon: 'Shield',

  // Node configuration
  nodeConfig: {
    // Size based on security score (higher score = larger = more attention)
    sizeField: 'score',
    sizeMin: 20,
    sizeMax: 55,
    sizeScale: 'linear',

    // Color strictly by severity
    colorField: 'severity',
    colorScale: 'categorical',

    // Prominent ring for score visualization
    showRing: true,
    ringField: 'score',
    ringWidth: 4,

    // Strong glow on critical/high severity
    glowThreshold: 40,
    glowIntensity: 'high',
    glowColor: 'severity',

    // Pulse animation for critical nodes
    pulseThreshold: 70,

    // Labels
    labelField: 'label',
    subtitleField: 'subtitle',

    // All nodes are circles in this view
    shapeByCategory: null,
  },

  // Edge configuration - de-emphasized in this view
  edgeConfig: {
    showEdges: true,
    thicknessField: 'strength',
    thicknessMin: 0.5,
    thicknessMax: 2,
    gradient: false,
    opacity: 0.3, // More subtle edges
    showLabels: false,
  },

  // Layout configuration
  layoutConfig: {
    type: 'force',
    forceStrength: -350,
    collisionRadius: 1.8,
    centerStrength: 0.15,

    // Cluster by severity level
    clusterBy: 'severity',
    clusterPadding: 60,
    clusterOrder: ['critical', 'high', 'medium', 'low', 'info'],
  },

  // Color palette emphasizing security states
  colorPalette: {
    severity: {
      critical: '#ef4444',
      high: '#f97316',
      medium: '#eab308',
      low: '#22c55e',
      info: '#64748b', // More muted for info
    },

    // Background highlights risk
    background: 'rgba(15, 23, 42, 0.4)',
    gridLines: 'rgba(51, 65, 85, 0.2)',
    text: '#94a3b8',
    textHighlight: '#f1f5f9',

    // Stronger gradients for severity
    nodeGradients: {
      critical: ['#b91c1c', '#ef4444', '#fca5a5'], // Deep red gradient
      high: ['#c2410c', '#f97316', '#fdba74'],
      medium: ['#a16207', '#eab308', '#fde047'],
      low: ['#15803d', '#22c55e', '#86efac'],
      info: ['#475569', '#64748b', '#94a3b8'],
    },

    edgeDefault: '#334155',
  },

  // Legend focused on security status
  legend: [
    {
      type: 'circle',
      label: 'Critical Risk',
      color: '#ef4444',
      description: 'Score 80-100',
    },
    {
      type: 'circle',
      label: 'High Risk',
      color: '#f97316',
      description: 'Score 60-79',
    },
    {
      type: 'circle',
      label: 'Medium Risk',
      color: '#eab308',
      description: 'Score 40-59',
    },
    {
      type: 'circle',
      label: 'Low Risk',
      color: '#22c55e',
      description: 'Score 20-39',
    },
    {
      type: 'circle',
      label: 'Minimal Risk',
      color: '#64748b',
      description: 'Score 0-19',
    },
    {
      type: 'divider',
    },
    {
      type: 'ring-3',
      label: 'Score Ring',
      description: 'Progress = security score',
    },
  ],

  // Filters for security analysis
  filters: [
    {
      id: 'severity',
      label: 'Risk Level',
      type: 'multiselect',
      field: 'severity',
      options: [
        { value: 'critical', label: 'Critical', color: '#ef4444' },
        { value: 'high', label: 'High', color: '#f97316' },
        { value: 'medium', label: 'Medium', color: '#eab308' },
        { value: 'low', label: 'Low', color: '#22c55e' },
        { value: 'info', label: 'Info', color: '#64748b' },
      ],
    },
    {
      id: 'scoreRange',
      label: 'Score Range',
      type: 'range',
      field: 'score',
      min: 0,
      max: 100,
    },
  ],

  // Summary metrics to show for this story
  metrics: [
    {
      id: 'criticalCount',
      label: 'Critical',
      filter: (node) => node.severity === 'critical',
      color: '#ef4444',
    },
    {
      id: 'highCount',
      label: 'High',
      filter: (node) => node.severity === 'high',
      color: '#f97316',
    },
    {
      id: 'avgScore',
      label: 'Avg Score',
      aggregate: 'average',
      field: 'score',
    },
  ],
}

export default securityPostureStory
