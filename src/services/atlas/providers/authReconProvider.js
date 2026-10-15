/**
 * AuthRecon Data Provider
 *
 * Fetches and normalizes AuthRecon run data for Atlas visualization.
 * Transforms scan runs into nodes (targets) and edges (IdP relationships).
 */

import authreconApi from '../../authreconApi'
import {
  scoreToSeverity,
  severityToColor,
  authTypeToColor,
  invertSecurityScore,
} from '../types'

/**
 * Extract domain from URL
 * @param {string} url - Full URL
 * @returns {string} Domain name
 */
const extractDomain = (url) => {
  try {
    const urlObj = new URL(url)
    return urlObj.hostname
  } catch {
    return url
  }
}

/**
 * Detect identity provider from redirect chain or OAuth configuration
 * @param {Object} run - AuthRecon run data
 * @returns {Object|null} IdP info with name and type
 */
const detectIdentityProvider = (run) => {
  const results = run.results || {}
  const redirectChain = results.redirect_chain || []
  const oauthConfig = results.oauth_config || {}
  const samlConfig = results.saml_config || {}

  // Check redirect chain for known IdPs
  const idpPatterns = [
    { pattern: /login\.microsoftonline\.com|login\.windows\.net/i, name: 'Azure AD', type: 'oauth' },
    { pattern: /okta\.com/i, name: 'Okta', type: 'oauth' },
    { pattern: /auth0\.com/i, name: 'Auth0', type: 'oauth' },
    { pattern: /accounts\.google\.com/i, name: 'Google', type: 'oauth' },
    { pattern: /ping(one|identity|federate)/i, name: 'PingIdentity', type: 'saml' },
    { pattern: /adfs/i, name: 'ADFS', type: 'saml' },
    { pattern: /sso\./i, name: 'SSO Gateway', type: 'oauth' },
    { pattern: /idp\./i, name: 'Identity Provider', type: 'saml' },
  ]

  // Check redirects
  for (const redirect of redirectChain) {
    const url = redirect.url || redirect
    for (const { pattern, name, type } of idpPatterns) {
      if (pattern.test(url)) {
        return { name, type, url: extractDomain(url) }
      }
    }
  }

  // Check OAuth authorization endpoint
  if (oauthConfig.authorization_endpoint) {
    for (const { pattern, name, type } of idpPatterns) {
      if (pattern.test(oauthConfig.authorization_endpoint)) {
        return { name, type, url: extractDomain(oauthConfig.authorization_endpoint) }
      }
    }
  }

  // Check SAML IdP
  if (samlConfig.idp_entity_id || samlConfig.idp_sso_url) {
    const samlUrl = samlConfig.idp_sso_url || samlConfig.idp_entity_id
    for (const { pattern, name, type } of idpPatterns) {
      if (pattern.test(samlUrl)) {
        return { name, type, url: extractDomain(samlUrl) }
      }
    }
    return { name: 'SAML IdP', type: 'saml', url: extractDomain(samlUrl) }
  }

  return null
}

/**
 * Fetch all AuthRecon runs
 * @returns {Promise<Array>} Array of run data
 */
export const fetchRuns = async () => {
  const response = await authreconApi.get('runs')
  return Array.isArray(response.data) ? response.data : []
}

/**
 * Fetch a single AuthRecon run with full details
 * @param {string} runId - Run ID
 * @returns {Promise<Object>} Run data
 */
export const fetchRun = async (runId) => {
  const response = await authreconApi.get(`runs/${runId}`)
  return response.data
}

/**
 * Transform AuthRecon runs into normalized Atlas data
 * @param {Array} runs - Array of AuthRecon runs
 * @returns {Object} Normalized Atlas data with nodes and edges
 */
export const normalizeData = (runs) => {
  const safeRuns = Array.isArray(runs) ? runs : []

  // Group runs by target domain
  const targetMap = new Map()
  const idpMap = new Map()
  const targetIdpConnections = new Map() // Track target -> IdP connections

  safeRuns.forEach((run) => {
    if (!run.target_url) return

    const domain = extractDomain(run.target_url)
    const existing = targetMap.get(domain) || {
      id: `target-${domain}`,
      domain,
      runs: [],
      authTypes: new Set(),
      totalScore: 0,
      scoreCount: 0,
      latestRun: null,
    }

    existing.runs.push(run)
    if (run.auth_type) {
      existing.authTypes.add(run.auth_type.toLowerCase())
    }

    // Track security scores
    const score = run.results?.overall_security_score
    if (typeof score === 'number') {
      existing.totalScore += score
      existing.scoreCount += 1
    }

    // Track latest run
    if (!existing.latestRun || new Date(run.submitted_at) > new Date(existing.latestRun.submitted_at)) {
      existing.latestRun = run
    }

    targetMap.set(domain, existing)

    // Detect and track IdP
    const idp = detectIdentityProvider(run)
    if (idp) {
      const idpId = `idp-${idp.name.replace(/\s+/g, '-').toLowerCase()}`

      if (!idpMap.has(idpId)) {
        idpMap.set(idpId, {
          id: idpId,
          name: idp.name,
          type: idp.type,
          url: idp.url,
          targets: new Set(),
        })
      }

      idpMap.get(idpId).targets.add(domain)

      // Track connection for edge creation
      const connectionKey = `${domain}|${idpId}`
      const existingConnection = targetIdpConnections.get(connectionKey) || { count: 0 }
      existingConnection.count += 1
      targetIdpConnections.set(connectionKey, existingConnection)
    }
  })

  // Create nodes for targets
  const nodes = []

  targetMap.forEach((target) => {
    const avgScore = target.scoreCount > 0 ? target.totalScore / target.scoreCount : 50
    // AuthRecon: lower score = more secure. We show it as-is but use inverted for severity
    const displayScore = Math.round(avgScore)
    const severity = scoreToSeverity(avgScore) // Higher raw score = worse = higher severity
    const primaryAuthType = Array.from(target.authTypes)[0] || 'unknown'

    nodes.push({
      id: target.id,
      label: target.domain,
      subtitle: `${target.runs.length} scan${target.runs.length !== 1 ? 's' : ''}`,
      score: displayScore,
      severity,
      category: primaryAuthType,
      color: authTypeToColor(primaryAuthType),
      metadata: {
        type: 'target',
        domain: target.domain,
        runCount: target.runs.length,
        authTypes: Array.from(target.authTypes),
        avgSecurityScore: displayScore,
        latestRunId: target.latestRun?.id,
        latestRunStatus: target.latestRun?.status,
        latestRunDate: target.latestRun?.submitted_at,
        results: target.latestRun?.results || {},
      },
    })
  })

  // Create nodes for IdPs
  idpMap.forEach((idp) => {
    nodes.push({
      id: idp.id,
      label: idp.name,
      subtitle: `${idp.targets.size} target${idp.targets.size !== 1 ? 's' : ''}`,
      score: 0, // IdPs don't have a security score
      severity: 'info',
      category: idp.type,
      color: authTypeToColor(idp.type),
      metadata: {
        type: 'idp',
        name: idp.name,
        authType: idp.type,
        url: idp.url,
        targetCount: idp.targets.size,
        targets: Array.from(idp.targets),
      },
    })
  })

  // Create edges between targets and IdPs
  const edges = []
  targetIdpConnections.forEach((connection, key) => {
    const [domain, idpId] = key.split('|')
    const targetId = `target-${domain}`

    edges.push({
      source: targetId,
      target: idpId,
      strength: Math.min(connection.count / 10, 1), // Normalize to 0-1
      label: 'authenticates via',
    })
  })

  // Create edges between targets that share the same IdP
  idpMap.forEach((idp) => {
    const targets = Array.from(idp.targets)
    for (let i = 0; i < targets.length; i++) {
      for (let j = i + 1; j < targets.length; j++) {
        edges.push({
          source: `target-${targets[i]}`,
          target: `target-${targets[j]}`,
          strength: 0.3,
          label: `shared: ${idp.name}`,
          color: authTypeToColor(idp.type),
        })
      }
    }
  })

  return {
    nodes,
    edges,
    metadata: {
      totalRuns: safeRuns.length,
      totalTargets: targetMap.size,
      totalIdPs: idpMap.size,
      lastUpdated: new Date().toISOString(),
    },
  }
}

/**
 * AuthRecon provider interface
 */
const authReconProvider = {
  id: 'authrecon',
  name: 'AuthRecon',
  description: 'Authentication reconnaissance scan data',

  /**
   * Fetch and normalize data
   * @returns {Promise<Object>} Normalized Atlas data
   */
  async getData() {
    const runs = await fetchRuns()
    return normalizeData(runs)
  },

  /**
   * Get details for a specific node
   * @param {string} nodeId - Node ID
   * @returns {Promise<Object>} Node details
   */
  async getNodeDetails(nodeId) {
    // For target nodes, fetch the latest run details
    if (nodeId.startsWith('target-')) {
      const runs = await fetchRuns()
      const domain = nodeId.replace('target-', '')
      const targetRuns = runs.filter((r) => extractDomain(r.target_url) === domain)

      if (targetRuns.length > 0) {
        // Get the most recent run with full details
        const latestRun = targetRuns.sort(
          (a, b) => new Date(b.submitted_at) - new Date(a.submitted_at)
        )[0]

        try {
          const fullRun = await fetchRun(latestRun.id)
          return {
            ...latestRun,
            ...fullRun,
            allRuns: targetRuns,
          }
        } catch {
          return { ...latestRun, allRuns: targetRuns }
        }
      }
    }

    return null
  },
}

export default authReconProvider
