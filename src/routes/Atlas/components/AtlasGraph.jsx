import React, { useEffect, useRef, useMemo, useCallback, useState } from 'react'
import * as d3 from 'd3'
import { SEVERITY_COLORS } from '../../../services/atlas/types'
import NodeTooltip from './NodeTooltip'

/**
 * Atlas Graph Component
 *
 * Enhanced D3.js force-directed graph with:
 * - Story-driven configuration
 * - Gradient and glow effects
 * - Edge rendering with gradients
 * - Multiple layout options
 * - Dynamic sizing and coloring
 */
function AtlasGraph({
  data,
  story,
  selectedNodeId,
  onNodeClick,
  onNodeHover,
  layout = 'force',
  filters = {},
}) {
  const svgRef = useRef(null)
  const simulationRef = useRef(null)
  const containerRef = useRef(null)

  // Tooltip state
  const [tooltipNode, setTooltipNode] = useState(null)
  const [tooltipPosition, setTooltipPosition] = useState(null)

  // Extract configuration from story
  const config = useMemo(() => {
    const nodeConfig = story?.nodeConfig || {}
    const edgeConfig = story?.edgeConfig || {}
    const layoutConfig = story?.layoutConfig || {}
    const colorPalette = story?.colorPalette || {}

    return {
      node: {
        sizeMin: nodeConfig.sizeMin || 20,
        sizeMax: nodeConfig.sizeMax || 60,
        sizeScale: nodeConfig.sizeScale || 'sqrt',
        sizeField: nodeConfig.sizeField || 'score',
        showRing: nodeConfig.showRing ?? false,
        ringWidth: nodeConfig.ringWidth || 3,
        glowThreshold: nodeConfig.glowThreshold,
        glowSeverities: nodeConfig.glowSeverities || ['critical', 'high'],
        pulseThreshold: nodeConfig.pulseThreshold,
      },
      edge: {
        show: edgeConfig.showEdges ?? true,
        thicknessMin: edgeConfig.thicknessMin || 1,
        thicknessMax: edgeConfig.thicknessMax || 4,
        gradient: edgeConfig.gradient ?? true,
        opacity: edgeConfig.opacity ?? 0.6,
        showLabels: edgeConfig.showLabels ?? false,
      },
      layout: {
        type: layout || layoutConfig.type || 'force',
        forceStrength: layoutConfig.forceStrength || -300,
        collisionRadius: layoutConfig.collisionRadius || 1.5,
        centerStrength: layoutConfig.centerStrength || 0.1,
      },
      colors: {
        severity: colorPalette.severity || SEVERITY_COLORS,
        gradients: colorPalette.nodeGradients || {},
        edgeDefault: colorPalette.edgeDefault || '#475569',
        text: colorPalette.text || '#94a3b8',
        textHighlight: colorPalette.textHighlight || '#f1f5f9',
      },
    }
  }, [story, layout])

  // Filter nodes based on active filters
  const filteredData = useMemo(() => {
    if (!data) return { nodes: [], edges: [] }

    let nodes = [...(data.nodes || [])]
    let edges = [...(data.edges || [])]

    // Apply filters
    Object.entries(filters).forEach(([filterId, filterValue]) => {
      if (!filterValue || (Array.isArray(filterValue) && filterValue.length === 0)) return

      const filterConfig = story?.filters?.find((f) => f.id === filterId)
      if (!filterConfig) return

      const field = filterConfig.field
      nodes = nodes.filter((node) => {
        const value = getNestedValue(node, field)
        if (filterConfig.type === 'multiselect') {
          return filterValue.includes(value)
        }
        if (filterConfig.type === 'range') {
          const [min, max] = filterValue
          return value >= min && value <= max
        }
        return true
      })
    })

    // Filter edges to only include those between visible nodes
    const nodeIds = new Set(nodes.map((n) => n.id))
    edges = edges.filter((e) => nodeIds.has(e.source) && nodeIds.has(e.target))

    return { nodes, edges }
  }, [data, filters, story])

  // Calculate node size
  const getNodeSize = useCallback(
    (node) => {
      const field = config.node.sizeField
      const value = getNestedValue(node, field) || 0
      const { sizeMin, sizeMax, sizeScale } = config.node

      // Normalize value (assuming 0-100 range for score, or count-based)
      let normalized
      if (sizeScale === 'sqrt') {
        normalized = Math.sqrt(value) / 10
      } else if (sizeScale === 'log') {
        normalized = Math.log(value + 1) / Math.log(101)
      } else {
        normalized = value / 100
      }

      return sizeMin + normalized * (sizeMax - sizeMin)
    },
    [config]
  )

  // Get node color
  const getNodeColor = useCallback(
    (node) => {
      if (node.color) return node.color
      return config.colors.severity[node.severity] || config.colors.severity.info
    },
    [config]
  )

  // Check if node should glow
  const shouldGlow = useCallback(
    (node) => {
      if (config.node.glowThreshold && node.score >= config.node.glowThreshold) {
        return true
      }
      if (config.node.glowSeverities?.includes(node.severity)) {
        return true
      }
      return false
    },
    [config]
  )

  // Check if node should pulse
  const shouldPulse = useCallback(
    (node) => {
      return config.node.pulseThreshold && node.score >= config.node.pulseThreshold
    },
    [config]
  )

  // Main D3 rendering effect
  useEffect(() => {
    if (!filteredData.nodes.length || !svgRef.current) return

    const svg = d3.select(svgRef.current)
    const width = svgRef.current.clientWidth
    const height = svgRef.current.clientHeight

    // Clear previous visualization
    svg.selectAll('*').remove()

    // Create defs for gradients and filters
    const defs = svg.append('defs')

    // Add glow filter
    const glowFilter = defs.append('filter').attr('id', 'glow').attr('x', '-50%').attr('y', '-50%').attr('width', '200%').attr('height', '200%')

    glowFilter.append('feGaussianBlur').attr('stdDeviation', '4').attr('result', 'coloredBlur')

    const feMerge = glowFilter.append('feMerge')
    feMerge.append('feMergeNode').attr('in', 'coloredBlur')
    feMerge.append('feMergeNode').attr('in', 'SourceGraphic')

    // Add node gradients
    Object.entries(config.colors.gradients).forEach(([severity, colors]) => {
      const gradient = defs
        .append('radialGradient')
        .attr('id', `gradient-${severity}`)
        .attr('cx', '30%')
        .attr('cy', '30%')
        .attr('r', '70%')

      gradient.append('stop').attr('offset', '0%').attr('stop-color', colors[1] || colors[0]).attr('stop-opacity', 1)

      gradient.append('stop').attr('offset', '100%').attr('stop-color', colors[0]).attr('stop-opacity', 0.8)
    })

    // Add edge gradients for each edge
    filteredData.edges.forEach((edge, i) => {
      if (!config.edge.gradient) return

      const sourceNode = filteredData.nodes.find((n) => n.id === edge.source)
      const targetNode = filteredData.nodes.find((n) => n.id === edge.target)
      if (!sourceNode || !targetNode) return

      const gradient = defs.append('linearGradient').attr('id', `edge-gradient-${i}`).attr('gradientUnits', 'userSpaceOnUse')

      gradient.append('stop').attr('offset', '0%').attr('stop-color', getNodeColor(sourceNode)).attr('stop-opacity', 0.6)

      gradient.append('stop').attr('offset', '100%').attr('stop-color', getNodeColor(targetNode)).attr('stop-opacity', 0.6)
    })

    // Add pulse animation
    defs
      .append('style')
      .text(`
        @keyframes pulse {
          0% { opacity: 1; }
          50% { opacity: 0.6; }
          100% { opacity: 1; }
        }
        .pulse {
          animation: pulse 2s ease-in-out infinite;
        }
      `)

    // Create container group for zoom/pan
    const g = svg.append('g')

    // Zoom behavior
    const zoom = d3
      .zoom()
      .scaleExtent([0.3, 4])
      .on('zoom', (event) => {
        g.attr('transform', event.transform)
      })

    svg.call(zoom)

    // Prepare node data with positions
    const nodes = filteredData.nodes.map((node) => ({
      ...node,
      radius: getNodeSize(node),
    }))

    // Prepare edge data
    const edges = filteredData.edges.map((edge, i) => ({
      ...edge,
      index: i,
      sourceNode: nodes.find((n) => n.id === edge.source),
      targetNode: nodes.find((n) => n.id === edge.target),
    }))

    // Create force simulation
    const simulation = d3
      .forceSimulation(nodes)
      .force(
        'charge',
        d3.forceManyBody().strength(config.layout.forceStrength)
      )
      .force('center', d3.forceCenter(width / 2, height / 2).strength(config.layout.centerStrength))
      .force(
        'collision',
        d3.forceCollide().radius((d) => d.radius * config.layout.collisionRadius)
      )

    // Add link force if edges exist
    if (edges.length > 0) {
      simulation.force(
        'link',
        d3
          .forceLink(edges)
          .id((d) => d.id)
          .distance(100)
          .strength((d) => d.strength || 0.5)
      )
    }

    simulationRef.current = simulation

    // Draw edges
    const edgeGroup = g.append('g').attr('class', 'edges')

    const edgeLines = edgeGroup
      .selectAll('.edge')
      .data(edges.filter((e) => e.sourceNode && e.targetNode))
      .enter()
      .append('line')
      .attr('class', 'edge')
      .attr('stroke', (d, i) => (config.edge.gradient ? `url(#edge-gradient-${i})` : d.color || config.colors.edgeDefault))
      .attr('stroke-width', (d) => {
        const strength = d.strength || 0.5
        return config.edge.thicknessMin + strength * (config.edge.thicknessMax - config.edge.thicknessMin)
      })
      .attr('stroke-opacity', config.edge.opacity)

    // Draw nodes
    const nodeGroup = g.append('g').attr('class', 'nodes')

    const nodeElements = nodeGroup
      .selectAll('.node')
      .data(nodes)
      .enter()
      .append('g')
      .attr('class', 'node')
      .style('cursor', 'pointer')
      .call(
        d3
          .drag()
          .on('start', dragStarted)
          .on('drag', dragged)
          .on('end', dragEnded)
      )
      .on('click', (event, d) => {
        event.stopPropagation()
        onNodeClick?.(d)
      })
      .on('mouseenter', (event, d) => {
        setTooltipNode(d)
        setTooltipPosition({ x: event.clientX, y: event.clientY })
        onNodeHover?.(d, event)
      })
      .on('mousemove', (event) => {
        setTooltipPosition({ x: event.clientX, y: event.clientY })
      })
      .on('mouseleave', () => {
        setTooltipNode(null)
        setTooltipPosition(null)
        onNodeHover?.(null)
      })

    // Node outer glow (for high severity)
    nodeElements
      .filter((d) => shouldGlow(d))
      .append('circle')
      .attr('class', 'glow-ring')
      .attr('r', (d) => d.radius + 8)
      .attr('fill', 'none')
      .attr('stroke', (d) => getNodeColor(d))
      .attr('stroke-width', 2)
      .attr('stroke-opacity', 0.3)
      .attr('filter', 'url(#glow)')

    // Node main circle with gradient
    nodeElements
      .append('circle')
      .attr('class', (d) => `node-circle ${shouldPulse(d) ? 'pulse' : ''}`)
      .attr('r', (d) => d.radius)
      .attr('fill', (d) => {
        const hasGradient = config.colors.gradients[d.severity]
        return hasGradient ? `url(#gradient-${d.severity})` : getNodeColor(d)
      })
      .attr('stroke', (d) => (d.id === selectedNodeId ? '#22d3ee' : 'rgba(30, 41, 59, 0.8)'))
      .attr('stroke-width', (d) => (d.id === selectedNodeId ? 3 : 1.5))

    // Score ring (if enabled)
    if (config.node.showRing) {
      nodeElements.each(function (d) {
        const node = d3.select(this)
        const ringRadius = d.radius + config.node.ringWidth + 2
        const circumference = 2 * Math.PI * ringRadius
        const scorePercent = (d.score || 0) / 100
        const dashLength = circumference * scorePercent

        // Background ring
        node
          .append('circle')
          .attr('class', 'score-ring-bg')
          .attr('r', ringRadius)
          .attr('fill', 'none')
          .attr('stroke', 'rgba(51, 65, 85, 0.4)')
          .attr('stroke-width', config.node.ringWidth)

        // Score progress ring
        node
          .append('circle')
          .attr('class', 'score-ring')
          .attr('r', ringRadius)
          .attr('fill', 'none')
          .attr('stroke', getNodeColor(d))
          .attr('stroke-width', config.node.ringWidth)
          .attr('stroke-dasharray', `${dashLength} ${circumference}`)
          .attr('stroke-linecap', 'round')
          .attr('transform', 'rotate(-90)')
      })
    }

    // Node score/count label (inside node)
    nodeElements
      .filter((d) => d.radius >= 24)
      .append('text')
      .attr('class', 'node-value')
      .attr('dy', 4)
      .attr('text-anchor', 'middle')
      .style('font-size', (d) => `${Math.max(10, d.radius / 3)}px`)
      .style('font-weight', '600')
      .style('fill', '#fff')
      .style('pointer-events', 'none')
      .style('user-select', 'none')
      .text((d) => {
        if (d.metadata?.type === 'idp') return ''
        if (typeof d.score === 'number') return d.score
        return d.metadata?.runCount || ''
      })

    // Node label (below node)
    nodeElements
      .append('text')
      .attr('class', 'node-label')
      .attr('dy', (d) => d.radius + 16)
      .attr('text-anchor', 'middle')
      .style('font-size', '11px')
      .style('fill', config.colors.text)
      .style('pointer-events', 'none')
      .style('user-select', 'none')
      .text((d) => truncateLabel(d.label, 20))

    // Node subtitle (below label)
    nodeElements
      .filter((d) => d.subtitle)
      .append('text')
      .attr('class', 'node-subtitle')
      .attr('dy', (d) => d.radius + 28)
      .attr('text-anchor', 'middle')
      .style('font-size', '9px')
      .style('fill', 'rgba(148, 163, 184, 0.7)')
      .style('pointer-events', 'none')
      .style('user-select', 'none')
      .text((d) => d.subtitle)

    // Update positions on tick
    simulation.on('tick', () => {
      edgeLines
        .attr('x1', (d) => d.source.x)
        .attr('y1', (d) => d.source.y)
        .attr('x2', (d) => d.target.x)
        .attr('y2', (d) => d.target.y)

      // Update edge gradients
      if (config.edge.gradient) {
        edges.forEach((edge, i) => {
          const gradient = defs.select(`#edge-gradient-${i}`)
          if (!gradient.empty()) {
            gradient
              .attr('x1', edge.source.x)
              .attr('y1', edge.source.y)
              .attr('x2', edge.target.x)
              .attr('y2', edge.target.y)
          }
        })
      }

      nodeElements.attr('transform', (d) => `translate(${d.x},${d.y})`)
    })

    // Drag functions
    function dragStarted(event) {
      if (!event.active) simulation.alphaTarget(0.3).restart()
      event.subject.fx = event.subject.x
      event.subject.fy = event.subject.y
    }

    function dragged(event) {
      event.subject.fx = event.x
      event.subject.fy = event.y
    }

    function dragEnded(event) {
      if (!event.active) simulation.alphaTarget(0)
      event.subject.fx = null
      event.subject.fy = null
    }

    // Cleanup
    return () => {
      if (simulationRef.current) {
        simulationRef.current.stop()
      }
    }
  }, [filteredData, config, selectedNodeId, getNodeSize, getNodeColor, shouldGlow, shouldPulse, onNodeClick, onNodeHover])

  return (
    <div ref={containerRef} className="relative w-full h-full bg-slate-900/30 rounded-xl border border-slate-800/50 overflow-hidden">
      <svg ref={svgRef} className="w-full h-full" />

      {/* Empty state */}
      {(!filteredData.nodes || filteredData.nodes.length === 0) && (
        <div className="absolute inset-0 flex items-center justify-center">
          <div className="text-center text-slate-500">
            <p className="text-sm">No data to display</p>
            <p className="text-xs mt-1">Try adjusting filters or selecting a different story</p>
          </div>
        </div>
      )}

      {/* Instructions */}
      <div className="absolute bottom-4 left-4 bg-slate-900/90 backdrop-blur-xs border border-slate-800/50 rounded-lg px-3 py-2">
        <div className="text-xs text-slate-400">Drag to move &bull; Scroll to zoom &bull; Click for details</div>
      </div>

      {/* Tooltip */}
      <NodeTooltip
        node={tooltipNode}
        position={tooltipPosition}
        visible={!!tooltipNode}
      />
    </div>
  )
}

// Helper functions
function getNestedValue(obj, path) {
  if (!path) return obj
  return path.split('.').reduce((current, key) => current?.[key], obj)
}

function truncateLabel(label, maxLength) {
  if (!label || label.length <= maxLength) return label
  return `${label.substring(0, maxLength - 3)}...`
}

export default AtlasGraph
