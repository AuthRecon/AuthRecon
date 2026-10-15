import React, { useState, useCallback, useRef } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Globe, RefreshCw, List, Network } from 'lucide-react'
import Header from '../../components/Header'
import * as d3 from 'd3'
import Button from '../../components/Button'
import Card from '../../components/Card'
import AtlasGraph from './components/AtlasGraph'
import AtlasDetail from './components/AtlasDetail'
import AtlasControls from './components/AtlasControls'
import AtlasLegend from './components/AtlasLegend'
import { fetchProviderData } from '../../services/atlas/providers'
import {
  getAllStories,
  getStory,
  getPersistedStory,
  persistStory,
} from './stories'

/**
 * Atlas Page
 *
 * Modular visualization dashboard with story-driven data display.
 * Shows the hosts and identity providers discovered by AuthRecon runs.
 */
function Atlas() {
  // View mode: graph or list
  const [viewMode, setViewMode] = useState('graph')

  // Story selection
  const [selectedStoryId, setSelectedStoryId] = useState(getPersistedStory)
  const selectedStory = getStory(selectedStoryId)
  const allStories = getAllStories()

  // Node selection
  const [selectedNode, setSelectedNode] = useState(null)

  // Filters
  const [activeFilters, setActiveFilters] = useState({})

  // SVG reference for zoom controls
  const svgRef = useRef(null)

  // Fetch data from provider
  const {
    data: providerData,
    isLoading,
    error,
    refetch,
  } = useQuery({
    queryKey: ['atlas-data', selectedStory?.provider],
    queryFn: () => fetchProviderData(selectedStory?.provider || 'authrecon'),
    enabled: !!selectedStory?.provider,
    refetchInterval: 30000,
    staleTime: 10000,
  })

  // Handle story change
  const handleStoryChange = useCallback((storyId) => {
    setSelectedStoryId(storyId)
    persistStory(storyId)
    setSelectedNode(null)
    setActiveFilters({})
  }, [])

  // Handle node click
  const handleNodeClick = useCallback((node) => {
    setSelectedNode(node)
  }, [])

  // Handle close detail
  const handleCloseDetail = useCallback(() => {
    setSelectedNode(null)
  }, [])

  // Handle filter change
  const handleFilterChange = useCallback((filterId, value) => {
    setActiveFilters((prev) => ({
      ...prev,
      [filterId]: value,
    }))
  }, [])

  // Reset filters
  const handleResetFilters = useCallback(() => {
    setActiveFilters({})
  }, [])

  // Zoom controls
  const handleZoomIn = useCallback(() => {
    const svg = d3.select(svgRef.current?.querySelector('svg'))
    if (!svg.empty()) {
      svg.transition().duration(300).call(
        d3.zoom().scaleBy,
        1.3
      )
    }
  }, [])

  const handleZoomOut = useCallback(() => {
    const svg = d3.select(svgRef.current?.querySelector('svg'))
    if (!svg.empty()) {
      svg.transition().duration(300).call(
        d3.zoom().scaleBy,
        0.7
      )
    }
  }, [])

  const handleFitView = useCallback(() => {
    const svg = d3.select(svgRef.current?.querySelector('svg'))
    if (!svg.empty()) {
      svg.transition().duration(300).call(
        d3.zoom().transform,
        d3.zoomIdentity
      )
    }
  }, [])

  // Get summary metrics
  const metrics = providerData ? {
    totalNodes: providerData.nodes?.length || 0,
    totalEdges: providerData.edges?.length || 0,
    criticalCount: providerData.nodes?.filter((n) => n.severity === 'critical').length || 0,
    highCount: providerData.nodes?.filter((n) => n.severity === 'high').length || 0,
  } : null

  return (
    <div className="h-full flex flex-col">
      <Header
        title="Atlas"
        subtitle={selectedStory?.name || 'Map of the targets your runs have touched'}
        actions={
          <div className="flex items-center gap-2">
              {/* View Toggle */}
              <div className="flex items-center gap-1 p-1 bg-slate-800/50 rounded-lg">
                <button
                  onClick={() => setViewMode('graph')}
                  className={`px-3 py-2 rounded-md transition-colors ${
                    viewMode === 'graph'
                      ? 'bg-(--sidebar-active-bg) text-(--accent-blue)'
                      : 'text-slate-400 hover:text-slate-300'
                  }`}
                  title="Graph View"
                >
                  <Network className="w-4 h-4" />
                </button>
                <button
                  onClick={() => setViewMode('list')}
                  className={`px-3 py-2 rounded-md transition-colors ${
                    viewMode === 'list'
                      ? 'bg-(--sidebar-active-bg) text-(--accent-blue)'
                      : 'text-slate-400 hover:text-slate-300'
                  }`}
                  title="List View"
                >
                  <List className="w-4 h-4" />
                </button>
              </div>

              <Button
                variant="outline"
                onClick={() => refetch()}
                disabled={isLoading}
              >
                <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
                <span>Refresh</span>
              </Button>
          </div>
        }
      />
      {/* Toolbar (z-50 so dropdowns float above the graph) */}
      <div className="border-b border-(--stroke-dark) relative z-50">
        <div className="px-6 py-3">
          {/* Controls bar */}
          <div>
            <AtlasControls
              stories={allStories}
              selectedStory={selectedStory}
              onStoryChange={handleStoryChange}
              filters={selectedStory?.filters}
              activeFilters={activeFilters}
              onFilterChange={handleFilterChange}
              onResetFilters={handleResetFilters}
              onZoomIn={handleZoomIn}
              onZoomOut={handleZoomOut}
              onFitView={handleFitView}
            />
          </div>
        </div>
      </div>

      {/* Summary metrics */}
      {metrics && !isLoading && (
        <div className="px-6 py-3 border-b border-slate-800/30 bg-slate-900/30">
          <div className="flex items-center gap-6 text-sm">
            <div className="flex items-center gap-2">
              <span className="text-slate-500">Nodes:</span>
              <span className="font-semibold text-slate-300">{metrics.totalNodes}</span>
            </div>
            {metrics.totalEdges > 0 && (
              <div className="flex items-center gap-2">
                <span className="text-slate-500">Connections:</span>
                <span className="font-semibold text-slate-300">{metrics.totalEdges}</span>
              </div>
            )}
            {metrics.criticalCount > 0 && (
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-red-500" />
                <span className="text-red-400 font-semibold">{metrics.criticalCount} Critical</span>
              </div>
            )}
            {metrics.highCount > 0 && (
              <div className="flex items-center gap-2">
                <span className="w-2 h-2 rounded-full bg-orange-500" />
                <span className="text-orange-400 font-semibold">{metrics.highCount} High</span>
              </div>
            )}
          </div>
        </div>
      )}

      {/* Content */}
      <div className="flex-1 overflow-hidden relative">
        {isLoading ? (
          <div className="flex items-center justify-center h-full">
            <div className="text-center">
              <div className="inline-flex items-center justify-center w-16 h-16 bg-cyan-500/10 rounded-2xl mb-4">
                <RefreshCw className="w-8 h-8 text-cyan-500 animate-spin" />
              </div>
              <p className="text-slate-400">Loading {selectedStory?.name || 'data'}...</p>
            </div>
          </div>
        ) : error ? (
          <div className="flex items-center justify-center h-full p-8">
            <Card className="max-w-md">
              <div className="p-8 text-center">
                <div className="w-16 h-16 mx-auto mb-4 bg-red-500/10 rounded-2xl flex items-center justify-center">
                  <Globe className="w-8 h-8 text-red-500" />
                </div>
                <h3 className="text-lg font-semibold text-slate-200 mb-2">
                  Error Loading Data
                </h3>
                <p className="text-sm text-slate-400 mb-4">
                  {error.message || 'Failed to fetch data from provider'}
                </p>
                <Button variant="secondary" onClick={() => refetch()}>
                  Try Again
                </Button>
              </div>
            </Card>
          </div>
        ) : !providerData?.nodes || providerData.nodes.length === 0 ? (
          <div className="flex items-center justify-center h-full p-8">
            <Card className="max-w-md">
              <div className="p-8 text-center">
                <div className="w-16 h-16 mx-auto mb-4 bg-slate-800/50 rounded-2xl flex items-center justify-center">
                  <Globe className="w-8 h-8 text-slate-600" />
                </div>
                <h3 className="text-lg font-semibold text-slate-200 mb-2">
                  No Data Found
                </h3>
                <p className="text-sm text-slate-400 mb-4">
                  Run AuthRecon scans to see targets here.
                </p>
                <p className="text-xs text-slate-500">
                  Try selecting a different story or check your data source
                </p>
              </div>
            </Card>
          </div>
        ) : viewMode === 'graph' ? (
          <div ref={svgRef} className="h-full p-6">
            <AtlasGraph
              data={providerData}
              story={selectedStory}
              selectedNodeId={selectedNode?.id}
              onNodeClick={handleNodeClick}
              filters={activeFilters}
            />

            {/* Legend */}
            <AtlasLegend
              story={selectedStory}
              className="absolute top-10 right-10"
            />
          </div>
        ) : (
          <div className="h-full overflow-y-auto p-6">
            <div className="max-w-4xl mx-auto space-y-3">
              {providerData.nodes.map((node) => (
                <Card
                  key={node.id}
                  className={`hover:border-cyan-500/30 transition-colors cursor-pointer ${
                    selectedNode?.id === node.id ? 'border-cyan-500/50' : ''
                  }`}
                  onClick={() => handleNodeClick(node)}
                >
                  <div className="p-4">
                    <div className="flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <div
                          className="w-3 h-3 rounded-full"
                          style={{ backgroundColor: node.color }}
                        />
                        <div>
                          <h3 className="text-sm font-medium text-slate-200">
                            {node.label}
                          </h3>
                          {node.subtitle && (
                            <p className="text-xs text-slate-500">{node.subtitle}</p>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center gap-4">
                        {typeof node.score === 'number' && (
                          <div className="text-right">
                            <div className="text-sm font-semibold text-slate-200">
                              {node.score}
                            </div>
                            <div className="text-xs text-slate-500">score</div>
                          </div>
                        )}
                        <div
                          className="px-2 py-1 rounded-sm text-xs font-medium"
                          style={{
                            backgroundColor: `${getSeverityColor(node.severity)}20`,
                            color: getSeverityColor(node.severity),
                          }}
                        >
                          {node.severity?.toUpperCase()}
                        </div>
                      </div>
                    </div>
                  </div>
                </Card>
              ))}
            </div>
          </div>
        )}

        {/* Node Detail Sidebar */}
        {selectedNode && (
          <AtlasDetail
            node={selectedNode}
            story={selectedStory}
            onClose={handleCloseDetail}
          />
        )}
      </div>
    </div>
  )
}

// Helper function
function getSeverityColor(severity) {
  const colors = {
    critical: '#ef4444',
    high: '#f97316',
    medium: '#eab308',
    low: '#22c55e',
    info: '#3b82f6',
  }
  return colors[severity] || colors.info
}

export default Atlas
