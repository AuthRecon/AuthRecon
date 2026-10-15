import React, { useState } from 'react'
import { Terminal, Wifi, Zap } from 'lucide-react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import Card from '../../components/Card'
import Button from '../../components/Button'
import Badge from '../../components/Badge'
import Header from '../../components/Header'
import api from '../../services/api'

const TOOLS = [
  { id: 'ping', label: 'Ping', description: 'Send ICMP echo requests (4 packets)', icon: Wifi },
  { id: 'traceroute', label: 'Traceroute', description: 'Trace network path (max 20 hops)', icon: Zap },
  { id: 'nslookup', label: 'DNS Lookup', description: 'Query DNS records', icon: Terminal },
]

const fetchRecentRuns = async () => {
  const response = await api.get('/api/diagnostics/recent')
  return response.data || []
}

function NetworkTools() {
  const queryClient = useQueryClient()
  const [selectedTool, setSelectedTool] = useState('ping')
  const [target, setTarget] = useState('')
  const [isPrivate, setIsPrivate] = useState(false)
  const [currentOutput, setCurrentOutput] = useState(null)

  const { data: recentRuns = [], isLoading: loadingHistory } = useQuery({
    queryKey: ['diagnostics', 'recent'],
    queryFn: fetchRecentRuns,
    refetchOnWindowFocus: false,
  })

  const runToolMutation = useMutation({
    mutationFn: async ({ tool, target, private: isPrivate }) => {
      const response = await api.post('/api/diagnostics/run', {
        tool,
        target,
        private: isPrivate,
      })
      return response.data
    },
    onSuccess: (data) => {
      // Fetch the artifact content
      api.get(`/api/artifacts/${data.artifact_id}/download`, { responseType: 'text' })
        .then((response) => {
          setCurrentOutput({
            tool: data.tool,
            target: data.target,
            exit_code: data.exit_code,
            output: response.data,
          })
        })
      // Refresh history
      queryClient.invalidateQueries(['diagnostics', 'recent'])
    },
    onError: (error) => {
      const message = error.response?.data?.detail || error.message
      alert(`Failed to run ${selectedTool}: ${message}`)
    },
  })

  const handleRun = () => {
    if (!target.trim()) {
      alert('Please enter a target hostname or IP address')
      return
    }
    setCurrentOutput(null)
    runToolMutation.mutate({
      tool: selectedTool,
      target: target.trim(),
      private: isPrivate,
    })
  }

  const handleKeyPress = (e) => {
    if (e.key === 'Enter' && !runToolMutation.isPending) {
      handleRun()
    }
  }

  const selectedToolInfo = TOOLS.find((t) => t.id === selectedTool)

  return (
    <>
      <Header title="Network Tools" subtitle="Diagnostic utilities for troubleshooting connectivity" />
      <div className="flex-1 overflow-y-auto scrollbar-thin p-6">
        <div className="max-w-6xl mx-auto space-y-6">
          {/* Tool Selection */}
          <Card padding="lg">
            <h3 className="text-lg font-semibold text-slate-50 mb-4">Select Tool</h3>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-3">
              {TOOLS.map((tool) => {
                const Icon = tool.icon
                const isSelected = selectedTool === tool.id
                return (
                  <button
                    key={tool.id}
                    onClick={() => setSelectedTool(tool.id)}
                    className={`p-4 rounded-xl border-2 transition-all text-left ${
                      isSelected
                        ? 'border-blue-500 bg-blue-950/20'
                        : 'border-slate-700/60 bg-slate-800/40 hover:border-slate-600'
                    }`}
                  >
                    <div className="flex items-start gap-3">
                      <Icon className={`w-5 h-5 mt-0.5 ${isSelected ? 'text-blue-400' : 'text-slate-400'}`} />
                      <div className="flex-1 min-w-0">
                        <p className={`font-medium mb-1 ${isSelected ? 'text-blue-300' : 'text-slate-300'}`}>
                          {tool.label}
                        </p>
                        <p className="text-xs text-slate-500">{tool.description}</p>
                      </div>
                    </div>
                  </button>
                )
              })}
            </div>
          </Card>

          {/* Target Input */}
          <Card padding="lg">
            <h3 className="text-lg font-semibold text-slate-50 mb-4">
              Run {selectedToolInfo?.label}
            </h3>
            <div className="space-y-4">
              <div>
                <label className="block text-sm text-slate-300 mb-2">
                  Target (hostname or IP address)
                </label>
                <input
                  type="text"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  onKeyPress={handleKeyPress}
                  placeholder="example.com or 8.8.8.8"
                  className="w-full px-4 py-3 bg-slate-800/60 border border-slate-700/60 rounded-xl text-slate-100 placeholder-slate-500 focus:outline-hidden focus:border-blue-500 focus:ring-1 focus:ring-blue-500"
                  disabled={runToolMutation.isPending}
                />
              </div>

              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id="private"
                  checked={isPrivate}
                  onChange={(e) => setIsPrivate(e.target.checked)}
                  className="w-4 h-4 rounded-sm border-slate-600 bg-slate-800 text-blue-500 focus:ring-blue-500 focus:ring-offset-slate-900"
                  disabled={runToolMutation.isPending}
                />
                <label htmlFor="private" className="text-sm text-slate-400 cursor-pointer">
                  Private (don't share asset globally)
                </label>
              </div>

              <div className="flex items-center gap-3">
                <Button
                  variant="primary"
                  onClick={handleRun}
                  loading={runToolMutation.isPending}
                  disabled={!target.trim()}
                  icon={selectedToolInfo?.icon}
                >
                  {runToolMutation.isPending ? 'Running...' : `Run ${selectedToolInfo?.label}`}
                </Button>
                {currentOutput && (
                  <Badge variant={currentOutput.exit_code === 0 ? 'success' : 'danger'}>
                    Exit code: {currentOutput.exit_code}
                  </Badge>
                )}
              </div>
            </div>
          </Card>

          {/* Output */}
          {currentOutput && (
            <Card padding="lg">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-lg font-semibold text-slate-50">
                  Output: {currentOutput.tool} {currentOutput.target}
                </h3>
                <Badge variant={currentOutput.exit_code === 0 ? 'success' : 'danger'}>
                  {currentOutput.exit_code === 0 ? 'Success' : 'Failed'}
                </Badge>
              </div>
              <div className="relative">
                <pre className="p-4 bg-slate-950/60 border border-slate-800/60 rounded-xl text-xs text-slate-300 overflow-x-auto scrollbar-thin font-mono whitespace-pre-wrap break-all max-h-96 overflow-y-auto">
                  {currentOutput.output}
                </pre>
              </div>
            </Card>
          )}

          {/* Recent Runs */}
          {recentRuns.length > 0 && (
            <Card padding="lg">
              <h3 className="text-lg font-semibold text-slate-50 mb-4">Recent Diagnostics</h3>
              <div className="space-y-2">
                {recentRuns.map((run) => (
                  <div
                    key={run.artifact_id}
                    className="p-3 rounded-lg border border-slate-700/60 bg-slate-800/40 hover:border-slate-600 transition-colors"
                  >
                    <div className="flex items-center justify-between gap-4">
                      <div className="flex items-center gap-3 flex-1 min-w-0">
                        <Badge variant="default" className="text-xs uppercase">
                          {run.tool}
                        </Badge>
                        <span className="text-sm text-slate-300 font-mono truncate">
                          {run.target}
                        </span>
                      </div>
                      <div className="flex items-center gap-3">
                        <Badge variant={run.exit_code === 0 ? 'success' : 'danger'} className="text-xs">
                          {run.exit_code === 0 ? '✓' : '✗'}
                        </Badge>
                        <button
                          onClick={() => {
                            api.get(`/api/artifacts/${run.artifact_id}/download`, { responseType: 'text' })
                              .then((response) => {
                                setCurrentOutput({
                                  tool: run.tool,
                                  target: run.target,
                                  exit_code: run.exit_code,
                                  output: response.data,
                                })
                                window.scrollTo({ top: 0, behavior: 'smooth' })
                              })
                              .catch((error) => {
                                alert(`Failed to load output: ${error.message}`)
                              })
                          }}
                          className="text-xs text-blue-400 hover:text-blue-300"
                        >
                          View
                        </button>
                      </div>
                    </div>
                    {run.summary && (
                      <p className="text-xs text-slate-500 mt-1 truncate">{run.summary}</p>
                    )}
                  </div>
                ))}
              </div>
            </Card>
          )}

          {/* Help */}
          <Card padding="lg" className="bg-slate-900/30">
            <h3 className="text-sm font-semibold text-slate-300 mb-3">Usage tips</h3>
            <ul className="text-xs text-slate-400 space-y-1">
              <li>• <strong>Ping</strong>: Test basic connectivity (sends 4 ICMP packets)</li>
              <li>• <strong>Traceroute</strong>: Show network path to target (max 20 hops)</li>
              <li>• <strong>DNS Lookup</strong>: Query DNS records for hostname</li>
              <li>• Press <kbd className="px-1 py-0.5 bg-slate-800 border border-slate-700 rounded-sm text-xs">Enter</kbd> to run</li>
              <li>• Results are stored as encrypted artifacts and linked to assets</li>
            </ul>
          </Card>
        </div>
      </div>
    </>
  )
}

export default NetworkTools
