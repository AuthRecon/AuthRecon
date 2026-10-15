import React, { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import authreconApi from '../../../../services/authreconApi'
import Card from '../../../../components/Card'
import Badge from '../../../../components/Badge'
import Button from '../../../../components/Button'
import { Globe, Code, Lock, AlertTriangle } from 'lucide-react'

const fetchHarData = async (runId) => {
  const response = await authreconApi.get(`runs/${runId}/har`)
  return response.data
}

function HttpFlowViewer({ runId }) {
  const [selectedEntry, setSelectedEntry] = useState(null)
  const [activeTab, setActiveTab] = useState('headers')

  const { data: harData, isLoading, error } = useQuery({
    queryKey: ['authrecon', 'har', runId],
    queryFn: () => fetchHarData(runId),
    enabled: !!runId,
  })

  if (isLoading) {
    return (
      <Card padding="lg">
        <div className="text-center py-8">
          <div className="inline-flex items-center justify-center w-12 h-12 bg-slate-800 rounded-full mb-3">
            <div className="w-6 h-6 border-3 border-slate-600 border-t-blue-500 rounded-full animate-spin" />
          </div>
          <p className="text-slate-400 text-sm">Loading HTTP flow data...</p>
        </div>
      </Card>
    )
  }

  if (error || !harData) {
    return (
      <Card padding="lg">
        <div className="text-center py-8">
          <p className="text-slate-400 text-sm">No HTTP flow data available</p>
        </div>
      </Card>
    )
  }

  const entries = harData?.log?.entries || []

  const getStatusColor = (status) => {
    if (status >= 200 && status < 300) return 'text-green-400'
    if (status >= 300 && status < 400) return 'text-yellow-400'
    if (status >= 400 && status < 500) return 'text-orange-400'
    if (status >= 500) return 'text-rose-400'
    return 'text-slate-400'
  }

  const getMethodColor = (method) => {
    switch (method?.toUpperCase()) {
      case 'GET': return 'bg-blue-500/20 text-blue-400'
      case 'POST': return 'bg-green-500/20 text-green-400'
      case 'PUT': return 'bg-yellow-500/20 text-yellow-400'
      case 'DELETE': return 'bg-rose-500/20 text-rose-400'
      default: return 'bg-slate-500/20 text-slate-400'
    }
  }

  return (
    <Card padding="none">
      <div className="flex h-[600px]">
        {/* Request List */}
        <div className="w-1/3 border-r border-slate-700/50 overflow-y-auto">
          <div className="p-4 border-b border-slate-700/50 bg-slate-900/40">
            <h3 className="text-sm font-medium text-slate-200 flex items-center gap-2">
              <Globe className="w-4 h-4" />
              HTTP Requests ({entries.length})
            </h3>
          </div>
          <div className="divide-y divide-slate-700/30">
            {entries.map((entry, index) => {
              const request = entry.request
              const response = entry.response
              const url = new URL(request.url)
              const path = url.pathname + url.search
              const isSelected = selectedEntry === index

              return (
                <button
                  key={index}
                  onClick={() => setSelectedEntry(index)}
                  className={`w-full text-left px-4 py-3 hover:bg-slate-800/50 transition-colors ${
                    isSelected ? 'bg-slate-800/70' : ''
                  }`}
                >
                  <div className="flex items-center gap-2 mb-1">
                    <Badge className={`text-xs ${getMethodColor(request.method)}`}>
                      {request.method}
                    </Badge>
                    <span className={`text-sm font-mono ${getStatusColor(response.status)}`}>
                      {response.status}
                    </span>
                  </div>
                  <p className="text-xs text-slate-300 truncate" title={path}>
                    {path}
                  </p>
                  <p className="text-xs text-slate-500 mt-1">
                    {url.hostname}
                  </p>
                </button>
              )
            })}
          </div>
        </div>

        {/* Request/Response Details */}
        <div className="flex-1 overflow-y-auto">
          {selectedEntry !== null ? (
            <RequestResponseView entry={entries[selectedEntry]} activeTab={activeTab} setActiveTab={setActiveTab} />
          ) : (
            <div className="flex items-center justify-center h-full text-slate-500 text-sm">
              Select a request to view details
            </div>
          )}
        </div>
      </div>
    </Card>
  )
}

function RequestResponseView({ entry, activeTab, setActiveTab }) {
  const { request, response } = entry
  const url = new URL(request.url)

  const tabs = [
    { id: 'headers', label: 'Headers' },
    { id: 'cookies', label: 'Cookies' },
    { id: 'response', label: 'Response' },
  ]

  return (
    <div className="h-full flex flex-col">
      {/* URL Header */}
      <div className="p-4 border-b border-slate-700/50 bg-slate-900/40">
        <div className="flex items-center gap-2 mb-2">
          <Badge className={`text-xs ${
            request.method === 'GET' ? 'bg-blue-500/20 text-blue-400' :
            request.method === 'POST' ? 'bg-green-500/20 text-green-400' :
            'bg-slate-500/20 text-slate-400'
          }`}>
            {request.method}
          </Badge>
          <span className="text-sm text-slate-300">{response.status} {response.statusText}</span>
          {response.status >= 400 && <AlertTriangle className="w-4 h-4 text-rose-400" />}
          {url.protocol === 'https:' && <Lock className="w-4 h-4 text-green-400" />}
        </div>
        <p className="text-sm text-slate-400 font-mono break-all">{request.url}</p>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-slate-700/50 bg-slate-900/20">
        {tabs.map(tab => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={`px-4 py-2 text-sm font-medium transition-colors ${
              activeTab === tab.id
                ? 'text-slate-200 border-b-2 border-blue-500'
                : 'text-slate-500 hover:text-slate-300'
            }`}
          >
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      <div className="flex-1 overflow-y-auto p-4">
        {activeTab === 'headers' && (
          <div className="space-y-4">
            <div>
              <h4 className="text-xs uppercase text-slate-500 mb-2 flex items-center gap-2">
                <Code className="w-3 h-3" />
                Request Headers
              </h4>
              <div className="space-y-1 font-mono text-xs">
                {request.headers.map((header, i) => (
                  <div key={i} className="flex gap-2">
                    <span className="text-slate-400">{header.name}:</span>
                    <span className="text-slate-300 break-all">{header.value}</span>
                  </div>
                ))}
              </div>
            </div>
            <div>
              <h4 className="text-xs uppercase text-slate-500 mb-2">Response Headers</h4>
              <div className="space-y-1 font-mono text-xs">
                {response.headers.map((header, i) => (
                  <div key={i} className="flex gap-2">
                    <span className="text-slate-400">{header.name}:</span>
                    <span className="text-slate-300 break-all">{header.value}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'cookies' && (
          <div>
            <h4 className="text-xs uppercase text-slate-500 mb-2">Cookies</h4>
            {request.cookies?.length > 0 || response.cookies?.length > 0 ? (
              <div className="space-y-3">
                {request.cookies?.length > 0 && (
                  <div>
                    <p className="text-xs text-slate-400 mb-1">Request Cookies:</p>
                    <div className="space-y-1 font-mono text-xs">
                      {request.cookies.map((cookie, i) => (
                        <div key={i} className="flex gap-2">
                          <span className="text-slate-400">{cookie.name}:</span>
                          <span className="text-slate-300 break-all">{cookie.value}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
                {response.cookies?.length > 0 && (
                  <div>
                    <p className="text-xs text-slate-400 mb-1">Set-Cookie:</p>
                    <div className="space-y-1 font-mono text-xs">
                      {response.cookies.map((cookie, i) => (
                        <div key={i} className="flex gap-2">
                          <span className="text-slate-400">{cookie.name}:</span>
                          <span className="text-slate-300 break-all">{cookie.value}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ) : (
              <p className="text-sm text-slate-500">No cookies</p>
            )}
          </div>
        )}

        {activeTab === 'response' && (
          <div>
            <h4 className="text-xs uppercase text-slate-500 mb-2">Response Body</h4>
            <pre className="bg-slate-900/60 p-3 rounded-sm text-xs text-slate-300 overflow-x-auto">
              {response.content?.text || '(empty response)'}
            </pre>
          </div>
        )}
      </div>
    </div>
  )
}

export default HttpFlowViewer
