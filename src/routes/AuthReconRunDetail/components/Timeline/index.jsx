import React, { useMemo, useState } from 'react'
import Card from '../../../../components/Card'
import TimelineEvent from './TimelineEvent'
import { classifyTimeline } from '../../../../utils/timelineEvents'

const chipClass = (active) => `px-3 py-1.5 rounded-lg text-xs font-medium transition-colors border ${
  active
    ? 'bg-(--sidebar-active-bg) text-(--accent-blue) border-(--stroke-blue)'
    : 'bg-(--bg-1) text-(--text-secondary) border-(--stroke-dark) hover:border-(--stroke-blue)'
}`

function Timeline({ timeline, compact = false }) {
  const [searchQuery, setSearchQuery] = useState('')
  const [filter, setFilter] = useState('all') // all | problems | role:<name>
  const [showDetail, setShowDetail] = useState(false)

  const events = useMemo(() => classifyTimeline(timeline || []), [timeline])
  const roles = useMemo(() => [...new Set(events.map(e => e.role).filter(Boolean))], [events])
  const problemCount = events.filter(e => e.level === 'error' || e.level === 'warning').length
  const detailCount = events.filter(e => e.detail).length

  if (!events.length) {
    return (
      <Card padding="lg">
        <h3 className="text-lg font-semibold text-slate-50 mb-4">Timeline</h3>
        <div className="py-8 text-center">
          <p className="text-sm text-slate-400">No timeline events available for this run</p>
        </div>
      </Card>
    )
  }

  const query = searchQuery.toLowerCase()
  const filtered = events.filter(event => {
    if (!showDetail && event.detail && !query) return false
    if (filter === 'problems' && event.level !== 'error' && event.level !== 'warning') return false
    if (filter.startsWith('role:') && event.role !== filter.slice(5)) return false
    if (query) {
      return event.message.toLowerCase().includes(query) || (event.role || '').toLowerCase().includes(query)
    }
    return true
  })

  return (
    <Card padding="lg">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-lg font-semibold text-slate-50">Timeline</h3>
        <span className="text-sm text-slate-500">
          {filtered.length} of {events.length} events
        </span>
      </div>

      <div className="mb-4 space-y-3">
        <div className="relative">
          <svg className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
            <path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z" />
          </svg>
          <input
            type="text"
            placeholder="Search timeline..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="w-full pl-10 pr-4 py-2 input-field text-sm placeholder-slate-500"
          />
        </div>
        <div className="flex flex-wrap gap-2">
          <button type="button" className={chipClass(filter === 'all')} onClick={() => setFilter('all')}>All</button>
          {problemCount > 0 && (
            <button type="button" className={chipClass(filter === 'problems')} onClick={() => setFilter('problems')}>
              Problems ({problemCount})
            </button>
          )}
          {roles.map(role => (
            <button key={role} type="button" className={chipClass(filter === `role:${role}`)} onClick={() => setFilter(`role:${role}`)}>
              {role}
            </button>
          ))}
          {detailCount > 0 && (
            <button type="button" className={chipClass(showDetail)} onClick={() => setShowDetail(v => !v)}
              title="Low-level discovery and bookkeeping steps">
              {showDetail ? 'Hide' : 'Show'} detail ({detailCount})
            </button>
          )}
        </div>
      </div>

      <div className={`space-y-2 overflow-y-auto scrollbar-thin ${compact ? 'max-h-[600px]' : 'max-h-[75vh]'}`}>
        {filtered.length > 0 ? (
          filtered.map(event => <TimelineEvent key={event.id} event={event} compact={compact} />)
        ) : (
          <div className="py-8 text-center">
            <p className="text-sm text-slate-400">No events match your filters</p>
          </div>
        )}
      </div>
    </Card>
  )
}

export default Timeline
