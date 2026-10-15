import React, { useState, useRef, useEffect } from 'react'
import {
  ChevronDown,
  Network,
  Shield,
  Server,
  Layers,
  Filter,
  RotateCcw,
  ZoomIn,
  ZoomOut,
  Maximize,
} from 'lucide-react'
import Button from '../../../components/Button'

/**
 * Icon mapping for stories
 */
const StoryIcons = {
  Network,
  Shield,
  Server,
  default: Layers,
}

/**
 * Atlas Controls Component
 *
 * Story switcher, filters, and zoom controls for the Atlas visualization.
 */
function AtlasControls({
  stories,
  selectedStory,
  onStoryChange,
  filters,
  activeFilters,
  onFilterChange,
  onResetFilters,
  onZoomIn,
  onZoomOut,
  onFitView,
}) {
  const [isStoryDropdownOpen, setIsStoryDropdownOpen] = useState(false)
  const [isFilterPanelOpen, setIsFilterPanelOpen] = useState(false)
  const dropdownRef = useRef(null)
  const filterRef = useRef(null)

  // Close dropdowns when clicking outside
  useEffect(() => {
    const handleClickOutside = (event) => {
      if (dropdownRef.current && !dropdownRef.current.contains(event.target)) {
        setIsStoryDropdownOpen(false)
      }
      if (filterRef.current && !filterRef.current.contains(event.target)) {
        setIsFilterPanelOpen(false)
      }
    }

    document.addEventListener('click', handleClickOutside)
    return () => document.removeEventListener('click', handleClickOutside)
  }, [])

  const StoryIcon = StoryIcons[selectedStory?.icon] || StoryIcons.default
  const hasActiveFilters = Object.values(activeFilters || {}).some(
    (v) => v && (Array.isArray(v) ? v.length > 0 : true)
  )

  return (
    <div className="flex items-center gap-3">
      {/* Story Selector */}
      <div ref={dropdownRef} className="relative">
        <button
          onClick={() => setIsStoryDropdownOpen(!isStoryDropdownOpen)}
          className="flex items-center gap-2 px-3 py-2 bg-slate-800/60 hover:bg-slate-800 border border-slate-700/50 rounded-lg transition-colors"
        >
          <StoryIcon className="w-4 h-4 text-cyan-400" />
          <span className="text-sm font-medium text-slate-200">
            {selectedStory?.name || 'Select Story'}
          </span>
          <ChevronDown
            className={`w-4 h-4 text-slate-400 transition-transform ${
              isStoryDropdownOpen ? 'rotate-180' : ''
            }`}
          />
        </button>

        {isStoryDropdownOpen && (
          <div className="absolute top-full left-0 mt-2 w-72 bg-slate-900 border border-slate-700/50 rounded-xl shadow-xl z-50 overflow-hidden">
            <div className="p-2">
              {stories.map((story) => {
                const Icon = StoryIcons[story.icon] || StoryIcons.default
                const isSelected = story.id === selectedStory?.id

                return (
                  <button
                    key={story.id}
                    onClick={() => {
                      onStoryChange(story.id)
                      setIsStoryDropdownOpen(false)
                    }}
                    className={`w-full flex items-start gap-3 p-3 rounded-lg transition-colors ${
                      isSelected
                        ? 'bg-cyan-500/20 border border-cyan-500/30'
                        : 'hover:bg-slate-800/50 border border-transparent'
                    }`}
                  >
                    <div
                      className={`p-2 rounded-lg ${
                        isSelected ? 'bg-cyan-500/20' : 'bg-slate-800/50'
                      }`}
                    >
                      <Icon
                        className={`w-4 h-4 ${
                          isSelected ? 'text-cyan-400' : 'text-slate-400'
                        }`}
                      />
                    </div>
                    <div className="flex-1 text-left">
                      <div
                        className={`text-sm font-medium ${
                          isSelected ? 'text-cyan-300' : 'text-slate-200'
                        }`}
                      >
                        {story.name}
                      </div>
                      <div className="text-xs text-slate-500 mt-0.5">
                        {story.description}
                      </div>
                    </div>
                    {isSelected && (
                      <div className="w-2 h-2 rounded-full bg-cyan-500 mt-2" />
                    )}
                  </button>
                )
              })}
            </div>
          </div>
        )}
      </div>

      {/* Filter Button */}
      {filters && filters.length > 0 && (
        <div ref={filterRef} className="relative">
          <button
            onClick={() => setIsFilterPanelOpen(!isFilterPanelOpen)}
            className={`flex items-center gap-2 px-3 py-2 border rounded-lg transition-colors ${
              hasActiveFilters
                ? 'bg-cyan-500/20 border-cyan-500/50 text-cyan-300'
                : 'bg-slate-800/60 hover:bg-slate-800 border-slate-700/50 text-slate-300'
            }`}
          >
            <Filter className="w-4 h-4" />
            <span className="text-sm font-medium">Filters</span>
            {hasActiveFilters && (
              <span className="flex items-center justify-center w-5 h-5 text-xs font-semibold bg-cyan-500 text-white rounded-full">
                {Object.values(activeFilters).filter(
                  (v) => v && (Array.isArray(v) ? v.length > 0 : true)
                ).length}
              </span>
            )}
          </button>

          {isFilterPanelOpen && (
            <div className="absolute top-full right-0 mt-2 w-80 bg-slate-900 border border-slate-700/50 rounded-xl shadow-xl z-50 overflow-hidden">
              <div className="p-4 border-b border-slate-800/50">
                <div className="flex items-center justify-between">
                  <h3 className="text-sm font-semibold text-slate-200">Filters</h3>
                  {hasActiveFilters && (
                    <button
                      onClick={onResetFilters}
                      className="flex items-center gap-1 text-xs text-slate-400 hover:text-slate-200 transition-colors"
                    >
                      <RotateCcw className="w-3 h-3" />
                      Reset
                    </button>
                  )}
                </div>
              </div>

              <div className="p-4 space-y-4 max-h-80 overflow-y-auto">
                {filters.map((filter) => (
                  <FilterControl
                    key={filter.id}
                    filter={filter}
                    value={activeFilters[filter.id]}
                    onChange={(value) => onFilterChange(filter.id, value)}
                  />
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Spacer */}
      <div className="flex-1" />

      {/* Zoom Controls */}
      <div className="flex items-center gap-1 bg-slate-800/60 border border-slate-700/50 rounded-lg p-1">
        <button
          onClick={onZoomOut}
          className="p-2 hover:bg-slate-700/50 rounded-md transition-colors"
          title="Zoom Out"
        >
          <ZoomOut className="w-4 h-4 text-slate-400" />
        </button>
        <button
          onClick={onZoomIn}
          className="p-2 hover:bg-slate-700/50 rounded-md transition-colors"
          title="Zoom In"
        >
          <ZoomIn className="w-4 h-4 text-slate-400" />
        </button>
        <div className="w-px h-4 bg-slate-700" />
        <button
          onClick={onFitView}
          className="p-2 hover:bg-slate-700/50 rounded-md transition-colors"
          title="Fit to View"
        >
          <Maximize className="w-4 h-4 text-slate-400" />
        </button>
      </div>
    </div>
  )
}

/**
 * Individual filter control based on filter type
 */
function FilterControl({ filter, value, onChange }) {
  if (filter.type === 'multiselect') {
    return (
      <div>
        <label className="block text-xs font-medium text-slate-400 mb-2">
          {filter.label}
        </label>
        <div className="flex flex-wrap gap-2">
          {filter.options.map((option) => {
            const isSelected = (value || []).includes(option.value)
            return (
              <button
                key={option.value}
                onClick={() => {
                  const newValue = isSelected
                    ? (value || []).filter((v) => v !== option.value)
                    : [...(value || []), option.value]
                  onChange(newValue.length > 0 ? newValue : null)
                }}
                className={`flex items-center gap-1.5 px-2.5 py-1.5 text-xs rounded-lg border transition-colors ${
                  isSelected
                    ? 'bg-cyan-500/20 border-cyan-500/50 text-cyan-300'
                    : 'bg-slate-800/50 border-slate-700/50 text-slate-400 hover:text-slate-200'
                }`}
              >
                {option.color && (
                  <span
                    className="w-2 h-2 rounded-full"
                    style={{ backgroundColor: option.color }}
                  />
                )}
                {option.label}
              </button>
            )
          })}
        </div>
      </div>
    )
  }

  if (filter.type === 'range') {
    const [min, max] = value || [filter.min, filter.max]
    return (
      <div>
        <label className="block text-xs font-medium text-slate-400 mb-2">
          {filter.label}: {min} - {max}
        </label>
        <div className="flex items-center gap-3">
          <input
            type="range"
            min={filter.min}
            max={filter.max}
            value={min}
            onChange={(e) => onChange([parseInt(e.target.value), max])}
            className="flex-1 accent-cyan-500"
          />
          <input
            type="range"
            min={filter.min}
            max={filter.max}
            value={max}
            onChange={(e) => onChange([min, parseInt(e.target.value)])}
            className="flex-1 accent-cyan-500"
          />
        </div>
      </div>
    )
  }

  return null
}

export default AtlasControls
