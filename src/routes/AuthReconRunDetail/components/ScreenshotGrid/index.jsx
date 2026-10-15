import React, { useState, useEffect } from 'react'
import Card from '../../../../components/Card'
import Badge from '../../../../components/Badge'
import authreconApi from '../../../../services/authreconApi'

// Helper to extract URL from description or return null
const extractUrlFromDescription = (description) => {
  if (!description) return null
  const match = description.match(/at (https?:\/\/[^\s]+)/)
  return match ? match[1] : null
}

function ScreenshotGrid({ screenshots }) {
  const [imageUrls, setImageUrls] = useState({})

  // Fetch images as blobs to avoid CORS issues
  useEffect(() => {
    const fetchImages = async () => {
      const urls = {}
      for (const screenshot of screenshots) {
        try {
          // Extract the path after /api/v1
          const path = screenshot.download_url.split('/api/v1/')[1]
          const response = await authreconApi.get(path, {
            responseType: 'blob'
          })
          urls[screenshot.id] = URL.createObjectURL(response.data)
        } catch (error) {
          console.error(`Failed to load image ${screenshot.id}:`, error)
        }
      }
      setImageUrls(urls)
    }

    if (screenshots && screenshots.length > 0) {
      fetchImages()
    }

    // Cleanup blob URLs
    return () => {
      Object.values(imageUrls).forEach(url => URL.revokeObjectURL(url))
    }
  }, [screenshots])

  const [lightboxOpen, setLightboxOpen] = useState(false)
  const [currentIndex, setCurrentIndex] = useState(0)

  if (!screenshots || screenshots.length === 0) {
    return (
      <Card padding="lg">
        <h3 className="text-lg font-semibold text-slate-50 mb-4">
          Screenshots
        </h3>
        <div className="py-8 text-center">
          <p className="text-sm text-slate-400">
            No screenshots captured for this run
          </p>
        </div>
      </Card>
    )
  }

  const openLightbox = (index) => {
    setCurrentIndex(index)
    setLightboxOpen(true)
  }

  const closeLightbox = () => {
    setLightboxOpen(false)
  }

  const goToPrevious = () => {
    setCurrentIndex((prev) => (prev > 0 ? prev - 1 : screenshots.length - 1))
  }

  const goToNext = () => {
    setCurrentIndex((prev) => (prev < screenshots.length - 1 ? prev + 1 : 0))
  }

  // Handle keyboard navigation
  React.useEffect(() => {
    if (!lightboxOpen) return

    const handleKeyDown = (e) => {
      if (e.key === 'Escape') closeLightbox()
      if (e.key === 'ArrowLeft') goToPrevious()
      if (e.key === 'ArrowRight') goToNext()
    }

    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [lightboxOpen])

  const currentShot = screenshots[currentIndex]

  return (
    <>
      <Card padding="lg">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-lg font-semibold text-slate-50">
            Screenshots
          </h3>
          <span className="text-sm text-slate-500">
            {screenshots.length} {screenshots.length === 1 ? 'capture' : 'captures'}
          </span>
        </div>

        {/* Larger Grid - 3 columns on desktop */}
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {screenshots.map((screenshot, idx) => (
            <div
              key={screenshot.id}
              onClick={() => openLightbox(idx)}
              className="group relative bg-(--bg-2) rounded-lg overflow-hidden border border-(--stroke-dark) hover:border-(--stroke-blue) cursor-pointer transition-all"
            >
              {/* Larger aspect ratio for better viewing */}
              <div className="aspect-4/3 relative">
                {imageUrls[screenshot.id] ? (
                  <img
                    src={imageUrls[screenshot.id]}
                    alt={screenshot.description || screenshot.name}
                    className="w-full h-full object-cover group-hover:scale-105 transition-transform duration-300"
                  />
                ) : (
                  <div className="w-full h-full flex items-center justify-center bg-slate-800/50">
                    <div className="w-8 h-8 border-4 border-[rgba(41,199,255,0.3)] border-t-(--accent-blue) rounded-full animate-spin" />
                  </div>
                )}
                <div className="absolute inset-0 bg-linear-to-t from-slate-900 via-transparent to-transparent opacity-0 group-hover:opacity-100 transition-opacity" />
              </div>

              {/* Always visible caption */}
              <div className="p-3 border-t border-(--stroke-dark) bg-(--bg-1)">
                <p className="text-sm font-medium text-slate-300 mb-1 truncate">
                  {screenshot.description || screenshot.name}
                </p>
                {extractUrlFromDescription(screenshot.description) && (
                  <p className="text-xs text-(--accent-blue) mb-1 truncate font-mono">
                    {extractUrlFromDescription(screenshot.description)}
                  </p>
                )}
                <p className="text-xs text-slate-500 truncate">
                  {screenshot.name}
                </p>
              </div>

              {/* Hover overlay with "View" */}
              <div className="absolute inset-0 flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity">
                <div className="bg-(--accent-blue)/90 text-white px-4 py-2 rounded-lg text-sm font-medium">
                  Click to view full size
                </div>
              </div>
            </div>
          ))}
        </div>
      </Card>

      {/* Enhanced Lightbox Modal */}
      {lightboxOpen && currentShot && (
        <div
          className="fixed inset-0 z-9999 bg-black/95"
          onClick={closeLightbox}
        >
          {/* Close Button - Top Right */}
          <button
            onClick={closeLightbox}
            className="absolute top-4 right-4 z-10000 w-12 h-12 flex items-center justify-center rounded-lg bg-black/70 hover:bg-black/50 text-slate-300 hover:text-white transition-colors border border-(--stroke-blue)"
            title="Close (ESC)"
          >
            <svg className="w-6 h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2}>
              <path strokeLinecap="round" strokeLinejoin="round" d="M6 18L18 6M6 6l12 12" />
            </svg>
          </button>

          {/* Info Bar - Top */}
          <div className="absolute top-4 left-4 right-20 z-10000 bg-(--bg-1) border border-(--stroke-blue) rounded-lg px-6 py-4 shadow-(--shadow-card-strong) max-h-32 overflow-y-auto" onClick={(e) => e.stopPropagation()}>
            <h3 className="text-sm font-semibold text-white mb-2 line-clamp-2">
              {currentShot.description || currentShot.name}
            </h3>
            {extractUrlFromDescription(currentShot.description) && (
              <div className="mb-3 p-2 bg-(--bg-2) border border-(--stroke-blue) rounded-sm max-h-20 overflow-y-auto">
                <p className="text-xs text-(--text-muted) mb-1">Page URL:</p>
                <p className="text-sm text-(--accent-blue) font-mono break-all">
                  {extractUrlFromDescription(currentShot.description)}
                </p>
              </div>
            )}
            <div className="flex flex-wrap items-center gap-3 text-sm">
              <Badge variant="info">
                {currentIndex + 1} of {screenshots.length}
              </Badge>
              <span className="text-slate-400">
                <span className="text-slate-200 font-mono">{currentShot.name}</span>
              </span>
              {currentShot.size_bytes && (
                <span className="text-slate-400">
                  • {(currentShot.size_bytes / 1024).toFixed(1)} KB
                </span>
              )}
            </div>
          </div>

          {/* Main Image */}
          <div className="absolute inset-0 flex items-center justify-center p-32 pt-40">
            {imageUrls[currentShot.id] ? (
              <img
                src={imageUrls[currentShot.id]}
                alt={currentShot.description || currentShot.name}
                className="max-w-full max-h-full object-contain rounded-lg shadow-2xl"
                onClick={(e) => e.stopPropagation()}
              />
            ) : (
              <div className="flex flex-col items-center gap-4">
                <div className="w-12 h-12 border-4 border-[rgba(41,199,255,0.3)] border-t-(--accent-blue) rounded-full animate-spin" />
                <p className="text-slate-400">Loading image...</p>
              </div>
            )}
          </div>

          {/* Previous Button */}
          {screenshots.length > 1 && (
            <button
              onClick={(e) => { e.stopPropagation(); goToPrevious(); }}
              className="absolute left-8 top-1/2 -translate-y-1/2 z-10000 w-14 h-14 flex items-center justify-center rounded-lg bg-(--bg-1) border border-(--stroke-dark) hover:border-(--stroke-blue) text-slate-300 hover:text-white transition-colors backdrop-blur-sm"
              title="Previous (←)"
            >
              <svg className="w-7 h-7" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M15 19l-7-7 7-7" />
              </svg>
            </button>
          )}

          {/* Next Button */}
          {screenshots.length > 1 && (
            <button
              onClick={(e) => { e.stopPropagation(); goToNext(); }}
              className="absolute right-8 top-1/2 -translate-y-1/2 z-10000 w-14 h-14 flex items-center justify-center rounded-lg bg-(--bg-1) border border-(--stroke-dark) hover:border-(--stroke-blue) text-slate-300 hover:text-white transition-colors backdrop-blur-sm"
              title="Next (→)"
            >
              <svg className="w-7 h-7" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={2.5}>
                <path strokeLinecap="round" strokeLinejoin="round" d="M9 5l7 7-7 7" />
              </svg>
            </button>
          )}

          {/* Navigation hint - Bottom */}
          <div className="absolute bottom-6 left-0 right-0 text-center z-10000" onClick={(e) => e.stopPropagation()}>
            <p className="text-sm text-slate-400">
              Use ← → arrow keys to navigate • ESC or click background to close
            </p>
          </div>
        </div>
      )}
    </>
  )
}

export default ScreenshotGrid
