import React, { Fragment, useEffect, useState } from 'react'
import { Dialog, Transition } from '@headlessui/react'
import { PlayCircle, Code } from 'lucide-react'
import StageConsole from './StageConsole'

function ReplayModal({
  open,
  onClose,
  stages = [],
  timeline = [],
  rawData = {},
}) {
  const [speed, setSpeed] = useState(1)
  const [activeIndex, setActiveIndex] = useState(-1)
  const [expandedStage, setExpandedStage] = useState(null)
  const [showRaw, setShowRaw] = useState(false)

  useEffect(() => {
    if (!open) {
      setActiveIndex(-1)
      return
    }
    setActiveIndex(-1)
    stages.forEach((_, index) => {
      setTimeout(() => setActiveIndex(index), (index + 1) * (250 / speed))
    })
  }, [open, stages, speed])

  return (
    <Transition appear show={open} as={Fragment}>
      <Dialog as="div" className="relative z-50" onClose={onClose}>
        <Transition.Child
          as={Fragment}
          enter="ease-out duration-200"
          enterFrom="opacity-0"
          enterTo="opacity-100"
          leave="ease-in duration-150"
          leaveFrom="opacity-100"
          leaveTo="opacity-0"
        >
          <div className="fixed inset-0 bg-black/70 backdrop-blur-xs" />
        </Transition.Child>

        <div className="fixed inset-0 overflow-y-auto">
          <div className="flex min-h-full items-center justify-center p-4 text-center">
            <Transition.Child
              as={Fragment}
              enter="ease-out duration-200"
              enterFrom="opacity-0 scale-95"
              enterTo="opacity-100 scale-100"
              leave="ease-in duration-150"
              leaveFrom="opacity-100 scale-100"
              leaveTo="opacity-0 scale-95"
            >
              <Dialog.Panel className="w-full max-w-6xl transform rounded-3xl border border-sky-500/40 bg-slate-950/90 p-6 text-left shadow-2xl backdrop-blur-2xl transition-all">
                <div className="flex items-center justify-between mb-4">
                  <Dialog.Title className="text-xl font-semibold text-slate-100 flex items-center gap-2">
                    <PlayCircle className="w-5 h-5 text-sky-400" />
                    Replay Sequence
                  </Dialog.Title>
                  <button
                    onClick={onClose}
                    className="text-sm text-slate-400 hover:text-slate-100 px-3 py-1 rounded-full border border-slate-700/70"
                  >
                    Close
                  </button>
                </div>

                <div className="flex flex-wrap items-center justify-between gap-3 mb-6">
                  <div className="flex items-center gap-2 text-sm text-slate-300">
                    Replay speed:
                    {[1, 2, 4].map((value) => (
                      <button
                        key={value}
                        onClick={() => setSpeed(value)}
                        className={`px-3 py-1 rounded-full border ${
                          speed === value
                            ? 'border-sky-400 bg-sky-500/20 text-sky-200'
                            : 'border-slate-700 text-slate-400 hover:border-slate-500'
                        }`}
                      >
                        {value}×
                      </button>
                    ))}
                  </div>
                  <button
                    onClick={() => setShowRaw((prev) => !prev)}
                    className="text-xs flex items-center gap-1 text-slate-400 hover:text-slate-100"
                  >
                    <Code className="w-4 h-4" />
                    {showRaw ? 'Hide raw events' : 'Show raw events'}
                  </button>
                </div>

                <StageConsole
                  stages={stages}
                  activeIndex={activeIndex}
                  expandedStage={expandedStage}
                  onToggleStage={setExpandedStage}
                  replayLabel={`${speed}×`}
                />

                {showRaw && (
                  <div className="mt-6 rounded-2xl border border-slate-800/80 bg-slate-900/70 p-4">
                    <pre className="text-xs text-slate-200 overflow-x-auto">
                      {JSON.stringify({ timeline, rawData }, null, 2)}
                    </pre>
                  </div>
                )}
              </Dialog.Panel>
            </Transition.Child>
          </div>
        </div>
      </Dialog>
    </Transition>
  )
}

export default ReplayModal
