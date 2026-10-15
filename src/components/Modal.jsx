import React, { Fragment } from 'react'
import { Dialog, Transition } from '@headlessui/react'
import { X } from 'lucide-react'
import Button from './Button'

/**
 * Modal Component
 * Dialog overlay using Headless UI
 */
function Modal({
  isOpen,
  onClose,
  title,
  description,
  children,
  footer,
  size = 'md',
  closeButton = true,
}) {
  const sizes = {
    sm: 'max-w-md',
    md: 'max-w-lg',
    lg: 'max-w-2xl',
    xl: 'max-w-4xl',
    full: 'max-w-7xl',
  }

  return (
    <Transition appear show={isOpen} as={Fragment}>
      <Dialog as="div" className="relative z-50" onClose={onClose}>
        {/* Backdrop */}
        <Transition.Child
          as={Fragment}
          enter="ease-out duration-300"
          enterFrom="opacity-0"
          enterTo="opacity-100"
          leave="ease-in duration-200"
          leaveFrom="opacity-100"
          leaveTo="opacity-0"
        >
          <div className="fixed inset-0 bg-black/80 backdrop-blur-sm" />
        </Transition.Child>

        {/* Modal Container */}
        <div className="fixed inset-0 overflow-y-auto">
          <div className="flex min-h-full items-center justify-center p-4">
            <Transition.Child
              as={Fragment}
              enter="ease-out duration-300"
              enterFrom="opacity-0 scale-95"
              enterTo="opacity-100 scale-100"
              leave="ease-in duration-200"
              leaveFrom="opacity-100 scale-100"
              leaveTo="opacity-0 scale-95"
            >
              <Dialog.Panel
                className={`
                  w-full ${sizes[size]}
                  transform overflow-hidden
                  glass-card
                  transition-all
                `}
              >
                {/* Header */}
                {(title || closeButton) && (
                  <div className="flex items-start justify-between pb-4 border-b border-slate-700/50">
                    <div>
                      {title && (
                        <Dialog.Title className="text-xl font-bold text-slate-50">
                          {title}
                        </Dialog.Title>
                      )}
                      {description && (
                        <Dialog.Description className="mt-1 text-sm text-slate-400">
                          {description}
                        </Dialog.Description>
                      )}
                    </div>
                    {closeButton && (
                      <button
                        onClick={onClose}
                        className="p-2 hover:bg-slate-700/50 rounded-lg transition-colors"
                      >
                        <X className="w-5 h-5 text-slate-400" />
                      </button>
                    )}
                  </div>
                )}

                {/* Content */}
                <div className="py-4">
                  {children}
                </div>

                {/* Footer */}
                {footer && (
                  <div className="pt-4 border-t border-slate-700/50 flex justify-end gap-3">
                    {footer}
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

export default Modal
