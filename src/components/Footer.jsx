import React from 'react'
import VERSION, { BUILD_INFO } from '../config/version'
import { SHOW_SECURITY_NOTICE_EVENT } from './SecurityNotice'

/**
 * Footer Component
 * Displays branding, version info, and copyright notice
 */
function Footer() {
  const currentYear = new Date().getFullYear()

  return (
    <footer className="border-t border-[var(--stroke-dark)] bg-[var(--bg-1)]">
      <div className="px-6 py-4">
        <div className="flex flex-col md:flex-row items-center justify-between gap-4 text-sm">
          {/* Left: Branding */}
          <div className="flex items-center gap-2">
            <a
              href="https://authrecon.com"
              target="_blank"
              rel="noopener noreferrer"
              className="text-[var(--accent-blue)] hover:text-[var(--accent-blue-strong)] font-medium transition-colors flex items-center gap-1.5"
            >
              <span>AuthRecon.com</span>
              <span className="text-base">🍁</span>
            </a>
          </div>

          {/* Center: Copyright + security notice */}
          <div className="flex items-center gap-3 text-[var(--text-muted)] text-xs md:text-sm">
            <span>© {currentYear} AuthRecon. All rights reserved.</span>
            <button
              type="button"
              onClick={() => window.dispatchEvent(new Event(SHOW_SECURITY_NOTICE_EVENT))}
              className="underline hover:text-[var(--accent-blue)]"
            >
              Security notice
            </button>
          </div>

          {/* Right: Version */}
          <div className="flex items-center gap-2 text-xs">
            <span className="text-[var(--text-muted)]">v{VERSION.toString()}</span>
            <span className="px-2 py-1 rounded bg-[var(--sidebar-active-bg)] text-[var(--accent-blue)] font-medium">
              {BUILD_INFO.releaseStage}
            </span>
          </div>
        </div>
      </div>
    </footer>
  )
}

export default Footer
