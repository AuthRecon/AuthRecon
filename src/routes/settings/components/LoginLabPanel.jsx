import React, { useState } from 'react'
import { FlaskConical, AlertTriangle, Clock, Power, PowerOff, Shield, Copy, Check } from 'lucide-react'
import PanelShell from './PanelShell'
import Button from '../../../components/Button'
import { useLoginLabStatus, useEnableLoginLab, useDisableLoginLab } from '../../../hooks/useLoginLabStatus'

const DURATION_OPTIONS = [
  { value: 15, label: '15 minutes' },
  { value: 30, label: '30 minutes (default)' },
  { value: 60, label: '1 hour' },
  { value: 120, label: '2 hours' },
]

const LOGINLAB_SCENARIOS = [
  {
    name: 'Microsoft / Azure AD',
    path: '/demo/microsoft',
    username: 'user@contoso.com',
    password: 'AzureDemo123!',
    authType: 'OAuth/SAML',
    color: 'from-blue-600 to-blue-700',
    borderColor: 'border-l-blue-500',
  },
  {
    name: 'Okta SSO',
    path: '/demo/okta',
    username: 'demo.user',
    password: 'OktaDemo123!',
    authType: 'SAML/OAuth',
    color: 'from-indigo-600 to-indigo-700',
    borderColor: 'border-l-indigo-500',
  },
  {
    name: 'Google OAuth',
    path: '/demo/google',
    username: 'demo@example.com',
    password: 'GoogleDemo123!',
    authType: 'OAuth',
    color: 'from-red-500 to-yellow-500',
    borderColor: 'border-l-red-500',
  },
  {
    name: 'Corporate SSO Portal',
    path: '/demo/corporate-sso',
    username: 'enterprise.user',
    password: 'SecureDemo123!',
    authType: 'Multi-provider',
    color: 'from-slate-500 to-slate-600',
    borderColor: 'border-l-slate-400',
  },
  {
    name: 'Basic Form Login',
    path: '/form-login',
    username: 'testuser@loginlab.local',
    password: 'TestPass123!',
    authType: 'Form',
    color: 'from-sky-600 to-sky-700',
    borderColor: 'border-l-sky-500',
  },
  {
    name: 'Multi-Step Login',
    path: '/multi-step',
    username: 'testuser@loginlab.local',
    password: 'TestPass123!',
    authType: 'Multi-step Form',
    color: 'from-teal-600 to-teal-700',
    borderColor: 'border-l-teal-500',
  },
  {
    name: 'Multi-Role Portal',
    path: '/lab/multirole',
    username: 'admin@lab.local',
    password: 'Beacon!2024',
    authType: 'Form + Roles',
    color: 'from-amber-500 to-orange-600',
    borderColor: 'border-l-amber-500',
  },
]

function CopyButton({ text }) {
  const [copied, setCopied] = useState(false)

  const handleCopy = async () => {
    await navigator.clipboard.writeText(text)
    setCopied(true)
    setTimeout(() => setCopied(false), 1500)
  }

  return (
    <button
      onClick={handleCopy}
      className="ml-2 p-1 hover:bg-slate-600/50 rounded-sm transition-colors"
      title="Copy to clipboard"
    >
      {copied ? (
        <Check className="w-3.5 h-3.5 text-emerald-400" />
      ) : (
        <Copy className="w-3.5 h-3.5 text-slate-400 hover:text-slate-200" />
      )}
    </button>
  )
}

function CopyableField({ value, className = '' }) {
  return (
    <div className={`flex items-center ${className}`}>
      <code className="bg-slate-700/50 px-2 py-1 rounded-sm text-sm font-mono truncate">{value}</code>
      <CopyButton text={value} />
    </div>
  )
}

function LoginLabPanel() {
  const { data: status, isLoading, error } = useLoginLabStatus()
  const enableMutation = useEnableLoginLab()
  const disableMutation = useDisableLoginLab()
  const [duration, setDuration] = useState(30)

  // Failures are shown below from the mutation's error state.
  const handleEnable = async () => {
    try {
      await enableMutation.mutateAsync(duration)
    } catch {
      /* shown below */
    }
  }

  const handleDisable = async () => {
    if (window.confirm('Are you sure you want to disable LoginLab? Any active training sessions will be interrupted.')) {
      try {
        await disableMutation.mutateAsync()
      } catch {
        /* shown below */
      }
    }
  }

  const mutationError = enableMutation.error || disableMutation.error

  const isActive = status?.active
  const remainingMinutes = Math.ceil((status?.remaining_seconds || 0) / 60)
  const serviceAvailable = status?.available !== false && !error

  return (
    <PanelShell
      eyebrow="Training Environment"
      title="LoginLab"
      description="Controlled training environment with simulated authentication pages for AuthRecon testing."
    >
      {/* Warning Banner */}
      <div className="flex items-start gap-4 p-4 bg-amber-500/10 border border-amber-500/30 rounded-xl">
        <AlertTriangle className="w-6 h-6 text-amber-400 shrink-0 mt-0.5" />
        <div>
          <p className="text-sm font-medium text-amber-300">Security Notice</p>
          <p className="text-sm text-amber-200/70 mt-1">
            LoginLab contains <strong>intentional vulnerabilities</strong> for testing purposes.
            It runs on an internal Docker network only and auto-disables after the configured timeout.
            Never expose LoginLab to external networks.
          </p>
        </div>
      </div>

      {/* Status Section */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div>
          <p className="text-xs uppercase text-slate-500">Status</p>
          <div className="flex items-center gap-2 mt-1">
            {isLoading ? (
              <span className="text-slate-400">Checking...</span>
            ) : !serviceAvailable ? (
              <span className="text-rose-400">Service Unavailable</span>
            ) : isActive ? (
              <>
                <span className="w-2 h-2 bg-emerald-400 rounded-full animate-pulse" />
                <span className="text-emerald-400 font-medium">Active</span>
              </>
            ) : (
              <>
                <span className="w-2 h-2 bg-slate-500 rounded-full" />
                <span className="text-slate-400">Disabled</span>
              </>
            )}
          </div>
        </div>

        <div>
          <p className="text-xs uppercase text-slate-500">Time Remaining</p>
          <p className="text-base text-slate-200 mt-1">
            {isActive ? `${remainingMinutes} minutes` : '—'}
          </p>
        </div>

        <div>
          <p className="text-xs uppercase text-slate-500">Enabled By</p>
          <p className="text-base text-slate-200 mt-1">
            {status?.enabled_by || '—'}
          </p>
        </div>

        <div>
          <p className="text-xs uppercase text-slate-500">Auto-Disable</p>
          <p className="text-base text-slate-200 mt-1">
            {status?.auto_disable_minutes || 30} min default
          </p>
        </div>
      </div>

      {/* Controls */}
      <div className="flex flex-col sm:flex-row items-start sm:items-end gap-4 pt-4 border-t border-slate-800/50">
        {!isActive ? (
          <>
            <label className="space-y-2 flex-1 max-w-xs">
              <span className="text-sm text-slate-300">Session Duration</span>
              <select
                className="w-full px-4 py-3 bg-slate-800/60 border border-slate-700/60 rounded-xl text-slate-100"
                value={duration}
                onChange={(e) => setDuration(Number(e.target.value))}
                disabled={!serviceAvailable}
              >
                {DURATION_OPTIONS.map((opt) => (
                  <option key={opt.value} value={opt.value}>
                    {opt.label}
                  </option>
                ))}
              </select>
            </label>

            <Button
              onClick={handleEnable}
              variant="primary"
              loading={enableMutation.isPending}
              disabled={!serviceAvailable}
              className="flex items-center gap-2"
            >
              <Power className="w-4 h-4" />
              {enableMutation.isPending ? 'Enabling...' : 'Enable LoginLab'}
            </Button>
          </>
        ) : (
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-2 px-4 py-2 bg-emerald-500/10 border border-emerald-500/30 rounded-lg">
              <Clock className="w-4 h-4 text-emerald-400" />
              <span className="text-sm text-emerald-300">
                Auto-disables in {remainingMinutes} min
              </span>
            </div>

            <Button
              onClick={handleDisable}
              variant="danger"
              loading={disableMutation.isPending}
              className="flex items-center gap-2"
            >
              <PowerOff className="w-4 h-4" />
              {disableMutation.isPending ? 'Disabling...' : 'Disable Now'}
            </Button>
          </div>
        )}
      </div>

      {/* Error Display */}
      {mutationError && (
        <p className="text-sm text-rose-400">
          {mutationError.response?.data?.detail || mutationError.message || 'An error occurred'}
        </p>
      )}

      {/* AuthRecon Scan Targets Section */}
      {isActive && (
        <div className="pt-4 border-t border-slate-800/50">
          <h3 className="text-lg font-medium text-slate-200 mb-3 flex items-center gap-2">
            <FlaskConical className="w-5 h-5 text-blue-400" />
            AuthRecon Scan Targets
          </h3>
          <p className="text-sm text-slate-400 mb-4">
            Copy these URLs and credentials for AuthRecon scans. Use the <code className="bg-slate-700/50 px-1.5 py-0.5 rounded-sm text-xs">loginlab:5500</code> hostname (Docker internal network).
          </p>

          <div className="space-y-3">
            {LOGINLAB_SCENARIOS.map((scenario) => (
              <div
                key={scenario.path}
                className={`overflow-hidden rounded-xl border border-slate-700/50 ${scenario.borderColor} border-l-4`}
              >
                {/* Colored Header */}
                <div className={`px-4 py-3 bg-linear-to-r ${scenario.color}`}>
                  <div className="flex items-center justify-between">
                    <h4 className="font-medium text-white">{scenario.name}</h4>
                    <span className="text-xs px-2 py-1 bg-white/20 rounded-sm text-white/90">
                      {scenario.authType}
                    </span>
                  </div>
                </div>

                {/* Credentials Section */}
                <div className="p-4 bg-slate-800/40">
                  <div className="grid grid-cols-1 lg:grid-cols-3 gap-3">
                    <div>
                      <p className="text-xs uppercase text-slate-500 mb-1">Target URL</p>
                      <CopyableField value={`http://loginlab:5500${scenario.path}`} />
                    </div>
                    <div>
                      <p className="text-xs uppercase text-slate-500 mb-1">Username</p>
                      <CopyableField value={scenario.username} />
                    </div>
                    <div>
                      <p className="text-xs uppercase text-slate-500 mb-1">Password</p>
                      <CopyableField value={scenario.password} />
                    </div>
                  </div>
                </div>
              </div>
            ))}
          </div>

          <div className="mt-4 p-3 bg-blue-500/10 border border-blue-500/30 rounded-lg">
            <p className="text-xs text-blue-300">
              <strong>Note:</strong> Use <code className="bg-blue-500/20 px-1.5 py-0.5 rounded-sm">http://loginlab:5500</code> for AuthRecon scans (Docker internal).
              Use <code className="bg-blue-500/20 px-1.5 py-0.5 rounded-sm">http://localhost:5500</code> only for browser preview (if port is exposed).
            </p>
          </div>
        </div>
      )}

      {/* Features List */}
      <div className="pt-4 border-t border-slate-800/50">
        <h3 className="text-sm font-medium text-slate-300 mb-3">Security Features</h3>
        <ul className="grid grid-cols-1 md:grid-cols-2 gap-2 text-sm text-slate-400">
          <li className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-emerald-400" />
            Internal Docker network only
          </li>
          <li className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-emerald-400" />
            Service token authentication
          </li>
          <li className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-emerald-400" />
            Auto-disable timeout
          </li>
          <li className="flex items-center gap-2">
            <Shield className="w-4 h-4 text-emerald-400" />
            Admin-only access
          </li>
        </ul>
      </div>
    </PanelShell>
  )
}

export default LoginLabPanel
