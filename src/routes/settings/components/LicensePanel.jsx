import React from 'react'
import Button from '../../../components/Button'
import Badge from '../../../components/Badge'
import PanelShell from './PanelShell'
import useLicenseStore from '../../../store/licenseStore'

function InfoRow({ label, value }) {
  return (
    <div>
      <p className="text-xs uppercase tracking-wider text-slate-500">{label}</p>
      <p className="text-base text-slate-200 break-all">{value ?? '—'}</p>
    </div>
  )
}

function FeatureTag({ label, enabled }) {
  return (
    <span
      className={`text-xs px-3 py-1 rounded-full border ${
        enabled ? 'border-emerald-500/50 text-emerald-300' : 'border-slate-700 text-slate-500'
      }`}
    >
      {label}
    </span>
  )
}

function LicensePanel() {
  const { status, loading, error, load } = useLicenseStore()
  const premiumFeatures = [
    { id: 'multi_role', label: 'Multi-role runs' },
    { id: 'screenshot_export', label: 'Screenshot export' },
    { id: 'har_export', label: 'HAR export' },
    { id: 'side_export', label: '.side generation' },
    { id: 'ai_analysis', label: 'AI-assisted analysis' },
  ]

  const handleRefresh = async () => {
    await load()
  }

  return (
    <PanelShell
      eyebrow="Licensing"
      title="AuthRecon License"
      description="AuthRecon is free and open source — all features are unlocked."
      actions={
        <Badge variant={status.valid ? 'success' : 'warning'}>
          {status.valid ? 'License valid' : 'License invalid'}
        </Badge>
      }
    >
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mb-6">
        <InfoRow label="Tier" value={status.tier} />
        <InfoRow label="Expires" value={status.expiration ? new Date(status.expiration).toLocaleString() : 'Perpetual'} />
        <InfoRow label="Installation ID" value={status.installation_id} />
        <InfoRow label="Last checked" value={status.last_checked ? new Date(status.last_checked).toLocaleString() : '—'} />
      </div>

      <div className="space-y-2">
        <p className="text-xs uppercase tracking-widest text-slate-500">Enabled features</p>
        <div className="flex flex-wrap gap-2">
          {premiumFeatures.map((feature) => (
            <FeatureTag key={feature.id} label={feature.label} enabled={status.features?.includes(feature.id)} />
          ))}
        </div>
      </div>

      <div className="flex flex-wrap gap-3 items-center">
        <Button variant="secondary" onClick={handleRefresh} disabled={loading}>
          {loading ? 'Refreshing…' : 'Refresh status'}
        </Button>
        {!status.valid && error && (
          <span className="text-xs text-rose-400">{error.message || 'License check failed'}</span>
        )}
      </div>

      <div className="text-xs text-slate-500 border-t border-slate-800/60 pt-3">
        AuthRecon is free and open source — all features are included.
      </div>
    </PanelShell>
  )
}

export default LicensePanel
