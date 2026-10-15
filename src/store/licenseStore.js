import { create } from 'zustand'
import licenseApi from '../services/licenseApi'

const DEFAULT_STATUS = {
  valid: true,
  tier: 'Open Source',
  expiration: null,
  installation_id: 'dev-local',
  features: ['multi_role', 'screenshot_export', 'har_export', 'side_export', 'ai_analysis'],
  last_checked: new Date().toISOString(),
  message: 'Free & open source — all features included.',
}

const useLicenseStore = create((set, get) => ({
  status: DEFAULT_STATUS,
  loading: false,
  error: null,
  load: async () => {
    set({ loading: true, error: null })
    try {
      const { data } = await licenseApi.getStatus()
      set({ status: { ...DEFAULT_STATUS, ...data }, loading: false })
    } catch (error) {
      console.warn('License status unavailable, continuing in dev mode.', error?.message)
      set({ loading: false, error })
    }
  },
  hasFeature: (feature) => {
    const { status } = get()
    if (!status?.valid) return false
    if (!status?.features || status.features.length === 0) return true
    return status.features.includes(feature)
  },
}))

export default useLicenseStore
