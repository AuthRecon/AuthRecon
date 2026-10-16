import authreconApi from './authreconApi'

// Tenable WAS scan exports for the scan analyzer. The raw upload is never
// downloadable; only metadata and the analysis come back.
export const listScanExports = async () => (await authreconApi.get('scan-exports')).data

export const uploadScanExport = async (file) => {
  const form = new FormData()
  form.append('file', file)
  // Let the browser set multipart/form-data with its boundary.
  return (await authreconApi.post('scan-exports', form, { timeout: 120000 })).data
}

export const deleteScanExport = async (id) => authreconApi.delete(`scan-exports/${id}`)

// Re-run the analyzer on a stored export (after an analyzer update).
export const reanalyzeScanExport = async (id) => (await authreconApi.post(`scan-exports/${id}/reanalyze`, null, { timeout: 120000 })).data
