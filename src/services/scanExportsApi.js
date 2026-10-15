import authreconApi from './authreconApi'

// Tenable WAS scan exports for the (MCP-only) scan analyzer. The raw zip is
// never downloadable; only metadata and the parsed summary come back.
export const listScanExports = async () => (await authreconApi.get('scan-exports')).data

export const uploadScanExport = async (file) => {
  const form = new FormData()
  form.append('file', file)
  // Let the browser set multipart/form-data with its boundary.
  return (await authreconApi.post('scan-exports', form, { timeout: 120000 })).data
}

export const deleteScanExport = async (id) => authreconApi.delete(`scan-exports/${id}`)
