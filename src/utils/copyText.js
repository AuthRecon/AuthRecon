// Copy to the clipboard, with a fallback for non-secure (plain-HTTP) origins.
export async function copyText(text) {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    // Non-secure origins (plain-HTTP hostnames) have no clipboard API.
    const area = document.createElement('textarea')
    area.value = text
    document.body.appendChild(area)
    area.select()
    const ok = document.execCommand('copy')
    document.body.removeChild(area)
    return ok
  }
}
