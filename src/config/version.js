/**
 * App version. The number comes from the repo-root VERSION file, injected at
 * build time by vite.config.js (__APP_VERSION__). Bump VERSION, not this file;
 * backend/authrecon/backend/tests/test_version.py fails CI if any component drifts from it.
 */
/* global __APP_VERSION__ */
const raw = typeof __APP_VERSION__ === 'string' ? __APP_VERSION__ : '0.0.0'
const [major = 0, minor = 0, patch = 0] = raw.split('.').map(n => parseInt(n, 10) || 0)

export const VERSION = {
  major,
  minor,
  patch,
  toString() {
    return `${this.major}.${this.minor}.${this.patch}`
  }
}

export const BUILD_INFO = {
  releaseStage: major >= 1 ? 'Stable' : 'Beta',
}

export default VERSION
