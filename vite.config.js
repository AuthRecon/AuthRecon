import { readFileSync } from 'node:fs'
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// Single source of truth for the app version (shown in the sidebar and footer).
const APP_VERSION = readFileSync(new URL('./VERSION', import.meta.url), 'utf8').trim()

// https://vite.dev/config/
// Production serves the static build (Dockerfile.frontend). These dev-server
// settings only apply to docker-compose.dev.yml / `npm run dev`.
export default defineConfig({
  plugins: [react()],
  define: {
    __APP_VERSION__: JSON.stringify(APP_VERSION),
  },
  server: {
    host: '0.0.0.0',
    port: 5173,
    // Only serve the app itself — never the repo root (.git, backend, .env).
    fs: {
      strict: true,
      allow: ['src', 'public', 'node_modules'],
    },
  },
})
