import React, { useMemo, useState } from 'react'
import { AlertTriangle, CheckCircle2, CircleSlash, Copy, KeyRound, PlugZap, Trash2 } from 'lucide-react'
import PanelShell from './PanelShell'
import Button from '../../../components/Button'
import config from '../../../config'
import {
  useAiStatus,
  useApiAccess,
  useSetApiAccess,
  useSetMcpEnabled,
  useUpdateAiPreferences,
} from '../../../services/useAiStatus'
import { useCreateApiKey, useRevokeApiKey } from '../../../services/useApiKeys'
import { usePortalUsers } from '../../../services/usePortalUsers'

function formatWhen(value) {
  if (!value) return 'never'
  try {
    return new Date(value).toLocaleString()
  } catch {
    return value
  }
}

function CopyBlock({ text }) {
  const [copied, setCopied] = useState(false)
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(text)
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    } catch {
      /* clipboard unavailable: user can select manually */
    }
  }
  return (
    <div className="relative">
      <pre className="text-xs bg-slate-950/70 border border-slate-800 rounded-lg p-3 pr-10 overflow-x-auto text-slate-200 whitespace-pre">{text}</pre>
      <button type="button" onClick={copy} className="absolute top-2 right-2 p-1 text-slate-400 hover:text-slate-100" title="Copy">
        {copied ? <CheckCircle2 className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
      </button>
    </div>
  )
}

function Toggle({ checked, disabled, onChange, label, hint }) {
  return (
    <label className={`flex items-start gap-3 p-4 rounded-lg border border-slate-800 bg-slate-900/40 ${disabled ? 'opacity-60' : 'cursor-pointer'}`}>
      <input
        type="checkbox"
        className="mt-1 w-4 h-4"
        style={{ accentColor: 'var(--accent-blue)' }}
        checked={checked}
        disabled={disabled}
        onChange={(e) => onChange(e.target.checked)}
      />
      <span>
        <span className="block text-sm font-medium text-slate-200">{label}</span>
        {hint && <span className="block text-xs text-slate-500 mt-1">{hint}</span>}
      </span>
    </label>
  )
}

function mcpUrl(path) {
  const base = (config.api.portal || window.location.origin).replace(/\/+$/, '')
  return `${base}${path}`
}

function isInsecureRemote(url) {
  try {
    const u = new URL(url)
    return u.protocol === 'http:' && !['localhost', '127.0.0.1', '::1'].includes(u.hostname)
  } catch {
    return false
  }
}

function ConnectInstructions({ url, apiKey }) {
  const desktopArgs = ['-y', 'mcp-remote', url, '--header', 'Authorization:${AUTHRECON_AUTH}']
  if (url.startsWith('http:')) desktopArgs.push('--allow-http')
  return (
    <div className="space-y-3">
      <p className="text-xs text-slate-400">Claude Code (run in a terminal):</p>
      <CopyBlock text={`claude mcp add --transport http authrecon ${url} \\\n  --header "Authorization: Bearer ${apiKey}"`} />
      <p className="text-xs text-slate-500">
        This puts the key in your shell history: run it in a terminal you trust, or clear the history entry afterwards.
      </p>
      <p className="text-xs text-slate-400">Claude Desktop (add to claude_desktop_config.json, then restart Claude Desktop):</p>
      <CopyBlock
        text={JSON.stringify(
          { mcpServers: { authrecon: { command: 'npx', args: desktopArgs, env: { AUTHRECON_AUTH: `Bearer ${apiKey}` } } } },
          null,
          2,
        )}
      />
    </div>
  )
}

function CreateKey({ url }) {
  const create = useCreateApiKey()
  const [name, setName] = useState('Claude Code')
  const [created, setCreated] = useState(null)

  const submit = async (e) => {
    e.preventDefault()
    try {
      setCreated(await create.mutateAsync({ name: name.trim() || 'MCP client' }))
    } catch {
      /* error shown below */
    }
  }

  if (created) {
    return (
      <div className="space-y-4">
        <div className="flex items-start gap-2 p-3 rounded-lg border border-amber-500/40 bg-amber-500/10 text-amber-100 text-xs">
          <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
          <span>
            This is the only time the key <span className="font-semibold">{created.name}</span> is shown. It's already
            filled into the commands below — copy what you need now. Anyone with it can act as you in AuthRecon.
          </span>
        </div>
        <CopyBlock text={created.key} />
        <ConnectInstructions url={url} apiKey={created.key} />
        <div className="flex justify-end">
          <Button variant="secondary" onClick={() => setCreated(null)}>Done</Button>
        </div>
      </div>
    )
  }

  return (
    <form onSubmit={submit} className="flex flex-col sm:flex-row gap-3 sm:items-end">
      <label className="flex-1">
        <span className="block text-xs text-slate-400 mb-1">Key name (which AI client is this for?)</span>
        <input
          value={name}
          onChange={(e) => setName(e.target.value)}
          maxLength={150}
          className="w-full px-3 py-2 rounded-lg bg-slate-950/70 border border-slate-800 text-sm text-slate-100"
        />
      </label>
      <Button type="submit" disabled={create.isPending}>
        <KeyRound className="w-4 h-4 mr-2 inline" />
        {create.isPending ? 'Creating…' : 'Create MCP key'}
      </Button>
      {create.isError && (
        <p className="text-sm text-rose-300 sm:self-center">
          {create.error?.response?.data?.detail || 'Could not create the key.'}
        </p>
      )}
    </form>
  )
}

function YourKeys({ keys }) {
  const revoke = useRevokeApiKey()
  if (!keys?.length) return <p className="text-sm text-slate-500">No keys yet.</p>
  return (
    <ul className="divide-y divide-slate-800 border border-slate-800 rounded-lg">
      {keys.map((k) => (
        <li key={k.id} className="flex items-center justify-between gap-3 p-3">
          <div className="min-w-0">
            <p className="text-sm text-slate-200 truncate">{k.name} <span className="text-xs text-slate-500 font-mono">{k.prefix}</span></p>
            <p className="text-xs text-slate-500">
              Created {formatWhen(k.created_at)} · last AI connection {formatWhen(k.last_mcp_used_at)}
            </p>
          </div>
          <button
            type="button"
            className="p-2 text-slate-400 hover:text-rose-300"
            title="Revoke"
            disabled={revoke.isPending}
            onClick={() => {
              if (confirm(`Revoke "${k.name}"? Any AI client using it stops working immediately.`)) revoke.mutate(k.id)
            }}
          >
            <Trash2 className="w-4 h-4" />
          </button>
        </li>
      ))}
    </ul>
  )
}

function UserAccess() {
  const { data: users, isLoading } = usePortalUsers()
  const { data: access } = useApiAccess(true)
  const setAccess = useSetApiAccess()
  const allowed = useMemo(
    () => Object.fromEntries((access || []).map((a) => [a.portal_user_id, a.api_access_enabled])),
    [access],
  )
  if (isLoading) return <p className="text-sm text-slate-400">Loading users…</p>
  return (
    <ul className="divide-y divide-slate-800 border border-slate-800 rounded-lg">
      {(users || []).map((u) => (
        <li key={u.id} className="flex items-center justify-between gap-3 p-3">
          <span className="text-sm text-slate-200">
            {u.username}
            {u.is_admin && <span className="ml-2 text-xs text-slate-500">admin · always allowed</span>}
          </span>
          {!u.is_admin && (
            <input
              type="checkbox"
              className="w-4 h-4"
              style={{ accentColor: 'var(--accent-blue)' }}
              checked={Boolean(allowed[String(u.id)])}
              disabled={setAccess.isPending}
              onChange={(e) => setAccess.mutate({ portalUserId: String(u.id), enabled: e.target.checked })}
              aria-label={`Allow ${u.username} to create API and MCP keys`}
            />
          )}
        </li>
      ))}
    </ul>
  )
}

/**
 * AI & MCP: the one place AI is configured.
 *
 * AuthRecon has no built-in LLM. AI features (login-flow help, the scan
 * analyzer) work by connecting YOUR AI client to AuthRecon's MCP endpoint,
 * authenticated with your own API key so it only ever sees your data.
 */
const TOOL_GROUPS = [
  ['Plan', 'detect_auth: what kind of login a site uses, without logging in · list_credentials: your saved credentials by name'],
  ['Run', 'submit_run · wait_for_run · rerun · cancel_run'],
  ['Scan setup', 'get_was_setup: page to verify, success pattern, script status · verify_script: replay a script in a clean browser'],
  ['Investigate', 'get_run_timeline · list_artifacts · list_runs · get_run_details'],
  ['Fix stuck logins', 'get_stuck_run_context · submit_login_suggestion (used when "AI login suggestions" is on)'],
  ['Learned patterns', 'list_playbooks · clear_playbook · clear_playbooks_for_domain'],
  ['Scan exports', 'list_scan_exports · get_scan_export_summary'],
]

const EXAMPLE_PROMPTS = [
  'What kind of login does https://staging.example.com/login use?',
  'Run AuthRecon against https://staging.example.com/login with my "Staging admin" credential and give me the WAS settings.',
  'Why did my last AuthRecon run fail, and what should I try next?',
]

function WhatAiCanDo() {
  return (
    <PanelShell
      eyebrow="Capabilities"
      title="What your AI client can do"
      description="Your AI client works through these tools, as you, on your own runs only."
    >
      <ul className="divide-y divide-slate-800 border border-slate-800 rounded-lg">
        {TOOL_GROUPS.map(([group, tools]) => (
          <li key={group} className="p-3 grid grid-cols-1 sm:grid-cols-[10rem_1fr] gap-1">
            <span className="text-sm font-medium text-slate-200">{group}</span>
            <span className="text-xs text-slate-400 font-mono">{tools}</span>
          </li>
        ))}
      </ul>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="p-4 rounded-lg border border-emerald-900/50 bg-emerald-950/10">
          <p className="text-xs uppercase text-emerald-400 mb-2">It can see</p>
          <ul className="space-y-1 text-sm text-slate-300 list-disc pl-5">
            <li>Your runs: targets, status, timeline, detected login type</li>
            <li>Scan settings: pages to verify, success patterns, file names</li>
            <li>Credential names you saved (not their contents)</li>
            <li>Login-page HTML from stuck runs, sanitized first</li>
          </ul>
        </div>
        <div className="p-4 rounded-lg border border-rose-900/50 bg-rose-950/10">
          <p className="text-xs uppercase text-rose-400 mb-2">It never sees</p>
          <ul className="space-y-1 text-sm text-slate-300 list-disc pl-5">
            <li>Usernames, passwords or other secrets</li>
            <li>Session cookies or tokens</li>
            <li>The .side, HAR or export files themselves</li>
            <li>Other users&apos; runs</li>
          </ul>
        </div>
      </div>
      <div>
        <p className="text-xs uppercase text-slate-500 mb-2">Try asking</p>
        <ul className="space-y-2">
          {EXAMPLE_PROMPTS.map(prompt => (
            <li key={prompt} className="text-sm text-slate-300 px-3 py-2 rounded-lg border border-slate-800 bg-slate-900/40">&ldquo;{prompt}&rdquo;</li>
          ))}
        </ul>
      </div>
    </PanelShell>
  )
}

function AiMcpPanel() {
  const { data, isLoading, error } = useAiStatus()
  const updatePrefs = useUpdateAiPreferences()
  const setMcp = useSetMcpEnabled()
  const enabled = Boolean(data?.mcp_enabled)
  const isAdmin = Boolean(data?.is_admin)
  const url = mcpUrl(data?.mcp_path || '/apps/authrecon/mcp')

  return (
    <div className="space-y-6">
      <PanelShell
        eyebrow="AI"
        title="AI & MCP"
        description="AuthRecon doesn't run an AI model itself. You connect your own AI client (Claude Code, Claude Desktop or another MCP client) and it uses AuthRecon's tools as you, seeing only your runs and exports. Nothing here sends data to an AI provider on its own."
      >
        {error && <p className="text-sm text-rose-300">Could not load AI status.</p>}
        <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
          <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/40">
            <p className="text-xs uppercase text-slate-500 mb-1">MCP</p>
            {isLoading ? (
              <p className="text-sm text-slate-400">Checking…</p>
            ) : enabled ? (
              <p className="flex items-center gap-2 text-sm text-emerald-300"><PlugZap className="w-4 h-4" /> Enabled</p>
            ) : (
              <p className="flex items-center gap-2 text-sm text-slate-300"><CircleSlash className="w-4 h-4" /> Disabled</p>
            )}
            <p className="text-xs text-slate-500 mt-1 break-all">{url}</p>
          </div>
          <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/40">
            <p className="text-xs uppercase text-slate-500 mb-1">Last AI connection</p>
            <p className="text-sm text-slate-200">{formatWhen(data?.last_client_activity)}</p>
            <p className="text-xs text-slate-500 mt-1">Most recent MCP connection with one of your keys</p>
          </div>
          <div className="p-4 rounded-lg border border-slate-800 bg-slate-900/40">
            <p className="text-xs uppercase text-slate-500 mb-1">Your keys</p>
            <p className="text-sm text-slate-200">{data?.api_keys?.length ?? '—'} active</p>
          </div>
        </div>

        {isAdmin && (
          <Toggle
            checked={enabled}
            disabled={isLoading || setMcp.isPending}
            onChange={(v) => setMcp.mutate(v)}
            label="Enable MCP for this AuthRecon (admin)"
            hint="When off, every AI client is refused, whatever key it has. Takes effect within seconds."
          />
        )}
        {setMcp.isError && <p className="text-sm text-rose-300">Could not change the MCP setting.</p>}

        <Toggle
          checked={Boolean(data?.use_ai_suggestions)}
          disabled={isLoading || updatePrefs.isPending}
          onChange={(v) => updatePrefs.mutate({ use_ai_suggestions: v })}
          label="Use AI login suggestions in my runs"
          hint="When a run gets stuck, a connected AI client can suggest login-form selectors. With this on, your re-runs try those selectors. The AI only suggests selectors: it never sees or types your credentials."
        />
        {updatePrefs.isError && <p className="text-sm text-rose-300">Could not save the preference.</p>}
      </PanelShell>

      <PanelShell
        eyebrow="Connect"
        title="Connect an AI client"
        description="Create a key for each AI client. The key is your client's login: the AI acts as you, and revoking the key cuts it off."
      >
        {!isLoading && !enabled && (
          <p className="text-sm text-amber-200">
            MCP is disabled. {isAdmin ? 'Turn it on above first.' : 'Ask an admin to enable it.'}
          </p>
        )}
        {isInsecureRemote(url) && (
          <p className="flex items-start gap-2 text-xs text-amber-200">
            <AlertTriangle className="w-4 h-4 shrink-0" />
            This address is plain HTTP. Your key would cross the network unencrypted: put AuthRecon behind HTTPS before
            connecting from another machine.
          </p>
        )}
        {!isLoading && data?.api_access ? (
          <CreateKey url={url} />
        ) : (
          !isLoading && <p className="text-sm text-slate-400">Your account can't create keys yet. Ask an admin to allow it below.</p>
        )}
        <div>
          <p className="text-xs uppercase text-slate-500 mb-2">Your keys</p>
          <YourKeys keys={data?.api_keys} />
        </div>
      </PanelShell>

      <WhatAiCanDo />

      {isAdmin && (
        <PanelShell
          eyebrow="Admin"
          title="Who can create keys"
          description="Users allowed here can create API and MCP keys for their own account. Turning someone off stops their existing keys immediately."
        >
          <UserAccess />
        </PanelShell>
      )}
    </div>
  )
}

export default AiMcpPanel
