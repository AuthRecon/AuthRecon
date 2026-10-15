"""
AuthRecon MCP server.

Exposes a deliberately narrow, explicit allow-list of AuthRecon
capabilities to MCP-compatible clients (Claude Desktop, Claude Code, and
similar). See SECURITY.md at the repo root for the rules this must
follow — the short version: tools here either return non-credential data,
or take a reference (credential_id, run_id) and let AuthRecon's own
backend handle anything sensitive server-side. No tool here ever accepts
or returns a raw username, password, or session cookie.

This is intentionally a thin translation layer, not a generic API proxy —
it only implements the tools defined below. Adding a new tool means
writing a new function here, not exposing another backend route wholesale.

Auth: each client sends its user's own AuthRecon API key
(``Authorization: Bearer ak_live_...``). This server holds no credentials.
Every request is checked against authrecon-api's ``/ai/mcp-gate`` (valid
key, user still has API access, MCP enabled by an admin), and every tool
call is made to authrecon-api with the caller's key — so the AI acts as
that user and sees only that user's runs (API keys are never admin-scoped;
see backend/authrecon/backend/app/api/deps.py). Clients reach this server
only through the portal at /apps/authrecon/mcp; it publishes no port.
"""
from __future__ import annotations

import asyncio
import hashlib
import os
import time
from collections import deque
from typing import Any, Callable

import httpx
from mcp.server.mcpserver import Context, MCPServer
from mcp.server.transport_security import TransportSecuritySettings

AUTHRECON_API_URL = os.getenv("AUTHRECON_API_URL", "http://authrecon-api:8000/api/v1").rstrip("/")
MCP_HOST = os.getenv("MCP_HOST", "0.0.0.0")
MCP_PORT = int(os.getenv("MCP_PORT", "8765"))
# Per-key request budget; a runaway client can't hammer the API.
RATE_LIMIT_PER_MINUTE = int(os.getenv("MCP_RATE_LIMIT_PER_MINUTE", "120"))
# How long a successful gate check is reused for the same key. Short, so an
# admin turning MCP off or revoking a key takes effect within seconds.
GATE_CACHE_SECONDS = float(os.getenv("MCP_GATE_CACHE_SECONDS", "10"))

# Swappable in tests (httpx.MockTransport).
_transport: httpx.AsyncBaseTransport | None = None

mcp = MCPServer(
    "authrecon",
    instructions=(
        "AuthRecon figures out how a web application logs in, performs the login, and "
        "produces what a credentialed DAST scan (Tenable WAS) needs: a Selenium .side "
        "script, the page to verify and the success pattern.\n"
        "Typical workflow:\n"
        "1. detect_auth(url) to see what kind of login a target uses (no login is attempted).\n"
        "2. list_credentials() to find a saved credential_id. Credentials are saved by "
        "the user in the AuthRecon app (Launch page); never ask the user to paste a password.\n"
        "3. submit_run(url, credential_id), then wait_for_run(run_id).\n"
        "4. get_was_setup(run_id) for the scan settings. verify_script() replays the .side "
        "in a clean browser to confirm it logs in (one more login on the account: only on request).\n"
        "5. If a run failed: get_run_timeline() and the 'failure' guidance explain why. If the "
        "login fields weren't found, get_stuck_run_context() + submit_login_suggestion() let you "
        "propose selectors (the user must enable AI login suggestions), then rerun().\n"
        "No tool returns passwords, session cookies or .side contents; page content is sanitized "
        "server-side. list_scan_exports()/get_scan_export_summary() cover WAS scan exports users uploaded."
    ),
)


def _api(api_key: str) -> httpx.AsyncClient:
    return httpx.AsyncClient(
        base_url=AUTHRECON_API_URL,
        # The client header only labels runs "via MCP"; identity is the key.
        headers={"X-API-Key": api_key, "X-AuthRecon-Client": "mcp"},
        timeout=30.0,
        transport=_transport,
    )


def _bearer(headers: Any) -> str:
    """The caller's API key from an Authorization header mapping, or ''."""
    if not headers:
        return ""
    value = ""
    for name, val in headers.items():
        if str(name).lower() == "authorization":
            value = str(val)
            break
    scheme, _, token = value.partition(" ")
    return token.strip() if scheme.lower() == "bearer" else ""


def _client(ctx: Context) -> httpx.AsyncClient:
    # The gate middleware already rejected requests without a valid key; the
    # API re-validates it on every call below anyway.
    key = _bearer(ctx.headers)
    if not key:
        raise RuntimeError("No API key on this request")
    return _api(key)


# Keys whose values are secrets wherever they appear in an API response
# (matched case-insensitively, at any depth). The API returns some of these to
# the owner on purpose — e.g. decrypted cookie values for the UI's cookie
# export — but they must never reach a model. Names, flags and analysis stay.
_SECRET_KEYS = frozenset({
    "value", "value_encrypted", "raw_token", "raw_token_encrypted",
    "set-cookie", "cookie", "cookies_raw", "session_cookies",
    "authorization", "proxy-authorization", "x-api-key", "x-auth-token", "x-csrf-token", "x-xsrf-token",
    "token", "access_token", "refresh_token", "id_token", "password", "secret", "client_secret",
})
REDACTED = "[REDACTED]"


def _redact_secrets(data: Any) -> Any:
    if isinstance(data, dict):
        return {
            k: (REDACTED if isinstance(k, str) and k.lower() in _SECRET_KEYS and v not in (None, "", [], {})
                else _redact_secrets(v))
            for k, v in data.items()
        }
    if isinstance(data, list):
        return [_redact_secrets(v) for v in data]
    return data


def _raise_for_status(resp: httpx.Response) -> None:
    if resp.status_code >= 400:
        detail = resp.text
        try:
            detail = resp.json().get("detail", detail)
        except Exception:
            pass
        raise RuntimeError(f"AuthRecon API error ({resp.status_code}): {detail}")


# --- Review job history -----------------------------------------------------


@mcp.tool()
async def list_runs(ctx: Context, status: str | None = None, limit: int = 20) -> list[dict[str, Any]]:
    """
    List your recent AuthRecon runs.

    Returns status, target URL, detected auth type, and timestamps only.
    Never includes credentials, usernames, or session cookies.

    Args:
        status: optional filter — one of queued, running, manual_recording,
            succeeded, failed.
        limit: max number of runs to return (most recent first).
    """
    async with _client(ctx) as client:
        resp = await client.get("/runs")
        _raise_for_status(resp)
        runs = _redact_secrets(resp.json())

    if status:
        runs = [r for r in runs if r.get("status") == status]
    return runs[:limit]


# Fields intentionally exposed from RunDetail. This is an allow-list, not a
# filter of a blacklist — a new field added to the backend schema later is
# excluded by default until someone deliberately adds it here.
_RUN_DETAIL_ALLOWED_FIELDS = {
    "id",
    "status",
    "target_url",
    "submitted_at",
    "started_at",
    "finished_at",
    "duration_seconds",
    "auth_type",
    "final_url",
    "pattern",
    "llm_pattern",
    "tech_fingerprint",
    "security_context",
    "timeline",
    "detected_auth",
    "warnings",
    "was_setup",
    "failure",
    "error_message",
}


@mcp.tool()
async def get_run_details(ctx: Context, run_id: str) -> dict[str, Any]:
    """
    Get details for one run: status, detected auth type, the session
    verification pattern, and the final authenticated URL — the inputs
    you'd need to configure a Tenable WAS scan (or similar) by hand.

    Never includes credentials, usernames, or session cookies.
    """
    async with _client(ctx) as client:
        resp = await client.get(f"/runs/{run_id}")
        _raise_for_status(resp)
        detail = resp.json()

    return _redact_secrets({k: v for k, v in detail.items() if k in _RUN_DETAIL_ALLOWED_FIELDS})


_TERMINAL = {"succeeded", "failed", "cancelled"}
_WAS_FIELDS = ("id", "status", "target_url", "auth_type", "warnings", "was_setup", "failure")


@mcp.tool()
async def detect_auth(ctx: Context, target_url: str, login_hint: str | None = None) -> dict[str, Any]:
    """
    Find out what kind of login a target uses, without logging in.

    Loads the page the way a run does first (no credentials are sent) and
    returns the detected auth type, confidence, the evidence, and whether
    the scanner should use a Selenium script or HTTP authentication settings.
    """
    payload: dict[str, Any] = {"target_url": target_url}
    if login_hint:
        payload["login_hint"] = login_hint
    async with _client(ctx) as client:
        resp = await client.post("/runs/detect", json=payload, timeout=120)
        _raise_for_status(resp)
        return _redact_secrets(resp.json())


@mcp.tool()
async def list_credentials(ctx: Context) -> list[dict[str, Any]]:
    """
    List the credentials you have saved in AuthRecon, to pass to submit_run().

    Returns the id, name, description, auth type and last-used time only:
    never the username or the secret.
    """
    async with _client(ctx) as client:
        resp = await client.get("/credentials")
        _raise_for_status(resp)
        rows = resp.json()
    keep = ("id", "name", "description", "auth_type", "last_used_at", "is_archived")
    return [{k: row.get(k) for k in keep} for row in rows if not row.get("is_archived")]


@mcp.tool()
async def wait_for_run(ctx: Context, run_id: str, timeout_seconds: int = 300) -> dict[str, Any]:
    """
    Wait until a run finishes (or the timeout passes), then return its outcome:
    status, warnings, the WAS setup (if it succeeded) or the failure guidance.

    Args:
        run_id: the run to wait for.
        timeout_seconds: how long to wait, 10-600 (default 300).
    """
    deadline = time.monotonic() + max(10, min(int(timeout_seconds), 600))
    async with _client(ctx) as client:
        while True:
            resp = await client.get(f"/runs/{run_id}")
            _raise_for_status(resp)
            detail = resp.json()
            if detail.get("status") in _TERMINAL or time.monotonic() >= deadline:
                break
            await asyncio.sleep(5)
    result = {k: detail.get(k) for k in _WAS_FIELDS}
    result["finished"] = detail.get("status") in _TERMINAL
    return _redact_secrets(result)


@mcp.tool()
async def get_was_setup(ctx: Context, run_id: str) -> dict[str, Any]:
    """
    What to enter in Tenable WAS for a successful run: the authentication
    method, login page, page to verify, the success pattern as a regex, and
    the .side script(s) by name with their replay-verification status.

    The .side file itself (which contains the credentials, for the scanner)
    is never returned: the user downloads it from the run page.
    """
    async with _client(ctx) as client:
        resp = await client.get(f"/runs/{run_id}")
        _raise_for_status(resp)
        detail = resp.json()
    return _redact_secrets({k: detail.get(k) for k in _WAS_FIELDS})


@mcp.tool()
async def get_run_timeline(ctx: Context, run_id: str, limit: int = 80) -> list[dict[str, Any]]:
    """
    The step-by-step log of a run (most recent last), for explaining what
    happened or why it failed. Messages never contain credentials.

    Args:
        run_id: the run.
        limit: how many of the latest events to return (1-300, default 80).
    """
    async with _client(ctx) as client:
        resp = await client.get(f"/runs/{run_id}")
        _raise_for_status(resp)
        timeline = resp.json().get("timeline") or []
    limit = max(1, min(int(limit), 300))
    return _redact_secrets(timeline[-limit:])


@mcp.tool()
async def list_artifacts(ctx: Context, run_id: str) -> list[dict[str, Any]]:
    """
    The files a run produced (scripts, screenshots, HAR, scanner imports):
    name, type, size and role only. Contents are never returned; the user
    downloads them from the run page.
    """
    async with _client(ctx) as client:
        resp = await client.get(f"/runs/{run_id}/artifacts")
        _raise_for_status(resp)
        rows = resp.json()
    keep = ("id", "name", "type", "size_bytes", "role_label", "description", "created_at")
    return [{k: row.get(k) for k in keep} for row in rows]


@mcp.tool()
async def verify_script(ctx: Context, run_id: str, artifact_id: str) -> dict[str, Any]:
    """
    Replay a run's .side script in a clean browser, the way the scanner will,
    to confirm it really logs in. The result shows up in get_was_setup()
    (scripts[].verification) after a minute or so.

    This performs one more login against the target with the stored
    credentials, so only do it when the user asks or agrees.

    Args:
        run_id: the run.
        artifact_id: the script's id, from get_was_setup() or list_artifacts().
    """
    async with _client(ctx) as client:
        resp = await client.post(f"/runs/{run_id}/artifacts/{artifact_id}/verify")
        _raise_for_status(resp)
        return _redact_secrets(resp.json())


# --- Trigger new runs --------------------------------------------------------


@mcp.tool()
async def submit_run(
    ctx: Context,
    target_url: str,
    credential_id: str,
    auth_type: str | None = None,
    login_hint: str | None = None,
    domain_prefix: str | None = None,
) -> dict[str, Any]:
    """
    Launch a new AuthRecon run against a target.

    IMPORTANT: this only accepts a reference to a credential already saved
    in AuthRecon (credential_id) — it will not accept a raw username or
    password. Use list_credentials() to find one; if none fits, ask the
    user to save the credentials in the AuthRecon app (Launch page, "save
    these credentials") and reference the new one here.
    This is deliberate: a raw password passed through a tool call ends up
    in this model provider's own request logs, permanently, outside
    AuthRecon's control. Referencing a stored credential avoids that.

    Args:
        target_url: URL to authenticate against.
        credential_id: ID of a credential already saved in AuthRecon.
        auth_type: optional override (e.g. azure_ad, ldap, okta, saml,
            form_auth) if you already know it.
        login_hint: optional keyword to disambiguate multiple login
            buttons/options on the target page.
        domain_prefix: optional NetBIOS-style domain prefix for the
            username (e.g. "COMPANY" for COMPANY\\username).
    """
    payload: dict[str, Any] = {"target_url": target_url, "credential_id": credential_id}
    if auth_type:
        payload["auth_type"] = auth_type
    if login_hint:
        payload["login_hint"] = login_hint
    if domain_prefix:
        payload["domain_prefix"] = domain_prefix

    async with _client(ctx) as client:
        resp = await client.post("/runs", json=payload)
        _raise_for_status(resp)
        return _redact_secrets(resp.json())


@mcp.tool()
async def cancel_run(ctx: Context, run_id: str) -> dict[str, Any]:
    """Cancel a running or queued AuthRecon run."""
    async with _client(ctx) as client:
        resp = await client.post(f"/runs/{run_id}/cancel")
        _raise_for_status(resp)
        return _redact_secrets(resp.json())


@mcp.tool()
async def rerun(ctx: Context, run_id: str) -> dict[str, Any]:
    """Re-run a previous AuthRecon run using the same configuration."""
    async with _client(ctx) as client:
        resp = await client.post(f"/runs/{run_id}/rerun")
        _raise_for_status(resp)
        return _redact_secrets(resp.json())


# --- Playbook management -----------------------------------------------------
# A playbook is a learned set of selectors for a domain+auth_type, reused
# instead of re-detecting from scratch on repeat runs. They're keyed by
# domain, not full path, so a playbook learned from one page can get wrongly
# reused against a different, unrelated page on the same domain — these
# tools are the fix for a run stuck on a bad playbook with no other way to
# clear it.


@mcp.tool()
async def list_playbooks(ctx: Context, domain: str | None = None) -> list[dict[str, Any]]:
    """
    List your learned auth playbooks (selectors AuthRecon reuses for repeat
    runs against a domain), optionally filtered to one domain.
    """
    async with _client(ctx) as client:
        params = {"domain": domain} if domain else None
        resp = await client.get("/playbooks", params=params)
        _raise_for_status(resp)
        return _redact_secrets(resp.json())


@mcp.tool()
async def clear_playbook(ctx: Context, playbook_id: str) -> dict[str, Any]:
    """Delete one playbook by ID."""
    async with _client(ctx) as client:
        resp = await client.delete(f"/playbooks/{playbook_id}")
        _raise_for_status(resp)
        return {"deleted": True, "playbook_id": playbook_id}


@mcp.tool()
async def clear_playbooks_for_domain(ctx: Context, domain: str) -> dict[str, Any]:
    """
    Delete every playbook for a domain in one call. Use this when a run
    keeps failing because it's reusing stale/wrong selectors learned from a
    different page on the same domain — this clears the slate so the next
    run re-detects from scratch.
    """
    async with _client(ctx) as client:
        resp = await client.delete("/playbooks", params={"domain": domain})
        _raise_for_status(resp)
        return _redact_secrets(resp.json())


# --- Assist with complex login flows -----------------------------------------


@mcp.tool()
async def get_stuck_run_context(ctx: Context, run_id: str) -> dict[str, Any]:
    """
    Get sanitized pre/post-authentication page HTML for a run the
    rule-based pattern library couldn't confidently classify, so you can
    help work out the right login selectors.

    The HTML has already been sanitized server-side before this tool ever
    sees it: every password-type input, every credential-shaped field,
    and every credential-shaped string in the page text has been stripped
    or redacted. You will never receive a real credential value through
    this tool.

    After forming a hypothesis, call submit_login_suggestion() with your
    proposed selectors — you propose where the fields are; AuthRecon's
    own deterministic code (which already holds the real credential) is
    what would actually attempt the login.
    """
    async with _client(ctx) as client:
        resp = await client.get(f"/runs/{run_id}/ai-context")
        _raise_for_status(resp)
        return _redact_secrets(resp.json())


@mcp.tool()
async def submit_login_suggestion(
    ctx: Context,
    run_id: str,
    auth_type: str,
    confidence: float,
    reasoning: str,
    username_selector: str | None = None,
    password_selector: str | None = None,
    submit_selector: str | None = None,
) -> dict[str, Any]:
    """
    Record a suggested auth type and selectors for a run, based on the
    sanitized page context from get_stuck_run_context().

    This records the suggestion against the run — it does NOT retry
    automatically. Call rerun() afterward (for form-based auth, the
    worker will try these selectors as a last resort if heuristic
    detection and any existing playbook both fail again) if you want it
    acted on; an operator can also just review it without retrying. You
    never provide or receive a credential value here, only selector
    guesses — the worker uses its own stored credential if it retries.

    Args:
        confidence: your confidence in this suggestion, 0.0 to 1.0.
        reasoning: brief explanation of why you believe this, for the
            operator reviewing it later.
    """
    payload = {
        "auth_type": auth_type,
        "confidence": confidence,
        "reasoning": reasoning,
        "username_selector": username_selector,
        "password_selector": password_selector,
        "submit_selector": submit_selector,
    }
    async with _client(ctx) as client:
        resp = await client.post(f"/runs/{run_id}/ai-suggestion", json=payload)
        _raise_for_status(resp)
        return _redact_secrets(resp.json())


# --- Scan export analyzer (SCAFFOLD) -----------------------------------------
# Users upload Tenable WAS scan exports in the AuthRecon app; these tools let
# the connected AI read the parsed summary to help fix scan problems (timeouts,
# needed exclusions, scan breakdowns). The raw zip is never exposed: it can
# contain scan credentials. TODO(scan-analyzer): findings-level tools once the
# parser exists (e.g. get_scan_issues, and a human-approved way to record
# suggested scan-config changes - see SECURITY.md, "AI and MCP").

_SCAN_EXPORT_FIELDS = ("id", "filename", "status", "created_at", "size_bytes")


@mcp.tool()
async def list_scan_exports(ctx: Context, limit: int = 20) -> list[dict[str, Any]]:
    """
    List Tenable WAS scan exports uploaded to AuthRecon for analysis.
    Returns id, filename, status, upload time and size only.
    """
    async with _client(ctx) as client:
        resp = await client.get("/scan-exports")
        _raise_for_status(resp)
        exports = resp.json()[: max(1, min(limit, 100))]
    return [{k: e.get(k) for k in _SCAN_EXPORT_FIELDS} for e in exports]


@mcp.tool()
async def get_scan_export_summary(ctx: Context, export_id: str) -> dict[str, Any]:
    """
    Get the parsed summary of one uploaded WAS scan export: file inventory
    today; scan findings once the analyzer's parser is built. Never includes
    file contents, credentials or the raw zip.
    """
    async with _client(ctx) as client:
        resp = await client.get(f"/scan-exports/{export_id}")
        _raise_for_status(resp)
        data = _redact_secrets(resp.json())
    return {
        **{k: data.get(k) for k in _SCAN_EXPORT_FIELDS},
        "summary": data.get("summary"),
        "error": data.get("error"),
    }


# --- Client authentication -------------------------------------------------


def _json(status: int, body: bytes, extra: list[tuple[bytes, bytes]] | None = None) -> list[dict]:
    headers = [(b"content-type", b"application/json")] + (extra or [])
    return [
        {"type": "http.response.start", "status": status, "headers": headers},
        {"type": "http.response.body", "body": body},
    ]


class ApiKeyGateMiddleware:
    """Per-request gate: a valid AuthRecon API key, MCP enabled, within rate limit."""

    def __init__(self, app: Any, *, clock: Callable[[], float] = time.monotonic) -> None:
        self.app = app
        self._clock = clock
        self._ok_until: dict[str, float] = {}
        self._hits: dict[str, deque[float]] = {}

    def _rate_limited(self, key_id: str) -> bool:
        now = self._clock()
        hits = self._hits.setdefault(key_id, deque())
        while hits and now - hits[0] > 60:
            hits.popleft()
        if len(hits) >= RATE_LIMIT_PER_MINUTE:
            return True
        hits.append(now)
        return False

    async def _check(self, key: str, key_id: str) -> tuple[int, bytes]:
        if self._ok_until.get(key_id, 0) > self._clock():
            return 200, b""
        async with _api(key) as client:
            resp = await client.get("/ai/mcp-gate")
        if resp.status_code == 200:
            self._ok_until[key_id] = self._clock() + GATE_CACHE_SECONDS
        else:
            self._ok_until.pop(key_id, None)
        return resp.status_code, resp.content

    async def __call__(self, scope: dict, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = {k.decode("latin-1"): v.decode("latin-1") for k, v in scope.get("headers", [])}
        key = _bearer(headers)
        if not key.startswith("ak_live_"):
            for msg in _json(401, b'{"error":"An AuthRecon API key is required (Authorization: Bearer ak_live_...)"}',
                             [(b"www-authenticate", b"Bearer")]):
                await send(msg)
            return
        key_id = hashlib.sha256(key.encode()).hexdigest()
        if self._rate_limited(key_id):
            for msg in _json(429, b'{"error":"Rate limit exceeded"}', [(b"retry-after", b"60")]):
                await send(msg)
            return
        try:
            status, body = await self._check(key, key_id)
        except httpx.HTTPError:
            for msg in _json(503, b'{"error":"AuthRecon API unavailable"}'):
                await send(msg)
            return
        if status != 200:
            code = status if status in (401, 403) else 502
            for msg in _json(code, body or b'{"error":"rejected"}'):
                await send(msg)
            return
        await self.app(scope, receive, send)


def build_http_app() -> ApiKeyGateMiddleware:
    # Stateless + JSON responses: every MCP message is a plain request/response,
    # which the portal's reverse proxy passes through unchanged. Host-header
    # (DNS-rebinding) checks are off because clients arrive via the portal with
    # its Host; the API-key gate is what authenticates them.
    inner = mcp.streamable_http_app(
        stateless_http=True,
        json_response=True,
        host=MCP_HOST,
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )
    return ApiKeyGateMiddleware(inner)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(build_http_app(), host=MCP_HOST, port=MCP_PORT)
