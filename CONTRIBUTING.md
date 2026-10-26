# Contributing

Bug reports and ideas are welcome as [GitHub Issues](https://github.com/AuthRecon/AuthRecon/issues). Include what you expected, what happened, steps to reproduce, the version (`VERSION`) and the relevant `docker compose logs <service>` output. Don't put real hostnames, credentials or captured artifacts in an issue. Security problems go through private reporting; see [SECURITY.md](./SECURITY.md).

## Layout

```
src/                              React 18 + Vite + Tailwind UI (plain JSX)
backend/security-portal/          Portal: login, two-factor, session cookies, gateway/proxy, LoginLab control, audit log
backend/authrecon/backend/        authrecon-api and authrecon-worker (FastAPI, RQ, Alembic)
  app/worker.py                   run pipeline and per-login-type dispatch
  app/services/auth_detection.py  login-type detection (+ scoring.py)
  app/services/automation/        login patterns (patterns/), pre-run discovery, AI-suggestion sanitizer
  app/services/side_files.py      builds the .side scripts
  app/services/side_replay.py     "Verify": replays a .side in a clean browser
  app/services/scan_readiness.py  per-run scan readiness grade and starting WAS settings
  app/services/scan_analysis.py   Scan Analyzer rules for uploaded WAS exports (+ scan_export_parser.py)
  app/services/target_guard.py    which targets may be visited; credential_domains.py binds credentials to hosts
  browser_agent/                  agent for the isolated browser container (BROWSER_ISOLATION)
  alembic/versions/               database migrations
backend/authrecon/cli/            `authrecon` CLI
backend/authrecon-mcp/            MCP server (separate service, reached through the portal)
backend/loginlab/                 practice login targets (fictional, deliberately weak)
docker-compose.yml                full stack; docker-compose.dev.yml = hot-reload frontend
install.sh                        installer
```

## Development

```bash
./install.sh                                    # once, generates .env files
docker compose up -d --build <service>          # code is baked into images; rebuild after backend edits
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d frontend   # Vite hot reload (local only)
docker compose --profile loginlab up -d loginlab                              # practice targets
```

Things to know:
- All services use Pydantic v2. In authrecon-api, URL fields use `app.schemas.types.HttpUrlStr` (validated, kept exactly as given), not `AnyHttpUrl`, and a nullable field needs an explicit `= None` to be optional.
- FastAPI 204 routes return `Response(status_code=204)`.
- New migrations go in `backend/authrecon/backend/alembic/versions/`. After changing migrations or `install.sh`, test with a **fresh clone + `./install.sh`**, because upgrade-in-place hides fresh-install bugs.

## Tests

```bash
(cd backend/authrecon/backend && python -m pytest tests)
(cd backend/security-portal  && python -m pytest tests)
(cd backend/authrecon-mcp    && python -m pytest tests)
npm ci && npm test && npm run build
```
CI (`.github/workflows/tests.yml`) runs the same steps, plus `pip-audit`, `npm audit` and a gitleaks secret scan. Regenerate `package-lock.json` with npm 11 or later; npm 10 can write a lockfile that `npm ci` then rejects. The unit tests use SQLite and mocks: no browsers, no Docker. Anything touching login automation also needs a real run against LoginLab, then **Verify** on the resulting `.side`. A `.side` that doesn't replay in a clean browser doesn't work in WAS.

## Adding a login type

1. **Detect it:** have `auth_detection.py`/`scoring.py` emit an `auth_type` string for it.
2. **Dispatch it:** in `app/worker.py`, accept that string in the dispatch block (look for `used_form_auth`) and add a `_run_<type>_variant` function. Reuse an existing pattern from `services/automation/patterns/` where you can.
3. **Record the script:** build the `.side` through `services/side_files.py`. Record every click the replay needs (including "show password" or "next" buttons), put a `waitForElementVisible` before each action, and set the page to verify.
4. **Add a target:** add a LoginLab scenario in `backend/loginlab/app/api/scenarios/` and test against it end to end, ending with Verify.
5. **Tests:** cover the detection and the `.side` steps.

Security rules for any change:
- **Before typing or posting a password,** call `ensure_safe_to_type(<current page URL>)` (`services/automation/typing_guard.py`). It stops the run if the login landed on a host the credential is not allowed on.
- **Create browsers only through** `create_webdriver()` (Selenium) and `launch_chromium()` + `harden_playwright_context()` (Playwright): they block requests to AuthRecon's own services and cloud metadata, deny downloads, and start the browser in the isolated container when browser isolation is on. Files a browser writes (HAR captures) go under `browser_tmp_dir()`, which that container shares.
- **New ways to reach a URL** (an HTTP client, a redirect follower) must check it with `services/target_guard.py`.
- Never put credentials, cookies or tokens in logs, timeline events or HARs.
- Every endpoint checks auth plus owner-or-admin. Add a cross-user test.
- Fail closed on missing secrets.
- Keep LoginLab loopback-only.
- **UI:** never store a token in `localStorage` or return one in a response to a browser session; the session is an HttpOnly cookie. No inline scripts or third-party hosts (the UI runs under a strict CSP).

## Releasing

The version lives in `VERSION`. When bumping it, update these too:
- `APP_VERSION` in `backend/authrecon/backend/app/core/config.py` and `backend/security-portal/config.py`
- `__version__` in `backend/authrecon/cli/authrecon/__init__.py`, and `version=` in `backend/authrecon/cli/setup.py`
- `package.json` and `package-lock.json` (`npm version <x.y.z> --no-git-tag-version`)

`backend/authrecon/backend/tests/test_version.py` fails if any of these drift.

## License

Contributions are accepted under the [Apache License 2.0](./LICENSE).
