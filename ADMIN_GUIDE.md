# AuthRecon Admin Guide

Install, operate and troubleshoot an AuthRecon deployment. Run all commands from the checkout directory.

## Install

```bash
./install.sh
```

- Run it as a user in the `docker` group, or with `sudo`. Under `sudo`, the generated files are handed back to the user who invoked it. On macOS with Docker Desktop, run it as yourself (no `sudo`).
- It prompts for the address users will browse to (e.g. `http://10.0.0.5:5173` or `https://authrecon.example.com`), which sets the frontend's API URLs and CORS.
- It writes four files, all mode `0600`. `.env.secrets` lists every generated secret, so **back it up somewhere safe**. The other three are `.env` (Compose settings), `backend/security-portal/.env` and `backend/authrecon/backend/.env`.
- It refuses to run over an existing install, because new secrets wouldn't match the existing database. `FORCE_REINSTALL=1 ./install.sh` overrides this, but you then have to rotate the database passwords to match.
- Database migrations run automatically when the worker starts.

Then open `<address>/setup` to create the first admin. `/setup` closes once an account exists.

If a first install fails before the database is up (a build or download error), the installer removes the files it generated, so you can fix the problem and run it again.

**Check it's healthy:**
```bash
docker compose ps
curl -sf http://localhost:9000/healthz          # portal
curl -sf http://localhost:8001/health/ready     # authrecon-api
```

## Corporate networks (TLS inspection and private mirrors)

Skip this section unless the install fails while downloading packages. Before the build, the installer fetches one Python and one npm package the way the build will, and says which of these two problems you have.

**1. The network inspects TLS.** A corporate proxy re-signs HTTPS with its own root certificate. Your laptop trusts that certificate, but the build containers don't. The errors look like this:
```
SSL: CERTIFICATE_VERIFY_FAILED ... self-signed certificate in certificate chain   (pip)
SELF_SIGNED_CERT_IN_CHAIN / UNABLE_TO_GET_ISSUER_CERT_LOCALLY                      (npm)
```
Export the proxy's root certificate as PEM (below) and run:
```bash
./install.sh --ca-file ~/root-ca.pem      # repeat --ca-file for more than one certificate
```
This copies the file into `certs/`. Every image trusts the certificates in `certs/`, both while building and at run time, so the API's own HTTPS requests through the proxy work too. With `certs/` empty, nothing changes.

Exporting the root certificate:
- **Which certificate:** run `openssl s_client -connect pypi.org:443 </dev/null 2>/dev/null | openssl x509 -noout -issuer`. If the issuer is your organisation's or your proxy vendor's CA rather than a public CA, you need that issuer's **root** certificate. Your IT team or the proxy client's install directory often has it as a file already.
- **macOS:** `security find-certificate -a -p -c "<root CA name>" /Library/Keychains/System.keychain > ~/root-ca.pem`. Or, in Keychain Access › System › Certificates, select the certificate, then File › Export Items › format *Privacy Enhanced Mail (.pem)*.
- **Linux:** use the file your IT team installed, usually in `/usr/local/share/ca-certificates/` (Debian, Ubuntu) or `/etc/pki/ca-trust/source/anchors/` (RHEL, Fedora).
- **Windows / WSL:** run `certmgr.msc` › Trusted Root Certification Authorities › Certificates, right-click the certificate, then All Tasks › Export › *Base-64 encoded X.509*. From WSL the file is under `/mnt/c/Users/<you>/`.
- A DER (binary) file must be converted first: `openssl x509 -inform der -in root-ca.cer -out root-ca.pem`.

Check the certificate works before a long build. The command prints `200`, or a certificate error if the certificate is still missing:
```bash
docker run --rm -v "$PWD/certs:/certs:ro" python:3.12-slim python -c "import glob,ssl,urllib.request as u; c=ssl.create_default_context(); [c.load_verify_locations(f) for f in glob.glob('/certs/*.crt')+glob.glob('/certs/*.pem')]; print(u.urlopen('https://pypi.org/simple/pip/', context=c).status)"
```

**2. The public registries are blocked.** You get HTTP 403, or a proxy block page, from `pypi.org`, `files.pythonhosted.org` or `registry.npmjs.org`, and your organisation provides a mirror (Artifactory, Nexus, ...) instead. Run:
```bash
./install.sh --pip-index                  # prompts for the index URL; input is hidden
./install.sh --npmrc ~/.npmrc-mirror      # an .npmrc for your npm mirror
```
(Combine them with `--ca-file` in one run.) The settings are saved in `.build-secrets/` (mode 0600, ignored by git and Docker), and `.env` gets `COMPOSE_FILE=docker-compose.yml:docker-compose.mirror.yml`, so later `docker compose` builds use the mirror too. They are passed to the build as BuildKit secrets, mounted only while dependencies install, so they never end up in an image layer or in `docker history`.

- **PyPI index URL:** the mirror's *simple* index, with your credentials, e.g. `https://USER:TOKEN@mirror.example.com/artifactory/api/pypi/pypi-remote/simple` (Artifactory) or `https://USER:TOKEN@mirror.example.com/repository/pypi-proxy/simple` (Nexus).
- **URL-encode the username and token.** A URL can contain only one bare `@`, the one before the host, so an e-mail username like `jane@example.com` must be written `jane%40example.com`. Encode `:`, `/`, `#`, `?` and `%` in either part the same way. `python3 -c 'import sys,urllib.parse as p; print(p.quote(sys.argv[1], safe=""))' 'jane@example.com'` prints the encoded form. Don't run that on a token, because it would land in your shell history. Tokens are usually URL-safe already.
- **npmrc:**
  ```
  registry=https://mirror.example.com/artifactory/api/npm/npm-remote/
  //mirror.example.com/artifactory/api/npm/npm-remote/:_authToken=TOKEN
  ```
- pip hides the password in its build output, but the username appears there.

**Existing install:** put the certificate in `certs/`, or create both `.build-secrets/pip_index_url` and `.build-secrets/npmrc` (leave one empty if you only need the other; mode 0600). For the mirror, also add the `COMPOSE_FILE=...` line above to `.env`. Then run `docker compose up -d --build`.

**Other downloads during the build.** Docker Desktop or the Docker daemon pulls the base images itself, so give it your proxy settings if those pulls fail. The worker image also downloads Chromium for Playwright and noVNC (from GitHub, checksum-verified). Neither goes through the mirror, so those hosts must be reachable, through the inspecting proxy if need be.

## Upgrade

```bash
git pull                       # or unpack the new release over the checkout, keeping your .env files
docker compose up -d --build   # migrations run when the worker restarts
docker compose logs authrecon-worker | grep -i "alembic\|listening"
```

Never run `docker compose down -v`: it deletes the database and artifact volumes. Take a [database dump](#back-up) before upgrading.

**Upgrading to 0.11:**
- Everyone is signed out once: sessions moved from browser storage to an HttpOnly cookie. Users sign in again; nothing else changes for them.
- Two migrations run at worker start. Existing stored credentials have no domain list yet: each is bound to the host of the next run that uses it, or set its domains first ([Stored credentials](#stored-credentials-and-their-domains)). Existing API keys keep full access; new keys can be read-only.
- The UI and the portal must be on the same host name (see [Network exposure](#network-exposure)); installs made with `install.sh` already are.
- Browser isolation is new and off by default; [turn it on](#browser-isolation-recommended) after the upgrade if you want it.

## Back up

| What | Where |
|---|---|
| Secrets | `.env.secrets` and the three `.env` files |
| Databases (users, runs, stored credentials) | volume `<project>_authrecon_db` |
| Run artifacts (encrypted) | volume `<project>_authrecon_artifacts` |
| Portal keys | volume `<project>_portal-data` |

`<project>` is the checkout directory's name. A logical database dump:
```bash
docker compose exec -T postgres pg_dumpall -U postgres | gzip > authrecon-db-$(date +%F).sql.gz
```
Encrypted data can't be read back without the matching secrets, so keep secrets and dumps together (and secured).

## Secrets

| Secret (`.env.secrets` name) | Used by | Notes |
|---|---|---|
| `AUTHRECON_SECRET_KEY` → `SECRET_KEY` | authrecon-api/worker | **Master encryption key** for stored credentials and per-user artifact keys. Changing it makes all of them unreadable. Do not rotate without a re-encryption step. |
| `PORTAL_ENCRYPTION_KEY` | portal | Encrypts portal-side stored secrets. Same rule: don't rotate without re-encrypting. |
| `PORTAL_SECRET_KEY` | portal | Signs user sessions/JWTs. Rotating logs everyone out. |
| `AUTHRECON_JWT_SECRET` → `JWT_SECRET_KEY` | authrecon-api | The API's own tokens. |
| `PORTAL_API_SECRET` | portal, authrecon-api, worker | Service-to-service auth. Must be identical everywhere. |
| `LOGINLAB_SERVICE_TOKEN` | portal, loginlab | LoginLab's own token, kept separate from the service secret on purpose. |
| `BROWSER_AGENT_TOKEN` | authrecon-browser, authrecon-api, worker | Lets the worker and API start browsers in the isolated browser container. Used only with browser isolation on. |
| `*_DB_PASSWORD`, `POSTGRES_SUPERUSER_PASSWORD`, `REDIS_PASSWORD` | database, cache | |

Every service refuses to start if a required secret is missing.

**Rotating** a signing secret, `PORTAL_API_SECRET`, `LOGINLAB_SERVICE_TOKEN`, `BROWSER_AGENT_TOKEN` or the Redis password:
1. Generate a value with `openssl rand -hex 32`.
2. Update it in `.env.secrets` and in every `.env` that contains it (`grep -l NAME .env backend/*/.env backend/authrecon/backend/.env`).
3. Apply it with `docker compose up -d`. A `restart` would keep the old environment.

**Database passwords:** first change the password in Postgres, e.g. `docker compose exec postgres psql -U postgres -c "ALTER USER authrecon WITH PASSWORD '<new>'"`. Then update the `.env` files and run `docker compose up -d`.

## Network exposure

- Put the UI (5173) and portal (9000) behind your reverse proxy or firewall like any internal web app. Serve both from the same host name (the installer does): the sign-in is an HttpOnly cookie restricted to the same site, so a UI at `https://authrecon.example.com` with the portal at another domain cannot sign in. Behind a TLS proxy the cookies are marked `Secure` automatically when the proxy sends `X-Forwarded-Proto: https`; set `SESSION_COOKIE_SECURE=true` in `backend/security-portal/.env` to force it.
- **Port 8001 (authrecon-api) is published on all interfaces** so the CLI and scripts can reach it. Requests on that port still need a valid API key or token, but they skip the portal layer (its per-request user checks and audit trail). Allow it with a host or network firewall only from hosts that need CLI access, or block it if nobody uses the CLI.
- LoginLab binds to `127.0.0.1` only. Its accounts and passwords are published in the docs, so never publish it.
- The MCP server and VNC live views publish no ports; they're reached only through the portal. The isolated browser container (`authrecon-browser`) publishes none either.

## Which targets AuthRecon may visit

AuthRecon loads, renders and screenshots whatever target it is given, from inside the Docker network that also holds its database and services. So it refuses some targets:
- cloud metadata addresses (`169.254.169.254` and similar), loopback, link-local and reserved addresses;
- AuthRecon's own services (`postgres`, `redis`, `portal`, `authrecon-api`, ...) and any address on its internal Docker network;
- the Docker host (`host.docker.internal`).

This is checked when a run is submitted, again when it starts (DNS can change in between), on every redirect during detection, and inside the browser for every request a page makes. Private ranges (10/8, 172.16/12, 192.168/16) stay allowed, because scanning internal applications is the main use. Adjust with these variables in `backend/authrecon/backend/.env`, then `docker compose up -d`:

| Variable | Effect |
|---|---|
| `TARGET_ALLOW` | Comma-separated hosts or CIDRs that are always allowed, e.g. `host.docker.internal` for an app running on the Docker host, or `10.20.0.0/16`. |
| `TARGET_DENY` | Comma-separated hosts or CIDRs that are always refused. |
| `TARGET_BLOCK_PRIVATE` | `true` to also refuse private addresses (internet-facing targets only). |

## Browser isolation (recommended)

By default the browsers that visit target sites run inside the worker and API containers, which also hold AuthRecon's master key and database access. With browser isolation on, every such browser (automated runs, detection, Verify, HAR capture, the Playwright engine, the live view and manual recording) runs in a separate `authrecon-browser` container instead:
- it holds no AuthRecon secrets, only its own agent token;
- it is on its own network with the worker, the API, LoginLab and the portal (which proxies the live view), and cannot reach Postgres, Redis or the MCP server. It can reach the portal's sign-in page, as any machine on your network can;
- the worker and API drive its browsers over WebDriver and Playwright, and the live view's display and VNC server run there too, so runs, screenshots, HAR, Verify, patterns, the live view and manual recording work the same.

Turn it on in `.env` (new installs already have `BROWSER_AGENT_TOKEN`; on an older install add one with `openssl rand -hex 32`):
```bash
BROWSER_ISOLATION=true
COMPOSE_PROFILES=browser-isolation
```
then `docker compose up -d --build`.

## Stored credentials and their domains

Each stored credential lists the domains it may be used on (**New Run › Saved credential › Edit domains**): `app.example.com`, or `*.example.com` for a domain and its subdomains. A run against any other host is refused, including runs an AI client starts. A credential with no domains is bound to the host of the first run that uses it.

During a run the worker also checks the page before typing a password. It types only on the target's own domain, the credential's allowed domains and well-known identity providers (Microsoft, Okta, Google, Auth0, Ping, OneLogin, ...). A login that redirects anywhere else stops with an error instead of handing over the password. If a legitimate login uses another host (for example a company ADFS server on a different domain), add that host to the credential's domains.

## HTTPS

Terminate TLS at a reverse proxy (nginx, Caddy, ...) in front of ports 5173 and 9000. Then:
1. Set the `VITE_*` URLs in `.env` to the `https://` / `wss://` addresses.
2. Set `ALLOWED_ORIGINS` in `backend/security-portal/.env` and in `backend/authrecon/backend/.env` to the HTTPS UI origin.
3. Rebuild the frontend, because the URLs are compiled into it (and into its Content-Security-Policy, which only lets the UI connect to those addresses): `docker compose up -d --build frontend && docker compose up -d`.

MCP clients on other machines send their API key on every request, so give them HTTPS.

## Users and API keys

- Admins manage users in **Settings › User Management**.
- API keys (for the CLI and AI clients) are created in **Settings › AI & MCP**. Admins can always create keys; an admin decides who else can. Keys are shown once, are stored hashed, and can be given an expiry or revoked at any time.
- A new user sees a short security notice that must be acknowledged, again every 7 days.

### Two-factor authentication

- Each user turns it on in **Settings › Account › Two-factor authentication**: scan the QR code with an authenticator app (Microsoft or Google Authenticator, 1Password, 2FAS, ...), enter a code, and save the 10 backup codes shown once. Sign-in then asks for a code after the password; a backup code works once in place of a code.
- The app lists the entry as **AuthRecon** with the part of the username before the @ (`jane.doe`, not the full email), so apps that guess a logo from the text don't show another company's. Most apps show a plain text badge (e.g. "AU") because AuthRecon has no logo in their catalogue; the app can rename it.
- **Require it for admins:** an admin with two-factor on can tick *Require two-factor for all administrators* in the same section. Other admins without it then reach only the setup page at their next sign-in, until they turn it on.
- **Lost phone:** another admin resets it with the shield button in **Settings › User Management**; the user signs in with their password and sets it up again. Every change is in the audit log.
- **The only admin lost both the phone and the backup codes:** turn it off from the server, then sign in with the password and set it up again:
  ```bash
  docker compose exec -T postgres psql -U postgres -d portal \
    -c "DELETE FROM user_mfa WHERE user_id = (SELECT id FROM portal_users WHERE username = 'admin@example.com')"
  ```

## AI & MCP

All of it is configured in **Settings › AI & MCP**; nothing goes in `.env`.
- MCP is **off** until an admin switches it on. While off, every client gets a 403. Changes apply within about 10 seconds.
- Each client authenticates with its own user's API key, acts as that user and sees only that user's data. Revoking the key cuts the client off.
- Rate limit: 120 requests per minute per key (`MCP_RATE_LIMIT_PER_MINUTE` on `authrecon-mcp`).
- **Read-only keys:** tick *Read-only* when creating a key. The client can list and read runs, WAS setup and exports, but every write is refused.
- **Approval:** *Runs started by AI clients need approval* (admin) holds every MCP-submitted run on its run page until a person approves or rejects it in the web UI.
- 19 tools: list and inspect runs, timelines and artifacts; detect a login type; list stored credentials (labels only); submit, wait for, cancel and rerun runs; get the WAS settings and run Verify; get sanitized context for a stuck run and submit a selector suggestion; manage playbooks; list and summarize scan exports.
- What the AI can and can't see: [SECURITY.md](./SECURITY.md#ai-and-mcp).

## LoginLab

```bash
docker compose --profile loginlab up -d loginlab   # start the container (loopback only)
```
Then use **Settings › LoginLab** to enable it for a time window. Target URLs use the internal hostname, e.g. `http://loginlab:5500/form-login`. Test account: `testuser@loginlab.local` / `TestPass123!`. Stop it with `docker compose stop loginlab`.

## CLI

```bash
pip install -e backend/authrecon/cli      # installs the `authrecon` command
authrecon login --api-url http://<host>:8001/api/v1   # prompts for an API key
authrecon runs list
authrecon runs show RUN-XXXXXXXX
authrecon runs create --target https://app.example.com/login --username alice   # prompts for the password
authrecon api-keys list | create --name CI --expires-days 30 | revoke <id>
```
Config is stored in `~/.authrecon/config.yaml`. In CI, read the password from a secret variable (`--password "$TEST_PASSWORD"`) instead of typing it on the command line.

## Scan readiness and the Scan Analyzer

- **Scan readiness** (bottom of a run's Tenable WAS card) grades a successful login for scanning and suggests starting settings named as in the WAS scan configuration. It comes from one login, so treat it as a starting point.
- **Scan Analyzer** (*preview*): after a scan, upload its debug `.zip` and/or its `.json` export (WAS: export the scan). The JSON includes the scan's own settings, so suggestions show current → new values. It reads Tenable's diagnostic plugins (authentication, logouts, timeouts, WAF, sitemap reasons, plugin telemetry) and lists the changes to make. The rules have not yet been tuned on many real exports; review its suggestions before applying them. **Re-analyze** re-reads a stored export after an AuthRecon upgrade.
- Neither needs an AI client. An MCP client can read the same analysis (`get_scan_export_summary`, `get_was_setup`); it never includes plugin output, query strings or credentials.

## Playbooks

After a successful run, AuthRecon saves the selectors as a playbook keyed by **domain + login type** and reuses them on later runs. If one domain hosts two different login pages, a playbook from one page can be wrongly reused on the other, and runs then fail with no obvious cause. To clear playbooks:

```bash
curl -H "X-API-Key: $KEY" "http://localhost:8001/api/v1/playbooks?domain=example.com"            # list
curl -X DELETE -H "X-API-Key: $KEY" "http://localhost:8001/api/v1/playbooks/<id>"                # one
curl -X DELETE -H "X-API-Key: $KEY" "http://localhost:8001/api/v1/playbooks?domain=example.com"  # whole domain
```
The same actions are available as MCP tools.

## Upgrading from older versions

Older releases had SecBot and a web scanner. Their databases are no longer used and can be dropped once you don't need the data:
```bash
docker compose exec postgres psql -U postgres -c "DROP DATABASE IF EXISTS secbot" -c "DROP ROLE IF EXISTS secbot" \
  -c "DROP DATABASE IF EXISTS scanner" -c "DROP ROLE IF EXISTS scanner"
```

Releases before 0.12.0 also had a licensing module and LoginLab demo pages styled after real identity providers; both are gone. The portal's two unused licensing tables can be dropped:
```bash
docker compose exec -T postgres psql -U postgres -d portal \
  -c "DROP TABLE IF EXISTS license_activations" -c "DROP TABLE IF EXISTS client_licenses"
```

## Troubleshooting

| Symptom | Check |
|---|---|
| Install or build fails with `CERTIFICATE_VERIFY_FAILED`, HTTP 403 or a block page | See [Corporate networks](#corporate-networks-tls-inspection-and-private-mirrors). |
| A service won't start | `docker compose ps`, then `docker compose logs <service>`. A "Set X in .env" error means a secret is missing. |
| Run stays *queued* | `docker compose logs --tail=50 authrecon-worker`. The worker must log `Listening on runs`. Then `docker compose up -d authrecon-worker`. |
| Run fails | Open the run page. The failure card and the timeline (filter by *error*) show where it stopped, and the screenshots show what the browser saw. |
| Target unreachable | The worker resolves names from inside Docker. For an app on the Docker host use `host.docker.internal` and allow it with `TARGET_ALLOW` (see [Which targets](#which-targets-authrecon-may-visit)). |
| "This target is not allowed" | The target guard refused it; see [Which targets](#which-targets-authrecon-may-visit). |
| "Stopped before entering the password" | The login form was on a host the credential is not allowed on. Add the host to the credential's domains if it is legitimate. |
| `.side` fails in WAS | Click **Verify** on the run page. It replays the script in a clean browser and reports the step that broke. |
| Run keeps failing with stale selectors | Clear that domain's playbooks (see [Playbooks](#playbooks)). |
| Signed out again right after signing in | The sign-in cookie is not reaching the portal: the UI and the portal must use the same host name, and the address you browse must match the `VITE_*` URLs. Over plain HTTP, don't set `SESSION_COOKIE_SECURE=true`. |
| A script gets `403 Missing X-Requested-With header` | It sent the browser's session cookie. Scripts should use `Authorization: Bearer <token>` or an API key instead. |
| Runs fail with "the browser container (authrecon-browser) is not reachable" | `BROWSER_ISOLATION=true` is set but the container isn't running: add `COMPOSE_PROFILES=browser-isolation` to `.env` and run `docker compose up -d`. |
| UI loads but API calls fail | The `VITE_*` URLs in `.env` and `ALLOWED_ORIGINS` must match the address you're browsing; rebuild the frontend after changing them. A browser console message about *Content Security Policy* means the same: the UI was built for another address. |
| CLI says "API access not enabled" | An admin must allow your user under **Settings › AI & MCP › Who can create keys**. |

Logs: `docker compose logs -f portal authrecon-api authrecon-worker authrecon-mcp`.
