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

Never run `docker compose down -v`: it deletes the database and artifact volumes.

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
| `*_DB_PASSWORD`, `POSTGRES_SUPERUSER_PASSWORD`, `REDIS_PASSWORD` | database, cache | |

Every service refuses to start if a required secret is missing.

**Rotating** a signing secret, `PORTAL_API_SECRET`, `LOGINLAB_SERVICE_TOKEN` or the Redis password:
1. Generate a value with `openssl rand -hex 32`.
2. Update it in `.env.secrets` and in every `.env` that contains it (`grep -l NAME .env backend/*/.env backend/authrecon/backend/.env`).
3. Apply it with `docker compose up -d`. A `restart` would keep the old environment.

**Database passwords:** first change the password in Postgres, e.g. `docker compose exec postgres psql -U postgres -c "ALTER USER authrecon WITH PASSWORD '<new>'"`. Then update the `.env` files and run `docker compose up -d`.

## Network exposure

- Put the UI (5173) and portal (9000) behind your reverse proxy or firewall like any internal web app.
- **Port 8001 (authrecon-api) is published on all interfaces** so the CLI and scripts can reach it. Requests on that port still need a valid API key or token, but they skip the portal layer (its per-request user checks and audit trail). Allow it with a host or network firewall only from hosts that need CLI access, or block it if nobody uses the CLI.
- LoginLab binds to `127.0.0.1` only. It is intentionally vulnerable, so never publish it.
- The MCP server and VNC live views publish no ports; they're reached only through the portal.

## HTTPS

Terminate TLS at a reverse proxy (nginx, Caddy, ...) in front of ports 5173 and 9000. Then:
1. Set the `VITE_*` URLs in `.env` to the `https://` / `wss://` addresses.
2. Set `ALLOWED_ORIGINS` in `backend/security-portal/.env` and in `backend/authrecon/backend/.env` to the HTTPS UI origin.
3. Rebuild the frontend, because the URLs are compiled into it: `docker compose up -d --build frontend && docker compose up -d`.

MCP clients on other machines send their API key on every request, so give them HTTPS.

## Users and API keys

- Admins manage users in **Settings › User Management**.
- API keys (for the CLI and AI clients) are created in **Settings › AI & MCP**. Admins can always create keys; an admin decides who else can. Keys are shown once, are stored hashed, and can be given an expiry or revoked at any time.
- A new user sees a short security notice that must be acknowledged, again every 7 days.

## AI & MCP

All of it is configured in **Settings › AI & MCP**; nothing goes in `.env`.
- MCP is **off** until an admin switches it on. While off, every client gets a 403. Changes apply within about 10 seconds.
- Each client authenticates with its own user's API key, acts as that user and sees only that user's data. Revoking the key cuts the client off.
- Rate limit: 120 requests per minute per key (`MCP_RATE_LIMIT_PER_MINUTE` on `authrecon-mcp`).
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

## Playbooks

After a successful run, AuthRecon saves the selectors as a playbook keyed by **domain + login type** and reuses them on later runs. If one domain hosts two different login pages, a playbook from one page can be wrongly reused on the other, and runs then fail with no obvious cause. To clear playbooks:

```bash
curl -H "X-API-Key: $KEY" "http://localhost:8001/api/v1/playbooks?domain=example.com"            # list
curl -X DELETE -H "X-API-Key: $KEY" "http://localhost:8001/api/v1/playbooks/<id>"                # one
curl -X DELETE -H "X-API-Key: $KEY" "http://localhost:8001/api/v1/playbooks?domain=example.com"  # whole domain
```
The same actions are available as MCP tools.

## Licensing

AuthRecon ships with a licensing module (`backend/authrecon/license`, **Settings › Licensing**). Validation is off by default (`LICENSE_VALIDATION_ENABLED=false`), and in that mode every feature is available and no license server is contacted. The module is optional and you can ignore it.

## Upgrading from older versions

Older releases had SecBot and a web scanner. Their databases are no longer used and can be dropped once you don't need the data:
```bash
docker compose exec postgres psql -U postgres -c "DROP DATABASE IF EXISTS secbot" -c "DROP ROLE IF EXISTS secbot" \
  -c "DROP DATABASE IF EXISTS scanner" -c "DROP ROLE IF EXISTS scanner"
```

## Troubleshooting

| Symptom | Check |
|---|---|
| Install or build fails with `CERTIFICATE_VERIFY_FAILED`, HTTP 403 or a block page | See [Corporate networks](#corporate-networks-tls-inspection-and-private-mirrors). |
| A service won't start | `docker compose ps`, then `docker compose logs <service>`. A "Set X in .env" error means a secret is missing. |
| Run stays *queued* | `docker compose logs --tail=50 authrecon-worker`. The worker must log `Listening on runs`. Then `docker compose up -d authrecon-worker`. |
| Run fails | Open the run page. The failure card and the timeline (filter by *error*) show where it stopped, and the screenshots show what the browser saw. |
| Target unreachable | The worker resolves names from inside Docker; for a host on the Docker host use `host.docker.internal`. |
| `.side` fails in WAS | Click **Verify** on the run page. It replays the script in a clean browser and reports the step that broke. |
| Run keeps failing with stale selectors | Clear that domain's playbooks (see [Playbooks](#playbooks)). |
| UI loads but API calls fail | The `VITE_*` URLs in `.env` and `ALLOWED_ORIGINS` must match the address you're browsing; rebuild the frontend after changing them. |
| CLI says "API access not enabled" | An admin must allow your user under **Settings › AI & MCP › Who can create keys**. |

Logs: `docker compose logs -f portal authrecon-api authrecon-worker authrecon-mcp`.
