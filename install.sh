#!/usr/bin/env bash
#
# AuthRecon installer
#
# Usage:
#   ./install.sh        # as a user in the docker group
#   sudo ./install.sh   # otherwise
#   FORCE_REINSTALL=1 ./install.sh   # over an existing install (see ADMIN_GUIDE.md)
#
# Requirements: Docker 20.10+ with Compose v2, python3, openssl, curl.
#

set -euo pipefail

# =============================================================================
# CONFIGURATION
# =============================================================================

VERSION="$(cat "$(dirname "${BASH_SOURCE[0]}")/VERSION" 2>/dev/null || echo unknown)"
MIN_DOCKER_VERSION="20.10"
MIN_COMPOSE_VERSION="2.0"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Directories
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="${SCRIPT_DIR}/backend"
DATA_DIR="${SCRIPT_DIR}/data"

# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_header() {
    echo ""
    echo "AuthRecon installer (version ${VERSION})"
    echo "========================================"
    echo ""
}

print_success_banner() {
    echo ""
    echo "AuthRecon is installed and healthy."
    echo "==================================="
    echo ""
}

# Check if running as root
check_root() {
    # Root is only needed for Docker access. A user in the docker group can
    # run the installer directly (and then owns the generated .env files).
    if [[ $EUID -ne 0 ]] && ! docker info >/dev/null 2>&1; then
        log_error "Cannot talk to Docker as $(id -un). Run with sudo, or add this user to the docker group."
        exit 1
    fi
}

# Generated secret files are chmod 600. Under sudo, give them back to the
# invoking user so later `docker compose ...` commands (run without sudo) can
# still read them.
own_generated_file() {
    if [[ $EUID -eq 0 && -n "${SUDO_USER:-}" ]]; then
        chown "${SUDO_USER}" "$1"
    fi
}

# Version comparison helper: is $1 >= $2? Plain bash (macOS ships bash 3.2
# and BSD sort, so no `sort -V`). Compares up to three numeric parts.
version_ge() {
    local IFS=.
    local -a have=($1) want=($2)
    local i
    for i in 0 1 2; do
        local h="${have[i]:-0}" w="${want[i]:-0}"
        h="${h%%[!0-9]*}"; w="${w%%[!0-9]*}"
        (( 10#${h:-0} > 10#${w:-0} )) && return 0
        (( 10#${h:-0} < 10#${w:-0} )) && return 1
    done
    return 0
}

# First x.y.z in a string (portable: no `grep -P`, which macOS lacks).
first_version() {
    sed -nE 's/[^0-9]*([0-9]+\.[0-9]+(\.[0-9]+)?).*/\1/p' | head -1
}

# =============================================================================
# PREREQUISITE CHECKS
# =============================================================================

check_prerequisites() {
    log_info "Checking prerequisites..."

    local errors=0

    # Check Docker
    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed"
        errors=$((errors + 1))
    else
        local docker_version
        docker_version=$(docker --version | first_version)
        if [[ -n "${docker_version}" ]] && version_ge "${docker_version}" "${MIN_DOCKER_VERSION}"; then
            log_success "Docker installed (version ${docker_version})"
        else
            log_error "Docker version ${docker_version} is too old (minimum: ${MIN_DOCKER_VERSION})"
            errors=$((errors + 1))
        fi
    fi

    # Check Docker Compose
    if ! docker compose version &> /dev/null; then
        log_error "Docker Compose V2 is not installed"
        log_info "Install with: sudo apt install docker-compose-plugin (Ubuntu/Debian)"
        log_info "Or: sudo yum install docker-compose-plugin (RHEL/CentOS)"
        log_info "macOS/Windows: Docker Desktop includes it"
        errors=$((errors + 1))
    else
        local compose_version
        compose_version=$(docker compose version --short 2>/dev/null | first_version)
        if [[ -n "${compose_version}" ]] && version_ge "${compose_version}" "${MIN_COMPOSE_VERSION}"; then
            log_success "Docker Compose installed (version ${compose_version})"
        else
            log_error "Docker Compose version ${compose_version} is too old (minimum: ${MIN_COMPOSE_VERSION})"
            errors=$((errors + 1))
        fi
    fi

    # Check required ports (externally published only)
    # VNC ports 5900/6080/6081+ are internal Docker network only — not checked here
    # A missing lsof must not make every port look free, so fall back to ss
    # and say so when neither tool exists.
    local required_ports=(9000 5173 8001)
    local port_tool=""
    if command -v ss &> /dev/null; then port_tool="ss"
    elif command -v lsof &> /dev/null; then port_tool="lsof"
    fi
    for port in "${required_ports[@]}"; do
        local in_use=0
        if [[ "${port_tool}" == "ss" ]]; then
            ss -Htln "sport = :${port}" 2>/dev/null | grep -q . && in_use=1
        elif [[ "${port_tool}" == "lsof" ]]; then
            lsof -Pi :${port} -sTCP:LISTEN -t >/dev/null 2>&1 && in_use=1
        else
            log_warning "Cannot check port ${port} (neither ss nor lsof is installed)"
            continue
        fi
        if [[ ${in_use} -eq 1 ]]; then
            log_warning "Port ${port} is already in use"
            errors=$((errors + 1))
        else
            log_success "Port ${port} available"
        fi
    done

    log_info "VNC access is proxied through the portal (port 9000) — no direct VNC ports exposed"

    # Check disk space (minimum 10GB free). `df -Pk` is the same on Linux and macOS.
    # (Docker Desktop keeps images in its own VM disk; this checks the host.)
    local available_space
    available_space=$(df -Pk "${SCRIPT_DIR}" | awk 'NR==2 {print int($4 / 1048576)}')
    if [[ -z "${available_space}" ]]; then
        log_warning "Could not check free disk space"
    elif [[ ${available_space} -lt 10 ]]; then
        log_warning "Low disk space: ${available_space}GB available (10GB+ recommended)"
    else
        log_success "Disk space: ${available_space}GB available"
    fi

    if [[ ${errors} -gt 0 ]]; then
        log_error "Prerequisites check failed with ${errors} error(s)"
        exit 1
    fi
}

# =============================================================================
# USER INPUT
# =============================================================================

gather_inputs() {
    log_info "Gathering deployment configuration..."
    echo ""

    # Deployment URL
    read -p "Enter deployment URL (e.g., https://sec.example.com or http://localhost:5173): " DEPLOYMENT_URL
    DEPLOYMENT_URL=${DEPLOYMENT_URL:-http://localhost:5173}

    # Normalize deployment URL - add http:// if missing
    if [[ ! "${DEPLOYMENT_URL}" =~ ^https?:// ]]; then
        DEPLOYMENT_URL="http://${DEPLOYMENT_URL}"
    fi

    log_success "Deployment URL: ${DEPLOYMENT_URL}"
}

# =============================================================================
# EXISTING INSTALL GUARD
# =============================================================================

# Re-running this script regenerates every secret with fresh random values, but
# an already-initialized Postgres volume keeps the OLD passwords (the init script
# only runs once, on first volume creation). Overwriting .env without
# also rotating the live database would silently break every service's DB and
# inter-service auth. Refuse to proceed over an existing install unless the
# operator explicitly opts in via FORCE_REINSTALL=1.
check_existing_install() {
    local found_env=0
    for f in "${SCRIPT_DIR}/.env" "${SCRIPT_DIR}/.env.docker" "${SCRIPT_DIR}/.env.secrets"; do
        [[ -f "$f" ]] && found_env=1
    done
    local found_volume=0
    # Only this checkout's volume (compose prefixes volumes with the project
    # name, which defaults to the directory name), not other installs.
    local project="${COMPOSE_PROJECT_NAME:-$(basename "${SCRIPT_DIR}")}"
    project="$(echo "${project}" | tr '[:upper:]' '[:lower:]' | tr -cd 'a-z0-9_-')"
    if docker volume ls --format '{{.Name}}' 2>/dev/null | grep -qx "${project}_authrecon_db"; then
        found_volume=1
    fi

    if [[ ${found_env} -eq 1 || ${found_volume} -eq 1 ]]; then
        log_warning "An existing deployment was detected (env file and/or authrecon_db volume already present)."
        log_warning "Re-running this installer generates BRAND NEW random secrets, but the existing"
        log_warning "Postgres volume still has the OLD passwords baked in — every service would fail"
        log_warning "to authenticate until the database passwords are rotated to match."
        if [[ "${FORCE_REINSTALL:-0}" != "1" ]]; then
            log_error "Refusing to overwrite an existing install."
            log_info "To add a fresh deployment anyway, remove the old .env/.env.secrets"
            log_info "files and the authrecon_db volume first, or re-run with FORCE_REINSTALL=1 if you"
            log_info "understand this will require rotating the live database passwords yourself."
            exit 1
        fi
        log_warning "FORCE_REINSTALL=1 set — proceeding anyway. You are responsible for rotating the"
        log_warning "live database passwords to match the new .env after this script finishes."
    fi
}

# =============================================================================
# SECRETS GENERATION
# =============================================================================

generate_secrets() {
    log_info "[1/7] Generating secrets..."

    # Generate Fernet key for portal credential encryption.
    # Uses only the Python standard library — no host-side cryptography package needed.
    # The output is a URL-safe base64-encoded 32-byte key, which is a valid Fernet key.
    local fernet_key
    fernet_key=$(python3 -c "import os, base64; print(base64.urlsafe_b64encode(os.urandom(32)).decode())")

    # Generate secrets file
    cat > "${SCRIPT_DIR}/.env.secrets" <<EOF
# Auto-generated secrets - $(date -u +"%Y-%m-%d %H:%M:%S UTC")
# BACKUP THIS FILE! Store in a secure location (password manager, Vault, etc.)
# Never commit this file to version control.

PORTAL_API_SECRET=$(openssl rand -hex 32)
PORTAL_SECRET_KEY=$(openssl rand -hex 32)
PORTAL_ENCRYPTION_KEY=${fernet_key}
AUTHRECON_SECRET_KEY=$(openssl rand -hex 32)
AUTHRECON_JWT_SECRET=$(openssl rand -hex 32)
POSTGRES_SUPERUSER_PASSWORD=$(openssl rand -hex 16)
PORTAL_DB_PASSWORD=$(openssl rand -hex 16)
AUTHRECON_DB_PASSWORD=$(openssl rand -hex 16)
REDIS_PASSWORD=$(openssl rand -hex 32)
LOGINLAB_SERVICE_TOKEN=$(openssl rand -hex 32)
EOF

    chmod 600 "${SCRIPT_DIR}/.env.secrets"
    own_generated_file "${SCRIPT_DIR}/.env.secrets"

    # Source secrets for use
    # shellcheck disable=SC1091
    source "${SCRIPT_DIR}/.env.secrets"

    log_success "Secrets generated → .env.secrets"
    log_warning "IMPORTANT: Backup .env.secrets to secure location!"
}

# =============================================================================
# CONFIGURATION FILES
# =============================================================================

create_env_files() {
    log_info "[2/7] Creating configuration files..."

    # Frontend .env
    # Extract base URL and construct proper API endpoints
    # Strip protocol and host, removing any existing port
    PROTO="${DEPLOYMENT_URL%%://*}"      # http or https
    HOST_WITH_PORT="${DEPLOYMENT_URL#*://}"  # e.g. 192.168.1.100 or 192.168.1.100:port
    HOST="${HOST_WITH_PORT%%:*}"         # e.g. 192.168.1.100 (strip port if present)
    BASE_URL="${PROTO}://${HOST}"        # e.g. http://192.168.1.100

    if [[ "${PROTO}" == "https" ]]; then WS_PROTO="wss"; else WS_PROTO="ws"; fi

    # Root .env: read by Docker Compose for variable substitution. The VITE_*
    # values are browser-facing URLs baked into the frontend build; the rest
    # are secrets that compose hands only to the services that need them.
    cat > "${SCRIPT_DIR}/.env" <<EOF
# Frontend build (public URLs, not secrets)
VITE_API_URL=${BASE_URL}:9000
VITE_PORTAL_API=${BASE_URL}:9000
VITE_AUTHRECON_API=${BASE_URL}:9000/apps/authrecon/api/v1
VITE_WS_URL=${WS_PROTO}://${HOST}:9000/ws

# Backend database credentials
POSTGRES_SUPERUSER_USER=postgres
POSTGRES_SUPERUSER_PASSWORD=${POSTGRES_SUPERUSER_PASSWORD}
PORTAL_DB_USER=portal
PORTAL_DB_PASSWORD=${PORTAL_DB_PASSWORD}
AUTHRECON_DB_USER=authrecon
AUTHRECON_DB_PASSWORD=${AUTHRECON_DB_PASSWORD}
REDIS_PASSWORD=${REDIS_PASSWORD}
PORTAL_API_SECRET=${PORTAL_API_SECRET}
LOGINLAB_SERVICE_TOKEN=${LOGINLAB_SERVICE_TOKEN}
EOF
    chmod 600 "${SCRIPT_DIR}/.env"
    own_generated_file "${SCRIPT_DIR}/.env"
    log_success ".env created (compose settings)"

    # Portal .env
    cat > "${BACKEND_DIR}/security-portal/.env" <<EOF
# Portal configuration
PORTAL_DATABASE_URL=postgresql+psycopg2://portal:${PORTAL_DB_PASSWORD}@postgres:5432/portal
PORTAL_API_SECRET=${PORTAL_API_SECRET}
PORTAL_SECRET_KEY=${PORTAL_SECRET_KEY}

# Encryption key for credential vault (never stored on disk — env var only)
PORTAL_ENCRYPTION_KEY=${PORTAL_ENCRYPTION_KEY}

# CORS — comma-separated list of allowed frontend origins
ALLOWED_ORIGINS=${BASE_URL}:5173

# Logging
PORTAL_LOG_PATH=/app/logs/portal.log

# Deployment label shown in the UI (change to suit your environment)
PORTAL_ENV_LABEL=Production

# Optional: session idle timeout in minutes (0 = disabled)
# Recommended: 60 for most environments, 30 for high-security deployments
# PORTAL_SESSION_IDLE_TIMEOUT=60
EOF
    chmod 600 "${BACKEND_DIR}/security-portal/.env"
    own_generated_file "${BACKEND_DIR}/security-portal/.env"
    log_success "${BACKEND_DIR}/security-portal/.env created"

    # AuthRecon .env
    cat > "${BACKEND_DIR}/authrecon/backend/.env" <<EOF
# AuthRecon configuration
DATABASE_URL=postgresql+psycopg2://authrecon:${AUTHRECON_DB_PASSWORD}@postgres:5432/authrecon
REDIS_URL=redis://:${REDIS_PASSWORD}@authrecon-redis:6379/0
SECRET_KEY=${AUTHRECON_SECRET_KEY}
JWT_SECRET_KEY=${AUTHRECON_JWT_SECRET}
PORTAL_API_SECRET=${PORTAL_API_SECRET}
PORTAL_SERVICE_ID=auth_recon
PORTAL_SERVICE_URL=http://portal:9000
ALLOWED_ORIGINS=["${BASE_URL}:5173"]
ENABLE_PLAYWRIGHT_HAR=true
ARTIFACTS_DIR=/app/data/artifacts
EOF
    chmod 600 "${BACKEND_DIR}/authrecon/backend/.env"
    own_generated_file "${BACKEND_DIR}/authrecon/backend/.env"
    log_success "${BACKEND_DIR}/authrecon/backend/.env created"

    log_success "CORS configured for ${DEPLOYMENT_URL}"
}

# =============================================================================
# DATABASE INITIALIZATION
# =============================================================================

start_database() {
    log_info "[3/7] Starting PostgreSQL..."

    # Start only Postgres first
    docker compose up -d postgres

    # Wait for Postgres to be ready
    log_info "Waiting for PostgreSQL to initialize (may take 30-60 seconds)..."
    local retries=0
    local max_retries=60

    while [[ ${retries} -lt ${max_retries} ]]; do
        if docker compose exec -T postgres pg_isready -U postgres > /dev/null 2>&1; then
            log_success "PostgreSQL ready (portal + authrecon databases created)"
            return 0
        fi
        sleep 1
        retries=$((retries + 1))
    done

    log_error "PostgreSQL failed to start within 60 seconds"
    docker compose logs postgres
    exit 1
}

# =============================================================================
# MIGRATIONS
# =============================================================================

run_migrations() {
    log_info "[4/7] Running database migrations..."

    # Start Redis and the worker (worker runs alembic on startup)
    docker compose up -d authrecon-redis authrecon-worker

    # Wait for the worker to finish migrations and enter the listening state
    log_info "Waiting for migrations to apply (up to 60 seconds)..."
    local retries=0
    local max_retries=60
    while [[ ${retries} -lt ${max_retries} ]]; do
        if docker compose logs authrecon-worker 2>/dev/null | grep -q "Listening on runs"; then
            log_success "AuthRecon migrations applied — worker is listening"
            break
        fi
        sleep 1
        retries=$((retries + 1))
    done
    if [[ ${retries} -ge ${max_retries} ]]; then
        log_warning "Worker did not reach listening state within 60s — check: docker compose logs authrecon-worker"
    fi
}

# =============================================================================
# SERVICE STARTUP
# =============================================================================

start_services() {
    log_info "[5/7] Starting all services..."

    docker compose up -d

    log_success "Containers started (the portal creates its schema on first start)"
}

# =============================================================================
# HEALTH CHECKS
# =============================================================================

# Services take a few seconds to start after `up -d`: poll before judging.
wait_for_url() {
    local url="$1" tries="${2:-45}"
    for ((i = 0; i < tries; i++)); do
        curl -sf "${url}" > /dev/null 2>&1 && return 0
        sleep 2
    done
    return 1
}

run_health_checks() {
    log_info "[6/7] Running health checks (waiting up to 90s for services to start)..."

    local errors=0

    # Portal health
    if wait_for_url http://localhost:9000/healthz; then
        log_success "Portal API: healthy (database schema ready)"
    else
        log_error "Portal API: unhealthy"
        errors=$((errors + 1))
    fi

    # AuthRecon health (published on host port 8001 per docker-compose.yml)
    if wait_for_url http://localhost:8001/health/ready; then
        log_success "AuthRecon API: healthy"
    else
        log_error "AuthRecon API: unhealthy (port 8001)"
        errors=$((errors + 1))
    fi

    # Database health
    if docker compose exec -T postgres pg_isready -U postgres > /dev/null 2>&1; then
        log_success "PostgreSQL: healthy"
    else
        log_error "PostgreSQL: unhealthy"
        errors=$((errors + 1))
    fi

    # Redis health
    if docker compose exec -T authrecon-redis redis-cli -a "${REDIS_PASSWORD}" PING > /dev/null 2>&1; then
        log_success "Redis: healthy"
    else
        log_warning "Redis: check may have failed"
    fi

    HEALTH_ERRORS=${errors}
    if [[ ${errors} -gt 0 ]]; then
        log_error "Some health checks failed - check logs: docker compose logs"
    fi
}

# =============================================================================
# FINAL OUTPUT
# =============================================================================

print_final_info() {
    log_success "[7/7] Deployment complete!"

    print_success_banner

    echo "Access AuthRecon at:"
    echo "  Web UI:          ${DEPLOYMENT_URL}"
    echo "  Portal API:      ${BASE_URL}:9000"
    echo "  AuthRecon API:   ${BASE_URL}:8001"
    echo "  VNC access:      Proxied through the portal (no direct VNC ports exposed)"
    echo ""
    echo "First-time setup:"
    echo "  Visit ${DEPLOYMENT_URL} and navigate to /setup to create your admin account"
    echo "  Password policy: minimum 12 characters, must include uppercase, number, and special character"
    echo ""
    echo "Important files:"
    echo "  Secrets backup:  ${SCRIPT_DIR}/.env.secrets  <-- BACK THIS UP NOW"
    echo "  Portal config:   ${BACKEND_DIR}/security-portal/.env"
    echo "  AuthRecon config:${BACKEND_DIR}/authrecon/backend/.env"
    echo ""
    echo "Optional configuration (edit ${BACKEND_DIR}/security-portal/.env):"
    echo "  PORTAL_SESSION_IDLE_TIMEOUT=60   # Session idle timeout in minutes (currently disabled)"
    echo ""
    echo "Next steps:"
    echo "  1. Create admin account at ${DEPLOYMENT_URL}/setup"
    echo "  2. BACK UP .env.secrets to a secure location (password manager, Vault, etc.)"
    echo "  3. Firewall port 8001 (direct API, skips the portal) to hosts that need CLI access"
    echo "  4. For HTTPS: set the VITE_* URLs in .env and ALLOWED_ORIGINS in both service .env"
    echo "     files, then: docker compose up -d --build frontend && docker compose up -d"
    echo "  5. Back up the authrecon_db, authrecon_artifacts and portal-data volumes"
    echo "  See ADMIN_GUIDE.md for each of these."
    echo ""
    echo "Useful commands:"
    echo "  View logs:       docker compose logs -f"
    echo "  Stop:            docker compose down"
    echo "  Apply .env edits: docker compose up -d   (restart does not reload .env)"
    echo "  Status:          docker compose ps"
    echo "  WARNING:         Never run 'docker compose down -v' -- destroys all data"
    echo ""
}

# =============================================================================
# MAIN INSTALLATION FLOW
# =============================================================================

main() {
    # docker compose resolves docker-compose.yml from the current directory.
    cd "${SCRIPT_DIR}"
    print_header

    check_root
    check_prerequisites
    check_existing_install

    # Interactive mode (default)
    gather_inputs

    # Installation steps
    generate_secrets
    create_env_files
    start_database
    run_migrations
    start_services
    run_health_checks
    if [[ ${HEALTH_ERRORS:-0} -gt 0 ]]; then
        log_error "Installation finished, but the stack is not healthy. Fix the errors above, then: docker compose up -d"
        exit 1
    fi
    print_final_info
}

# Run installation
main "$@"
