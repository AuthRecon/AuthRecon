"""Which URLs AuthRecon may visit as a run target (SSRF guard).

AuthRecon fetches, renders and screenshots whatever target it is given, from
inside the Docker network that also holds its database, Redis and services.
Without a guard, any user could point a run at:
- cloud metadata (169.254.169.254 and friends), which hands out cloud credentials;
- AuthRecon's own services (postgres, redis, portal, the API) by name or IP;
- the Docker host (host.docker.internal) and loopback.

Private ranges (10/8, 172.16/12, 192.168/16) stay allowed by default: scanning
internal applications is the main use case. Admins can tighten or loosen this
with environment variables on authrecon-api and authrecon-worker:

  TARGET_ALLOW          comma-separated hostnames or CIDRs always allowed
                        (e.g. host.docker.internal, 10.20.0.0/16)
  TARGET_DENY           comma-separated hostnames or CIDRs always refused
  TARGET_BLOCK_PRIVATE  "true" to also refuse private (RFC 1918 / ULA) addresses
"""
from __future__ import annotations

import ipaddress
import os
import socket
from functools import lru_cache
from urllib.parse import urlsplit

# AuthRecon's own services (docker-compose service names).
INTERNAL_HOSTS = frozenset({
    "postgres", "redis", "authrecon-redis", "portal", "authrecon-api", "authrecon-worker",
    "authrecon-mcp", "frontend", "localhost", "localhost.localdomain", "host.docker.internal",
    "gateway.docker.internal", "metadata", "metadata.google.internal",
})
# Practice targets inside the stack, allowed by name (they are profile-gated and loopback-bound).
TEST_HOSTS = frozenset({"loginlab"})
METADATA_IPS = frozenset({
    ipaddress.ip_address("169.254.169.254"), ipaddress.ip_address("169.254.170.2"),
    ipaddress.ip_address("100.100.100.200"), ipaddress.ip_address("fd00:ec2::254"),
})


class TargetBlocked(ValueError):
    """The URL is not an allowed run target (message is shown to the user)."""


def _split(env: str) -> tuple[set[str], list[ipaddress._BaseNetwork]]:
    hosts: set[str] = set()
    nets: list[ipaddress._BaseNetwork] = []
    for item in (os.getenv(env) or "").split(","):
        item = item.strip().lower()
        if not item:
            continue
        try:
            nets.append(ipaddress.ip_network(item, strict=False))
        except ValueError:
            hosts.add(item.rstrip("."))
    return hosts, nets


@lru_cache(maxsize=1)
def own_networks() -> tuple[ipaddress._BaseNetwork, ...]:
    """IPv4 networks this container is attached to (its Docker networks), from
    the kernel routing table. Targets inside them are AuthRecon's own services."""
    nets = []
    try:
        with open("/proc/net/route") as fh:
            next(fh, None)
            for line in fh:
                fields = line.split()
                if len(fields) < 8 or fields[1] == "00000000":
                    continue
                dest = socket.inet_ntoa(int(fields[1], 16).to_bytes(4, "little"))
                mask = socket.inet_ntoa(int(fields[7], 16).to_bytes(4, "little"))
                nets.append(ipaddress.ip_network(f"{dest}/{mask}", strict=False))
    except (OSError, ValueError):
        pass
    return tuple(nets)


def _resolve(host: str) -> list[ipaddress._BaseAddress]:
    try:
        return [ipaddress.ip_address(host)]
    except ValueError:
        pass
    try:
        infos = socket.getaddrinfo(host, None)
    except OSError:
        return []  # unresolvable: the visit simply fails later
    out = []
    for info in infos:
        try:
            out.append(ipaddress.ip_address(info[4][0].split("%", 1)[0]))
        except ValueError:
            continue
    return out


def check_host(host: str, *, resolve: bool = True) -> None:
    """Raise TargetBlocked if ``host`` may not be visited."""
    host = (host or "").strip().lower().rstrip(".").strip("[]")
    if not host:
        raise TargetBlocked("The target URL has no host.")
    allow_hosts, allow_nets = _split("TARGET_ALLOW")
    deny_hosts, deny_nets = _split("TARGET_DENY")
    if host in allow_hosts:
        return
    if host in deny_hosts:
        raise TargetBlocked(f"{host} is on this server's deny list (TARGET_DENY).")
    if host in TEST_HOSTS:
        return
    if host in INTERNAL_HOSTS:
        raise TargetBlocked(
            f"{host} is part of AuthRecon or the Docker host, not a target. "
            "An admin can allow it with TARGET_ALLOW (see ADMIN_GUIDE.md).")
    if resolve:
        addresses = _resolve(host)
    else:  # literal IPs only (fast path for per-request browser checks)
        try:
            addresses = [ipaddress.ip_address(host)]
        except ValueError:
            return
    block_private = (os.getenv("TARGET_BLOCK_PRIVATE") or "").strip().lower() in ("1", "true", "yes")
    for ip in addresses:
        if any(ip in net for net in allow_nets):
            continue
        if any(ip in net for net in deny_nets):
            raise TargetBlocked(f"{host} ({ip}) is on this server's deny list (TARGET_DENY).")
        if ip in METADATA_IPS:
            raise TargetBlocked(f"{host} ({ip}) is a cloud metadata address.")
        if ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_unspecified or ip.is_reserved:
            raise TargetBlocked(f"{host} ({ip}) is a loopback, link-local or reserved address.")
        if ip.version == 4 and any(ip in net for net in own_networks()):
            raise TargetBlocked(
                f"{host} ({ip}) is on AuthRecon's internal Docker network. "
                "An admin can allow it with TARGET_ALLOW (see ADMIN_GUIDE.md).")
        if block_private and ip.is_private:
            raise TargetBlocked(f"{host} ({ip}) is a private address and TARGET_BLOCK_PRIVATE is on.")


def check_target(url: str, *, resolve: bool = True) -> None:
    """Raise TargetBlocked if ``url`` may not be used as (or redirect to) a target."""
    parts = urlsplit((url or "").strip())
    if parts.scheme not in ("http", "https"):
        raise TargetBlocked("Only http:// and https:// targets are allowed.")
    check_host(parts.hostname or "", resolve=resolve)


def is_allowed(url: str, *, resolve: bool = True) -> bool:
    try:
        check_target(url, resolve=resolve)
        return True
    except TargetBlocked:
        return False


# URL patterns for the browser's own request blocking (Selenium CDP
# Network.setBlockedURLs): names and literal IPs only, so they work for every
# request a page makes, including ones its scripts start.
BROWSER_BLOCK_PATTERNS = tuple(
    [f"*://{h}/*" for h in sorted(INTERNAL_HOSTS)]
    + [f"*://{h}:*" for h in sorted(INTERNAL_HOSTS)]
    + [f"*://{ip}/*" for ip in ("169.254.169.254", "169.254.170.2", "100.100.100.200", "[fd00:ec2::254]")]
    + [f"*://{ip}:*" for ip in ("169.254.169.254", "169.254.170.2", "100.100.100.200")]
    + ["*://127.*", "*://[::1]*", "*://0.0.0.0*"]
)
