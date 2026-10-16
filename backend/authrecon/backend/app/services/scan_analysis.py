"""Tenable WAS scan-export analysis: what went wrong with a scan, and which
settings to change before the next one.

Deterministic rules over the scan's own diagnostic plugins (authentication,
logout, timeouts, WAF), the sitemap's per-URL "not queued / not audited"
reasons, and plugin telemetry. No AI.

The export layout is read tolerantly: findings are found by plugin ID in any
JSON, CSV or XML file in the zip, and attachment tables (sitemap, plugins.csv)
are recognised by their content, not their file names.

The analysis is shown in the UI and handed to MCP clients, so it never contains
raw plugin output (which can hold session tokens or page content): only plugin
IDs and names, counts, URL paths without query strings, and setting changes.
"""
from __future__ import annotations

import csv
import io
import json
import re
import xml.etree.ElementTree as ET
import zipfile
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Iterable
from urllib.parse import urlsplit

ANALYZER_VERSION = 1
MAX_MEMBER_BYTES = 64 * 1024 * 1024
MAX_READ_BYTES = 400 * 1024 * 1024
MAX_FINDINGS = 200_000

# --- WAS plugins the rules use (tenable.com/plugins/was/<id>) ---------------------------
AUTH_FAILED = {
    98142: "Selenium Authentication Failed", 98034: "Login Form Authentication Failed",
    98026: "HTTP Server Authentication Failed", 98140: "Cookie Authentication Failed",
    113013: "Bearer Token Authentication Failed", 113011: "API Key Authentication Failed",
    115203: "OAuth 2.0 Authentication Failed", 113225: "Kerberos Authentication Failed",
    113330: "Client Certificate Authentication Failed",
}
AUTH_OK = {
    98141: "Selenium Authentication Succeeded", 98035: "Login Form Authentication Succeeded",
    98025: "HTTP Server Authentication Succeeded", 98139: "Cookie Authentication Succeeded",
    113012: "Bearer Token Authentication Succeeded", 113010: "API Key Authentication Succeeded",
    115202: "OAuth 2.0 Authentication Succeeded", 113224: "Kerberos Authentication Succeeded",
    113329: "Client Certificate Authentication Succeeded",
}
P_SCAN_INFO, P_SITEMAP, P_TIMEOUT, P_TIMEOUT_ABORT = 98000, 98009, 98019, 98137
P_LOGOUT_ABORT, P_LOGOUT_INTERMITTENT, P_PATTERN_UNAUTH = 98044, 98043, 114247
P_WAF, P_EXCLUDED, P_EXTERNAL_URLS, P_EXTERNAL_API = 98008, 98007, 98154, 114128
P_API_DETECTED, P_XHR = 112616, 98772
P_OPENAPI_OK, P_OPENAPI_FAIL, P_GRAPHQL_FAIL, P_WSDL_FAIL = 112569, 112570, 114776, 114930
P_SELENIUM_CRAWL_FAIL = 98145
P_PLUGIN_TELEMETRY, P_PERF_TELEMETRY = 114543, 113393
KNOWN_NAMES = {
    **AUTH_FAILED, **AUTH_OK, P_SCAN_INFO: "Scan Information", P_SITEMAP: "Web Application Sitemap",
    P_TIMEOUT: "Network Timeout Encountered", P_TIMEOUT_ABORT: "Scan aborted after too many timeouts",
    P_LOGOUT_ABORT: "Scan Aborted After Being Logged Out", P_LOGOUT_INTERMITTENT: "Scan Logged-out Intermittently",
    P_PATTERN_UNAUTH: "Authentication Check Pattern Found in Unauthenticated Browser",
    P_WAF: "Web Application Firewall Detected", P_EXCLUDED: "URI Blocked Due to Exclusion Rule",
    P_EXTERNAL_URLS: "External URLs", P_EXTERNAL_API: "External Backend API Detected",
    P_API_DETECTED: "API Detected", P_XHR: "Fetch/XHR Detected", P_OPENAPI_OK: "OpenAPI Import Success",
    P_OPENAPI_FAIL: "OpenAPI Import Failed", P_GRAPHQL_FAIL: "GraphQL Import Failed",
    P_WSDL_FAIL: "WSDL Import Failed", P_SELENIUM_CRAWL_FAIL: "Selenium Crawl Failed",
    P_PLUGIN_TELEMETRY: "Plugin Telemetry", P_PERF_TELEMETRY: "Performance Telemetry",
}

# Sitemap (98009) reasons: why a URL was not queued for audit / not audited.
NOT_QUEUED = ("not_in_domain", "scope_configuration", "directory_depth", "exclude_file_extension",
              "exclude_path_patterns", "redundant_path", "request_redirect_limit", "queue_full")
NOT_AUDITED = ("timeout", "filesize_exceeded", "scan_timelimit_reached", "user_abort")
REASONS = NOT_QUEUED + NOT_AUDITED
_REASON_RE = re.compile(r"\b(" + "|".join(REASONS) + r")\b")
_URL_RE = re.compile(r"https?://[^\s\"'<>,;|]+")
_LOGOUT_RE = re.compile(r"log[\s_-]?out|sign[\s_-]?out|log[\s_-]?off|sign[\s_-]?off|end[\s_-]?session|session/(end|destroy)",
                        re.I)

PLUGIN_ID_KEYS = ("plugin_id", "pluginid", "plugin id", "pluginID", "plugin")
URL_KEYS = ("uri", "url", "request_url", "request url", "path", "asset", "asset_url", "location")
NAME_KEYS = ("plugin_name", "plugin name", "name", "title", "synopsis")
OUTPUT_KEYS = ("output", "plugin_output", "plugin output", "details", "proof", "evidence")
SEVERITY_KEYS = ("severity", "risk", "risk_factor", "risk factor")


@dataclass
class Finding:
    plugin_id: int
    name: str = ""
    uri: str | None = None
    output: str = ""
    severity: str | None = None


@dataclass
class ExportContent:
    findings: list[Finding] = field(default_factory=list)
    tables: list[list[dict[str, str]]] = field(default_factory=list)
    texts: list[str] = field(default_factory=list)  # free text (plugin outputs, txt files), for reason scans
    log_texts: list[str] = field(default_factory=list)  # debug logs: error types only, never lines
    har_entries: list[dict] = field(default_factory=list)
    current: dict[str, Any] = field(default_factory=dict)  # the scan's own settings (JSON export)
    read_files: list[str] = field(default_factory=list)
    skipped_files: list[str] = field(default_factory=list)


# The scan's current settings, when a JSON export includes them. Names vary by
# export version, so several spellings map to one WAS setting. Anything
# credential-like is never read.
SETTING_KEYS = {
    "Regex for Excluded URLs": ("exclude_path_patterns", "excluded_urls", "exclusion_regex", "exclude_urls"),
    "File Extensions to Exclude": ("exclude_file_extensions", "excluded_file_extensions"),
    "Max Number of HTTP Requests Per Second": ("request_max_rate", "max_requests_per_second", "requests_per_second",
                                               "max_rps", "max_request_rate"),
    "Max Number of Concurrent HTTP Connections": ("request_concurrency", "max_concurrent_connections",
                                                  "concurrent_connections", "max_concurrent_requests"),
    "Network Timeout (In Seconds)": ("request_timeout", "network_timeout"),
    "Timeout Threshold": ("timeout_threshold", "max_timeouts", "timeouts_threshold"),
    "Target Scan Max Time (HH:MM:SS)": ("scan_timeout", "max_scan_time", "timeout"),
    "Number of URLS to Crawl and Browse": ("max_spider_urls", "max_urls", "url_limit", "crawl_url_limit",
                                           "max_crawl_urls"),
    "Path Directory Depth": ("max_url_depth", "path_depth", "directory_depth", "max_path_depth"),
    "Request Redirect Limit": ("max_redirects", "redirect_limit", "request_redirect_limit"),
    "Max Response Size": ("max_response_size", "response_max_size"),
}
_SECRETISH = re.compile(r"pass|secret|token|cookie|credential|key|auth", re.I)
_SELENIUM_ERRORS = re.compile(
    r"\b(NoSuchElementException|ElementNotInteractableException|ElementClickInterceptedException|"
    r"StaleElementReferenceException|TimeoutException|InvalidSelectorException|NoSuchFrameException|"
    r"UnexpectedAlertPresentException|WebDriverException|element not found|element is not visible|"
    r"Unable to locate element|net::ERR_[A-Z_]+)\b")


# --- reading ------------------------------------------------------------------------

def _norm(key: str) -> str:
    return re.sub(r"[\s_-]+", "_", str(key).strip().lower())


def _pick(d: dict, keys: Iterable[str]) -> Any:
    lowered = {_norm(k): v for k, v in d.items()}
    for key in keys:
        if _norm(key) in lowered and lowered[_norm(key)] not in (None, ""):
            return lowered[_norm(key)]
    return None


def _plugin_id(value: Any) -> int | None:
    if isinstance(value, dict):
        value = _pick(value, ("id", "plugin_id"))
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return number if 98000 <= number <= 98999 or 112000 <= number <= 119999 else None


def _finding_from(d: dict) -> Finding | None:
    pid = _plugin_id(_pick(d, PLUGIN_ID_KEYS))
    if pid is None:
        return None
    plugin = d.get("plugin") if isinstance(d.get("plugin"), dict) else {}
    name = _pick(d, NAME_KEYS) or _pick(plugin, NAME_KEYS) or KNOWN_NAMES.get(pid, "")
    uri = _pick(d, URL_KEYS)
    output = _pick(d, OUTPUT_KEYS)
    severity = _pick(d, SEVERITY_KEYS) or _pick(plugin, SEVERITY_KEYS)
    return Finding(pid, str(name)[:200], str(uri)[:2000] if uri else None,
                   output if isinstance(output, str) else json.dumps(output)[:200000] if output else "",
                   str(severity).lower() if severity else None)


def _collect_settings(node: dict, content: ExportContent) -> None:
    for key, value in node.items():
        k = _norm(key)
        if _SECRETISH.search(k) and k not in ("timeout",):
            continue
        for setting, names in SETTING_KEYS.items():
            if k in names and setting not in content.current:
                if isinstance(value, (int, float, str)) and len(str(value)) < 100:
                    content.current[setting] = value
                elif isinstance(value, list) and all(isinstance(v, (str, int)) for v in value):
                    content.current[setting] = [str(v)[:200] for v in value[:100]]


def _walk_json(node: Any, content: ExportContent, depth: int = 0) -> None:
    if depth > 12 or len(content.findings) >= MAX_FINDINGS:
        return
    if isinstance(node, dict):
        _collect_settings(node, content)
        finding = _finding_from(node)
        if finding:
            content.findings.append(finding)
            if finding.output:
                content.texts.append(finding.output)
        for value in node.values():
            _walk_json(value, content, depth + 1)
    elif isinstance(node, list):
        if node and all(isinstance(x, dict) for x in node[:50]) and not any(_finding_from(x) for x in node[:5]):
            content.tables.append([{str(k): "" if v is None else str(v) for k, v in x.items()} for x in node[:200000]])
        for value in node:
            _walk_json(value, content, depth + 1)


def _read_csv(text: str, content: ExportContent) -> None:
    rows = list(csv.DictReader(io.StringIO(text)))
    if not rows:
        return
    found = False
    for row in rows:
        finding = _finding_from(row)
        if finding:
            found = True
            content.findings.append(finding)
            if finding.output:
                content.texts.append(finding.output)
    if not found:
        content.tables.append([{str(k): str(v or "") for k, v in r.items() if k is not None} for r in rows])


def _read_xml(data: bytes, content: ExportContent) -> None:
    root = ET.fromstring(data)  # ElementTree does not resolve external entities
    for el in root.iter():
        attrs = {**el.attrib, **{child.tag: (child.text or "") for child in el if len(child) == 0}}
        finding = _finding_from(attrs)
        if finding:
            content.findings.append(finding)
            if finding.output:
                content.texts.append(finding.output)


def read_export(data: bytes) -> ExportContent:
    content = ExportContent()
    budget = MAX_READ_BYTES
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        for info in zf.infolist():
            if info.is_dir():
                continue
            name = info.filename
            lower = name.lower()
            if info.file_size > MAX_MEMBER_BYTES or info.file_size > budget:
                content.skipped_files.append(name)
                continue
            if not lower.endswith((".json", ".csv", ".xml", ".nessus", ".har", ".txt", ".log")):
                continue
            budget -= info.file_size
            raw = zf.read(info)
            try:
                if lower.endswith(".har"):
                    entries = json.loads(raw.decode("utf-8-sig", "replace")).get("log", {}).get("entries", [])
                    content.har_entries.extend(e for e in entries[:500000] if isinstance(e, dict))
                elif lower.endswith(".json"):
                    parsed = json.loads(raw.decode("utf-8-sig", "replace"))
                    if isinstance(parsed, dict) and isinstance(parsed.get("log"), dict) and "entries" in parsed["log"]:
                        content.har_entries.extend(e for e in parsed["log"]["entries"][:500000] if isinstance(e, dict))
                    else:
                        _walk_json(parsed, content)
                elif lower.endswith(".csv"):
                    _read_csv(raw.decode("utf-8-sig", "replace"), content)
                elif lower.endswith((".xml", ".nessus")):
                    _read_xml(raw, content)
                else:
                    text = raw.decode("utf-8", "replace")
                    content.texts.append(text)
                    content.log_texts.append(text)
                content.read_files.append(name)
            except (ValueError, ET.ParseError, csv.Error):
                content.skipped_files.append(name)
    return content


# --- facts --------------------------------------------------------------------------

def _safe_url(url: str | None) -> str | None:
    """Scheme, host and path only: query strings and fragments can hold tokens."""
    if not url:
        return None
    parts = urlsplit(url.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        return None
    return f"{parts.scheme}://{parts.netloc.rsplit('@', 1)[-1]}{parts.path or '/'}"[:300]


def _sitemap(content: ExportContent) -> dict[str, Any]:
    """Per-reason counts and sample URLs from sitemap tables or text."""
    reasons: Counter[str] = Counter()
    samples: dict[str, list[str]] = {}
    urls: set[str] = set()
    hosts: Counter[str] = Counter()

    def add(reason: str | None, url: str | None) -> None:
        safe = _safe_url(url)
        if safe:
            urls.add(safe)
        if reason:
            reasons[reason] += 1
            if safe and len(samples.setdefault(reason, [])) < 8 and safe not in samples[reason]:
                samples[reason].append(safe)
            if reason == "not_in_domain" and safe:
                hosts[urlsplit(safe).hostname or ""] += 1

    for table in content.tables:
        if not table:
            continue
        head = table[:200]
        has_reasons = any(_REASON_RE.search(" ".join(r.values())) for r in head)
        url_rows = sum(1 for r in head if any(_URL_RE.match((v or "").strip()) for v in r.values()))
        if not has_reasons and url_rows < len(head) / 2:
            continue  # neither a sitemap nor a URL list
        for row in table:
            url = _pick(row, URL_KEYS) or next((v for v in row.values() if _URL_RE.match(v or "")), None)
            found = _REASON_RE.findall(" ".join(row.values()))
            if not found:
                add(None, url)
            for reason in set(found):
                add(reason, url)
    if not reasons:  # fall back to sitemap text in plugin output or text files
        for text in content.texts:
            if not _REASON_RE.search(text):
                continue
            for line in text.splitlines():
                found = _REASON_RE.findall(line)
                url_match = _URL_RE.search(line)
                url = url_match.group(0) if url_match else None
                if not found:
                    add(None, url)
                for reason in set(found):
                    add(reason, url)
    return {"reasons": dict(reasons), "samples": samples, "urls": urls,
            "external_hosts": dict(hosts.most_common(10))}


def _plugin_requests(content: ExportContent) -> list[dict[str, Any]]:
    """Requests per plugin from plugins.csv-style tables (98000 / plugin telemetry)."""
    out: Counter[int] = Counter()
    for table in content.tables:
        if not table:
            continue
        keys = {_norm(k): k for k in table[0]}
        pid_key = next((keys[k] for k in keys if k in ("plugin_id", "pluginid", "plugin", "id")), None)
        req_key = next((keys[k] for k in keys if "request" in k), None)
        if not pid_key or not req_key:
            continue
        for row in table:
            pid = _plugin_id(row.get(pid_key))
            try:
                count = int(float(row.get(req_key) or 0))
            except ValueError:
                continue
            if pid:
                out[pid] += count
    total = sum(out.values()) or 1
    return [{"plugin_id": pid, "requests": n, "share": round(n / total, 3)} for pid, n in out.most_common(10)]


def _path_template(url: str) -> str:
    """/calendar/2024/05/17 -> /calendar/{n}/{n}/{n}: groups crawl-trap URLs."""
    path = urlsplit(url).path
    path = re.sub(r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}(?=/|$)", "/{uuid}", path, flags=re.I)
    path = re.sub(r"/\d{4}-\d{2}-\d{2}(?=/|$)", "/{date}", path)
    return re.sub(r"/\d+(?=/|$)", "/{n}", path)


def _template_regex(template: str) -> str:
    """A WAS exclusion regex for a path template (case-sensitive, matched anywhere)."""
    parts = re.split(r"(\{n\}|\{date\}|\{uuid\})", template)
    out = []
    for part in parts:
        if part == "{n}":
            out.append(r"\d+")
        elif part == "{date}":
            out.append(r"\d{4}-\d{2}-\d{2}")
        elif part == "{uuid}":
            out.append(r"[0-9a-fA-F-]{36}")
        else:
            out.append(re.escape(part).replace("\\/", "/"))
    return "".join(out)


def _http_stats(entries: list[dict]) -> dict[str, Any]:
    """Status mix of the scan's own HTTP traffic (debug zip), split into halves so a
    session that dies mid-scan shows as redirects-to-login rising late."""
    statuses: Counter[str] = Counter()
    login_redirects = [0, 0]
    slow = 0
    half = len(entries) // 2 or 1
    for i, entry in enumerate(entries):
        resp = entry.get("response") or {}
        status = resp.get("status")
        if isinstance(status, int):
            bucket = "0" if status == 0 else f"{status // 100}xx" if status not in (401, 403, 429) else str(status)
            statuses[bucket] += 1
            if 300 <= status < 400 and re.search(r"log[\s_-]?in|sign[\s_-]?in|/auth|sso", resp.get("redirectURL") or "", re.I):
                login_redirects[0 if i < half else 1] += 1
        if isinstance(entry.get("time"), (int, float)) and entry["time"] > 10000:
            slow += 1
    return {"requests": len(entries), "statuses": dict(statuses), "login_redirects_first_half": login_redirects[0],
            "login_redirects_second_half": login_redirects[1], "slow": slow}


def _selenium_errors(texts: list[str]) -> dict[str, int]:
    """Error types in debug logs. Counts only: log lines can hold typed credentials."""
    counts: Counter[str] = Counter()
    for text in texts:
        for match in _SELENIUM_ERRORS.findall(text):
            counts[match] += 1
    return dict(counts.most_common(10))


# --- rules --------------------------------------------------------------------------

def analyze(data: bytes) -> dict[str, Any]:
    content = read_export(data)
    by_plugin: dict[int, list[Finding]] = {}
    for f in content.findings:
        by_plugin.setdefault(f.plugin_id, []).append(f)
    present = set(by_plugin)
    sitemap = _sitemap(content)
    reasons = sitemap["reasons"]
    plugin_requests = _plugin_requests(content)

    recs: list[dict[str, Any]] = []

    def rec(rec_id: str, severity: str, title: str, detail: str, changes: list[dict[str, str]] | None = None,
            evidence: list[str] | None = None) -> None:
        recs.append({"id": rec_id, "severity": severity, "title": title, "detail": detail,
                     "changes": changes or [], "evidence": evidence or []})

    def plugins_ev(ids: Iterable[int]) -> list[str]:
        return [f"{pid} {KNOWN_NAMES.get(pid) or (by_plugin[pid][0].name if by_plugin.get(pid) else '')} "
                f"({len(by_plugin.get(pid, []))}×)" for pid in ids if pid in present]

    # Authentication
    failed = sorted(present & set(AUTH_FAILED))
    succeeded = sorted(present & set(AUTH_OK))
    if failed:
        rec("auth_failed", "critical", "The scan did not log in",
            "Authentication failed, so the scan ran (or stopped) logged out: most of the app was never tested. "
            "Re-run the login in AuthRecon, click Verify, and upload the fresh .side with the run's page and "
            "pattern to verify.",
            [{"section": "Credentials", "setting": "Selenium script (.side)", "value": "Fresh, verified script from AuthRecon",
              "why": "The current script or credentials failed."}],
            plugins_ev(failed))
    if P_PATTERN_UNAUTH in present:
        rec("pattern_unauthenticated", "critical", "The success pattern also appears when logged out",
            "The scanner found the authentication check pattern in an unauthenticated browser, so it cannot tell "
            "logged-in from logged-out pages. Use text that only appears after login (AuthRecon's WAS card picks "
            "such text).",
            [{"section": "Credentials", "setting": "Pattern to Verify", "value": "Text only shown when logged in",
              "why": "The current pattern matches the login page too."}],
            plugins_ev([P_PATTERN_UNAUTH]))

    # Logged out mid-scan
    logout_urls = sorted({u for u in sitemap["urls"] if _LOGOUT_RE.search(urlsplit(u).path)})
    logout_changes = [{"section": "Scope", "setting": "Regex for Excluded URLs",
                       "value": re.escape(urlsplit(u).path).replace("\\/", "/"),
                       "why": "Logout-like URL the scanner visited"}
                      for u in logout_urls[:10] if "logout" not in urlsplit(u).path]
    if P_LOGOUT_ABORT in present:
        rec("logged_out_abort", "critical", "The scan was aborted after being logged out",
            "It lost its session and could not log back in. Exclude any URL that ends the session, and check the "
            "account was not locked or its password changed during the scan.",
            logout_changes, plugins_ev([P_LOGOUT_ABORT]) + logout_urls[:5])
    elif P_LOGOUT_INTERMITTENT in present:
        rec("logged_out_intermittent", "warning", "The scan was logged out and had to log back in",
            "Usually a link that ends the session. Exclude it so the scanner stops logging itself out "
            "(each re-login repeats the Selenium script and counts as a login on the account).",
            logout_changes, plugins_ev([P_LOGOUT_INTERMITTENT]) + logout_urls[:5])

    # Timeouts and protection
    timeout_count = len(by_plugin.get(P_TIMEOUT, [])) + reasons.get("timeout", 0)
    perf_changes = [
        {"section": "Performance", "setting": "Max Number of HTTP Requests Per Second", "value": "10",
         "why": "Default 25; the target is not keeping up."},
        {"section": "Performance", "setting": "Max Number of Concurrent HTTP Connections", "value": "5",
         "why": "Default 10."},
        {"section": "Performance", "setting": "Slow down the scan when network congestion is detected",
         "value": "Enabled", "why": "Backs off automatically when responses slow."},
        {"section": "Performance", "setting": "Network Timeout (In Seconds)", "value": "60", "why": "Default 30."},
    ]
    if P_TIMEOUT_ABORT in present:
        rec("timeout_abort", "critical", "The scan was aborted after too many timeouts",
            "The target stopped answering in time (by default 100 consecutive timeouts end the scan). Slow the "
            "scan down; if it still happens, ask whether a WAF or rate limit is blocking the scanner.",
            perf_changes + [{"section": "Performance", "setting": "Timeout Threshold", "value": "300",
                             "why": "Default 100; tolerate bursts once the rate is lower."}],
            plugins_ev([P_TIMEOUT_ABORT, P_TIMEOUT]))
    elif timeout_count >= 10:
        rec("timeouts", "warning", f"{timeout_count} requests timed out",
            "Timed-out URLs were not audited. Lower the request rate and raise the timeout.",
            perf_changes, plugins_ev([P_TIMEOUT]) + sitemap["samples"].get("timeout", [])[:5])
    if P_WAF in present:
        rec("waf", "warning", "A web application firewall was detected",
            "It may block or slow the scanner and hide findings. Ask for the scanner's IP to be allow-listed, and "
            "identify scan traffic with the Scan ID header.",
            [{"section": "HTTP Settings", "setting": "Add Scan ID HTTP Header", "value": "Enabled",
              "why": "Lets the site's team allow-list or spot the scan."},
             {"section": "Performance", "setting": "Max Number of HTTP Requests Per Second", "value": "10",
              "why": "Below the WAF's rate rules."}],
            plugins_ev([P_WAF]))

    # Coverage: sitemap reasons
    def reason_rec(reason: str, severity: str, title: str, detail: str, changes: list[dict[str, str]]) -> None:
        if reasons.get(reason):
            rec(f"sitemap_{reason}", severity, title.format(n=reasons[reason]), detail, changes,
                sitemap["samples"].get(reason, [])[:5])

    reason_rec("queue_full", "warning", "{n} URLs were dropped: the audit queue was full",
               "The scan reached its URL limit. Raise the limit, or cut noise first (exclusions, Deduplicate "
               "Similar Pages) so the limit is spent on real pages.",
               [{"section": "Limits", "setting": "Number of URLS to Crawl and Browse", "value": "20000",
                 "why": "Default 10000 was reached."},
                {"section": "Scope", "setting": "Deduplicate Similar Pages", "value": "Enabled",
                 "why": "Stops near-identical pages using up the queue."}])
    reason_rec("scan_timelimit_reached", "warning", "{n} queued URLs were never audited: the scan ran out of time",
               "Raise the maximum scan time, or narrow the scope so the time goes to the app's real pages.",
               [{"section": "General", "setting": "Target Scan Max Time (HH:MM:SS)", "value": "16:00:00",
                 "why": "Default 08:00:00 was reached (maximum 48:00:00)."}])
    reason_rec("directory_depth", "warning", "{n} URLs were skipped as too deep",
               "Pages deeper than the path depth limit were not scanned.",
               [{"section": "Limits", "setting": "Path Directory Depth", "value": "15", "why": "Default 10."}])
    reason_rec("request_redirect_limit", "warning", "{n} URLs hit the redirect limit",
               "Chains of redirects (often a login or locale redirect) stopped the crawler. Check the samples; "
               "raise the limit if the chains are legitimate.",
               [{"section": "Limits", "setting": "Request Redirect Limit", "value": "5", "why": "Default 3."}])
    reason_rec("filesize_exceeded", "info", "{n} responses were too large to analyze",
               "Large pages were fetched but not analyzed for vulnerabilities.",
               [{"section": "Limits", "setting": "Max Response Size", "value": "2000000", "why": "Default 500000 bytes."}])
    reason_rec("exclude_path_patterns", "info", "{n} URLs were excluded by your exclusion regexes",
               "Check the samples are meant to be excluded: an over-broad regex hides parts of the app.", [])
    reason_rec("scope_configuration", "info", "{n} URLs were outside the include list",
               "If they belong to the app, widen the scan's crawl limit or add them to the List of URLs.", [])

    # Crawl traps: many URLs that differ only by numbers, dates or ids
    templates = Counter(_path_template(u) for u in sitemap["urls"])
    traps = [(t, n) for t, n in templates.most_common(5)
             if n >= 150 and ("{n}" in t or "{date}" in t or "{uuid}" in t)]
    if traps:
        rec("crawl_traps", "warning", "Possible crawl traps",
            "Many URLs differ only by a number, date or id (calendars, paging, records). Excluding the pattern, or "
            "turning on Deduplicate Similar Pages, frees the scan for the rest of the app.",
            [{"section": "Scope", "setting": "Regex for Excluded URLs", "value": _template_regex(t),
              "why": f"{n} URLs like {t}"} for t, n in traps]
            + [{"section": "Scope", "setting": "Deduplicate Similar Pages", "value": "Enabled",
                "why": "Audits one of each similar page."}],
            [f"{t}: {n} URLs" for t, n in traps])

    # Other hosts and APIs
    ext_hosts = sitemap["external_hosts"]
    if P_EXTERNAL_API in present or (ext_hosts and sum(ext_hosts.values()) >= 20):
        rec("external_hosts", "info", "The app uses other hosts the scan skipped",
            "URLs on other domains are not scanned. If one is the app's own backend API, scan it as an additional "
            "target.", [], plugins_ev([P_EXTERNAL_API, P_EXTERNAL_URLS]) + [f"{h}: {n} URLs" for h, n in ext_hosts.items()][:5])
    if (P_API_DETECTED in present or P_XHR in present) and P_OPENAPI_OK not in present:
        rec("api_no_spec", "info", "The app calls an API but no API definition was imported",
            "Crawling finds only the API calls the UI makes. If the app has an OpenAPI/Swagger, GraphQL or WSDL "
            "definition, add it to the scan's scope to test every endpoint.",
            [{"section": "Scope", "setting": "OpenAPI (Swagger) Specification", "value": "Upload the app's spec",
              "why": "API detected without a spec."}], plugins_ev([P_API_DETECTED, P_XHR]))
    for pid, what in ((P_OPENAPI_FAIL, "OpenAPI"), (P_GRAPHQL_FAIL, "GraphQL"), (P_WSDL_FAIL, "WSDL")):
        if pid in present:
            rec(f"import_failed_{pid}", "warning", f"The {what} definition could not be imported",
                "Check the plugin output in Tenable for the parse error, fix the definition and re-upload it.",
                [], plugins_ev([pid]))
    if P_SELENIUM_CRAWL_FAIL in present:
        rec("crawl_script_failed", "warning", "A Selenium crawl script failed",
            "The pages it should reach were not scanned. Re-record the crawl script (AuthRecon's Manual recording "
            "or Selenium IDE) and check it replays.", [], plugins_ev([P_SELENIUM_CRAWL_FAIL]))

    # Low coverage on an authenticated scan
    audited_guess = len(sitemap["urls"])
    if succeeded and not failed and 0 < audited_guess < 25:
        rec("low_coverage", "warning", f"Only {audited_guess} URLs were found",
            "The scan logged in but saw very little of the app. Seed it with known pages (List of URLs), add a "
            "crawl script for areas behind menus or wizards, or import an API definition.",
            [{"section": "Scope", "setting": "List of URLs", "value": "Key pages of the app", "why": "Low coverage."}])

    # Debug zip: the scan's own HTTP traffic and Selenium logs
    http = _http_stats(content.har_entries) if content.har_entries else None
    if http and http["requests"]:
        st = http["statuses"]
        n = http["requests"]
        if st.get("429", 0) >= 5:
            rec("rate_limited", "warning", f"The target answered {st['429']} requests with 429 Too Many Requests",
                "It is rate-limiting the scanner; rate-limited requests test nothing.", perf_changes,
                [f"{st['429']} of {n} requests"])
        if st.get("5xx", 0) / n >= 0.05:
            rec("server_errors", "warning", f"{st['5xx']} server errors (5xx)",
                "A high error rate usually means the target is overloaded by the scan. Slow it down.",
                perf_changes, [f"{st['5xx']} of {n} requests"])
        late, early = http["login_redirects_second_half"], http["login_redirects_first_half"]
        if late >= 10 and late > 3 * max(early, 1):
            rec("session_died", "warning", "Requests started redirecting to the login page part-way through",
                f"{late} redirects to a login page in the second half of the scan versus {early} in the first: the "
                "session ended mid-scan. Look for a logout or session-ending URL to exclude, and compare the "
                "session lifetime with the scan's length (AuthRecon's scan readiness shows the cookie lifetime).",
                logout_changes, [f"{early} \u2192 {late} login redirects"])
    selenium_errors = _selenium_errors(content.log_texts)
    if selenium_errors and (failed or P_SELENIUM_CRAWL_FAIL in present or sum(selenium_errors.values()) >= 3):
        rec("selenium_errors", "warning" if not failed else "critical", "The Selenium script hit errors",
            "Element-not-found or timeout errors mean the login page changed or loaded slower than the script "
            "expects. Re-run the login in AuthRecon and Verify it; for slow pages raise the Selenium delays.",
            [{"section": "Selenium Settings", "setting": "Page Rendering Delay", "value": "45000",
              "why": "Default 30000 ms; for slow login pages."},
             {"section": "Selenium Settings", "setting": "Command Execution Delay", "value": "1000",
              "why": "Default 500 ms."}],
            [f"{name}: {count}" for name, count in selenium_errors.items()])

    # Where the requests went
    if plugin_requests and plugin_requests[0]["share"] >= 0.4:
        top = plugin_requests[0]
        rec("plugin_heavy", "info", f"One plugin sent {int(top['share'] * 100)}% of the scan's requests",
            "If the scan runs out of time, this plugin is where the time goes. Disable it (or its family) only "
            "if it does not apply to this app.", [],
            [f"{p['plugin_id']}: {p['requests']} requests" for p in plugin_requests[:5]])

    if succeeded and not failed and P_PATTERN_UNAUTH not in present:
        rec("auth_ok", "ok", "The scan logged in", "Authentication succeeded.", [], plugins_ev(succeeded))

    order = {"critical": 0, "warning": 1, "info": 2, "ok": 3}
    recs.sort(key=lambda r: order.get(r["severity"], 9))
    vulns = Counter((f.severity or "unknown") for f in content.findings if f.severity not in (None, "info", "none", "0"))
    for r in recs:
        r["changes"] = _against_current(r["changes"], content.current)
    return {
        "analyzer_version": ANALYZER_VERSION,
        "recognised": bool(content.findings or reasons or content.har_entries),
        "facts": {
            "findings": len(content.findings),
            "plugins_seen": len(present),
            "authentication": "failed" if failed else "succeeded" if succeeded else "unknown",
            "sitemap_urls": len(sitemap["urls"]),
            "sitemap_reasons": reasons,
            "vulnerabilities_by_severity": dict(vulns),
            "http": http,
            "selenium_errors": selenium_errors,
            "current_settings": {k: v for k, v in content.current.items()},
            "files_read": content.read_files[:50],
            "files_skipped": content.skipped_files[:50],
        },
        "recommendations": recs,
        "settings": _merge_changes(recs),
        "plugin_requests": plugin_requests,
    }


_LOWER = {"Max Number of HTTP Requests Per Second", "Max Number of Concurrent HTTP Connections"}


def _hms(value: Any) -> int | None:
    match = re.fullmatch(r"(\d+):(\d{2}):(\d{2})", str(value).strip())
    return int(match[1]) * 3600 + int(match[2]) * 60 + int(match[3]) if match else None


def _against_current(changes: list[dict[str, str]], current: dict[str, Any]) -> list[dict[str, str]]:
    """Fill in the scan's current value and keep each suggestion a real change:
    drop exclusions it already has; if a limit is already past the suggestion,
    go one step further from where it is."""
    out = []
    for change in changes:
        setting, value = change["setting"], change["value"]
        cur = current.get(setting)
        if cur is None:
            out.append(change)
            continue
        change = {**change, "current": ", ".join(cur) if isinstance(cur, list) else str(cur)}
        if setting == "Regex for Excluded URLs":
            if isinstance(cur, list) and value in cur:
                continue
        elif setting == "Target Scan Max Time (HH:MM:SS)":
            have, want = _hms(cur), _hms(value)
            if have and want and have >= want:
                if have >= 48 * 3600:
                    change["value"] = cur
                    change["why"] += " Already at the 48:00:00 maximum: narrow the scope instead."
                else:
                    doubled = min(have * 2, 48 * 3600)
                    change["value"] = f"{doubled // 3600:02d}:{doubled % 3600 // 60:02d}:00"
        else:
            try:
                have, want = float(cur), float(value)
            except (TypeError, ValueError):
                out.append(change)
                continue
            if setting in _LOWER and have <= want:
                change["value"] = str(max(1, int(have // 2)))
            elif setting not in _LOWER and have >= want:
                change["value"] = str(int(have * 2))
            if change["value"] == change["current"]:
                continue
        out.append(change)
    return out


def _merge_changes(recs: list[dict[str, Any]]) -> dict[str, list[dict[str, str]]]:
    """All suggested changes grouped by WAS section; exclusion regexes are collected,
    other settings keep the first (most severe) suggestion."""
    out: dict[str, list[dict[str, str]]] = {}
    seen: set[tuple[str, str, str]] = set()
    for r in recs:
        for c in r["changes"]:
            key = (c["section"], c["setting"], c["value"] if c["setting"] == "Regex for Excluded URLs" else "")
            if key in seen:
                continue
            seen.add(key)
            out.setdefault(c["section"], []).append(c)
    return out
