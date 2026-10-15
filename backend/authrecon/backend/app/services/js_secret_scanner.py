"""
JavaScript Secret Scanner

Scans JavaScript files extracted from HAR captures for hardcoded secrets,
API keys, credentials, and other sensitive data.

WHY THIS EXISTS:
- Real-world finding: Vendor portal exposed credentials in JS files
- Attackers can view JS without authentication
- Most scanners don't check for this
- Compliance risk (PCI-DSS, SOC2, etc.)

WHAT IT DETECTS:
- Cloud provider API keys (AWS, Azure, Google, etc.)
- Hardcoded passwords and credentials
- JWT tokens and session tokens
- Database connection strings
- Private keys (RSA, EC, SSH)
- Internal URLs and endpoints
- Environment variables and config leaks

OUTPUT:
- List of findings with severity, location, impact
- Pre-auth vs post-auth distinction
- Code snippets with context
- Line numbers for remediation
"""

import re
import json
import base64
import math
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, asdict
from collections import Counter


@dataclass
class JSSecretFinding:
    """Represents a secret found in JavaScript code."""
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    type: str  # "AWS Access Key", "Hardcoded Password", etc.
    file: str  # Filename from URL
    url: str  # Full URL to the JS file
    line: int  # Line number where secret was found
    snippet: str  # Code snippet showing the secret (with context)
    matched_value: str  # The actual matched string
    impact: str  # What this means for security
    pre_auth: bool  # Was this found before authentication?
    confidence: str = "HIGH"  # HIGH, MEDIUM, LOW


# Well-known constants that should never be flagged as secrets
KNOWN_CONSTANTS: Set[str] = {
    # Flash Player CLSID (ActiveX control ID from 1996)
    "D27CDB6E-AE6D-11cf-96B8-444553540000",
    "d27cdb6e-ae6d-11cf-96b8-444553540000",

    # Common GUIDs used in web development
    "00000000-0000-0000-0000-000000000000",  # Null GUID

    # Common public hashes/identifiers (add more as discovered)
}

# Patterns that indicate a value is NOT a secret (just a variable name)
NON_SECRET_PATTERNS = [
    r"^[a-zA-Z_][a-zA-Z0-9_]*$",  # Simple variable names (camelCase, snake_case)
    r"^[a-zA-Z_][a-zA-Z0-9_]*:[a-zA-Z_][a-zA-Z0-9_]*$",  # Object property (key:value)
]


def calculate_entropy(s: str) -> float:
    """
    Calculate Shannon entropy of a string.

    Higher entropy = more random (likely a real secret)
    Lower entropy = more patterns (likely a function name or constant)

    Returns:
        Entropy value (typically 0-5 for text, higher for random data)
    """
    if not s:
        return 0.0

    # Count character frequencies
    counts = Counter(s)
    length = len(s)

    # Calculate Shannon entropy: -sum(p(x) * log2(p(x)))
    entropy = 0.0
    for count in counts.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return entropy


def is_likely_minified(filename: str, content: str) -> bool:
    """
    Detect if a JavaScript file is minified.

    Args:
        filename: Name of the file
        content: File content

    Returns:
        True if likely minified
    """
    # Check filename
    if filename.endswith('.min.js'):
        return True

    # Check content patterns (minified files have very long lines)
    lines = content.split('\n')
    if lines:
        avg_line_length = sum(len(line) for line in lines[:100]) / min(100, len(lines))
        if avg_line_length > 500:  # Minified files often have 1000+ char lines
            return True

    return False


def is_in_assignment_context(content: str, match_start: int, window: int = 50) -> bool:
    """
    Check if a match appears in an assignment context (key=value, key:value).

    Helps filter out matches in comments, function names, or other non-secret contexts.

    Args:
        content: Full file content
        match_start: Position of the match
        window: Number of chars to check before match

    Returns:
        True if in assignment context
    """
    # Look at characters before the match
    start = max(0, match_start - window)
    before_text = content[start:match_start]

    # Check for assignment patterns
    assignment_patterns = [
        r'[a-zA-Z_][a-zA-Z0-9_]*\s*[=:]\s*["\']?$',  # variable = "match" or key: "match"
        r'[a-zA-Z_][a-zA-Z0-9_]*\s*[=:]\s*$',  # without quotes
    ]

    for pattern in assignment_patterns:
        if re.search(pattern, before_text):
            return True

    return False


# Secret detection patterns
# Each pattern has: regex, severity, impact description, and confidence level
SECRET_PATTERNS = {
    "AWS Access Key": {
        "pattern": r"AKIA[0-9A-Z]{16}",
        "severity": "CRITICAL",
        "impact": "Full AWS account access - attacker can read/write S3, launch EC2 instances, access databases",
        "confidence": "HIGH"
    },
    "AWS Secret Key": {
        "pattern": r"aws_secret_access_key[\s]*[=:][\s]*['\"]([A-Za-z0-9/+=]{40})['\"]",
        "severity": "CRITICAL",
        "impact": "AWS secret key - combined with access key grants full AWS access",
        "confidence": "HIGH"
    },
    "Azure Client Secret": {
        "pattern": r"(?:client[_-]?secret|azure[_-]?secret|app[_-]?secret)[\s]*[=:][\s]*['\"]?([0-9a-zA-Z~_.-]{34,40})['\"]?",
        "severity": "HIGH",
        "impact": "Azure service principal access",
        "confidence": "MEDIUM",  # Requires context validation
        "requires_context": True  # Must be in assignment context
    },
    "Google API Key": {
        "pattern": r"AIza[0-9A-Za-z-_]{35}",
        "severity": "HIGH",
        "impact": "Google Cloud API access - may allow data access or service abuse",
        "confidence": "HIGH"
    },
    "Generic API Key": {
        "pattern": r"(?:api[_-]?key|apikey)[\s]*[=:][\s]*['\"]([a-zA-Z0-9_-]{20,})['\"]",
        "severity": "HIGH",
        "impact": "API key exposure - may grant access to internal or external services",
        "confidence": "MEDIUM"
    },
    "Hardcoded Password": {
        "pattern": r"(?:password|passwd|pwd)[\s]*[=:][\s]*['\"]([^'\"]{8,})['\"]",
        "severity": "HIGH",
        "impact": "Hardcoded password - credential exposure",
        "confidence": "MEDIUM"  # May catch variable names
    },
    "JWT Token": {
        "pattern": r"eyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}",
        "severity": "HIGH",
        "impact": "JWT token exposure - may allow session hijacking or API access",
        "confidence": "HIGH"
    },
    "Bearer Token": {
        "pattern": r"Bearer[\s]+[a-zA-Z0-9_-]{20,}",
        "severity": "HIGH",
        "impact": "Bearer token - API authentication token",
        "confidence": "MEDIUM"
    },
    "Database Connection String (MySQL)": {
        "pattern": r"mysql://[^\s\"']+",
        "severity": "CRITICAL",
        "impact": "MySQL database connection string - direct database access",
        "confidence": "HIGH"
    },
    "Database Connection String (PostgreSQL)": {
        "pattern": r"postgres(?:ql)?://[^\s\"']+",
        "severity": "CRITICAL",
        "impact": "PostgreSQL database connection string - direct database access",
        "confidence": "HIGH"
    },
    "Database Connection String (MongoDB)": {
        "pattern": r"mongodb(?:\+srv)?://[^\s\"']+",
        "severity": "CRITICAL",
        "impact": "MongoDB connection string - direct database access",
        "confidence": "HIGH"
    },
    "Redis Connection String": {
        "pattern": r"redis://[^\s\"']+",
        "severity": "HIGH",
        "impact": "Redis connection string - cache/session store access",
        "confidence": "HIGH"
    },
    "Private Key (RSA)": {
        "pattern": r"-----BEGIN RSA PRIVATE KEY-----",
        "severity": "CRITICAL",
        "impact": "RSA private key - cryptographic credential exposure",
        "confidence": "HIGH"
    },
    "Private Key (EC)": {
        "pattern": r"-----BEGIN EC PRIVATE KEY-----",
        "severity": "CRITICAL",
        "impact": "EC private key - cryptographic credential exposure",
        "confidence": "HIGH"
    },
    "Private Key (OpenSSH)": {
        "pattern": r"-----BEGIN OPENSSH PRIVATE KEY-----",
        "severity": "CRITICAL",
        "impact": "SSH private key - server access credential",
        "confidence": "HIGH"
    },
    "Internal Admin URL": {
        "pattern": r"https?://(?:admin|internal|staging|dev)[\w.-]+",
        "severity": "MEDIUM",
        "impact": "Internal URL disclosure - reveals infrastructure topology",
        "confidence": "MEDIUM"
    },
    "Internal API Endpoint": {
        "pattern": r"(?:api[_-]?url|api[_-]?endpoint|base[_-]?url)[\s]*[=:][\s]*['\"]([^'\"]+/(?:api|admin|internal)[^'\"]*)['\"]",
        "severity": "MEDIUM",
        "impact": "Internal API endpoint disclosure - may allow unauthenticated probing",
        "confidence": "HIGH"
    },
    "Slack Webhook": {
        "pattern": r"https://hooks\.slack\.com/services/[A-Z0-9/]+",
        "severity": "MEDIUM",
        "impact": "Slack webhook URL - can send messages to private channels",
        "confidence": "HIGH"
    },
    "Twilio API Key": {
        "pattern": r"SK[a-z0-9]{32}",
        "severity": "HIGH",
        "impact": "Twilio API key - SMS/call service access",
        "confidence": "HIGH"
    },
    "Stripe API Key": {
        "pattern": r"sk_(?:live|test)_[0-9a-zA-Z]{24,}",
        "severity": "CRITICAL",
        "impact": "Stripe API key - payment processing access (live keys are critical)",
        "confidence": "HIGH"
    },
    "GitHub Token": {
        "pattern": r"ghp_[a-zA-Z0-9]{36}",
        "severity": "HIGH",
        "impact": "GitHub personal access token - repository access",
        "confidence": "HIGH"
    },
    "GitHub OAuth": {
        "pattern": r"gho_[a-zA-Z0-9]{36}",
        "severity": "HIGH",
        "impact": "GitHub OAuth token - user authentication",
        "confidence": "HIGH"
    },
}


def extract_js_from_har(har_bytes: bytes) -> List[Dict[str, Any]]:
    """
    Extract JavaScript files from HAR capture.

    Args:
        har_bytes: HAR file content as bytes

    Returns:
        List of dicts with url, content, mime_type
    """
    js_files = []

    try:
        har = json.loads(har_bytes)
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        print(f"Error parsing HAR: {e}")
        return []

    entries = har.get("log", {}).get("entries", [])

    for entry in entries:
        url = entry.get("request", {}).get("url", "")
        response = entry.get("response", {})
        content_data = response.get("content", {})
        mime_type = content_data.get("mimeType", "")

        # Only process JavaScript files
        if not any(js_type in mime_type.lower() for js_type in ["javascript", "ecmascript", "text/js", "application/js"]):
            continue

        # Get content (may be base64 encoded)
        content = content_data.get("text", "")
        encoding = content_data.get("encoding", "")

        # Decode if base64
        if encoding == "base64":
            try:
                content = base64.b64decode(content).decode('utf-8', errors='ignore')
            except Exception:
                continue  # Skip if can't decode

        if content and len(content) > 0:
            js_files.append({
                "url": url,
                "content": content,
                "mime_type": mime_type,
                "size": len(content)
            })

    return js_files


def scan_content_for_secrets(
    content: str,
    url: str,
    pre_auth: bool = True
) -> List[JSSecretFinding]:
    """
    Scan JavaScript content for secrets using regex patterns with false positive filtering.

    Args:
        content: JavaScript source code
        url: URL where the JS was loaded from
        pre_auth: Whether this was scanned before authentication

    Returns:
        List of JSSecretFinding objects (filtered for quality)
    """
    findings = []
    filename = url.split('/')[-1].split('?')[0]  # Extract filename, remove query params

    # Detect if file is minified
    is_minified = is_likely_minified(filename, content)

    for secret_type, config in SECRET_PATTERNS.items():
        pattern = config["pattern"]
        requires_context = config.get("requires_context", False)

        # Find all matches
        for match in re.finditer(pattern, content, re.IGNORECASE):
            # Get matched value
            matched = match.group(0)

            # **FILTER 1: Known constants blocklist**
            if matched in KNOWN_CONSTANTS or matched.upper() in KNOWN_CONSTANTS:
                continue  # Skip well-known public constants

            # **FILTER 2: Non-secret patterns (simple variable names)**
            is_non_secret = any(re.match(pat, matched) for pat in NON_SECRET_PATTERNS)
            if is_non_secret:
                continue  # Skip simple variable names like "googleAnalyticsCustomVariableScope"

            # **FILTER 3: Entropy check**
            # Function names have low entropy, real secrets have high entropy
            entropy = calculate_entropy(matched)
            if entropy < 3.0:  # Low entropy = likely not a secret
                # Exception: Some patterns like database URLs don't need high entropy
                requires_high_entropy = secret_type not in [
                    "Database Connection String (MySQL)",
                    "Database Connection String (PostgreSQL)",
                    "Database Connection String (MongoDB)",
                    "Redis Connection String",
                    "Internal Admin URL"
                ]
                if requires_high_entropy:
                    continue  # Skip low-entropy matches

            # **FILTER 4: Context requirement**
            # Some patterns (like Azure) must be in assignment context
            if requires_context:
                if not is_in_assignment_context(content, match.start()):
                    continue  # Skip if not in assignment context

            # Calculate line number
            line_num = content[:match.start()].count('\n') + 1

            # Extract code snippet with context (3 lines before and after)
            lines = content.split('\n')
            start_line = max(0, line_num - 3)
            end_line = min(len(lines), line_num + 3)

            # Build snippet with line numbers
            snippet_lines = []
            for i in range(start_line, end_line):
                line_marker = "→" if i == line_num - 1 else " "
                snippet_lines.append(f"{i+1:4d}{line_marker} {lines[i]}")

            snippet = '\n'.join(snippet_lines)

            # Truncate if too long
            matched_display = matched
            if len(matched_display) > 100:
                matched_display = matched_display[:97] + "..."

            # **FILTER 5: Reduce confidence for minified files**
            confidence = config.get("confidence", "MEDIUM")
            if is_minified and confidence == "HIGH":
                confidence = "MEDIUM"  # Downgrade confidence for minified files
            elif is_minified and confidence == "MEDIUM":
                confidence = "LOW"

            finding = JSSecretFinding(
                severity=config["severity"],
                type=secret_type,
                file=filename,
                url=url,
                line=line_num,
                snippet=snippet,
                matched_value=matched_display,
                impact=config["impact"],
                pre_auth=pre_auth,
                confidence=confidence
            )

            findings.append(finding)

    return findings


def scan_javascript_secrets(
    har_bytes: bytes,
    pre_auth: bool = True,
    max_findings_per_file: int = 10
) -> Dict[str, Any]:
    """
    Main entry point: Scan HAR for JavaScript files and detect secrets.

    Args:
        har_bytes: HAR file content
        pre_auth: Whether this scan is before authentication
        max_findings_per_file: Limit findings per file to avoid spam

    Returns:
        Dict matching JSSecretsAnalysis schema (for JSON serialization)
    """
    all_findings = []

    # Extract JS files from HAR
    js_files = extract_js_from_har(har_bytes)
    total_js_files = len(js_files)

    if not js_files:
        # Return empty JSSecretsAnalysis structure
        return {
            "findings": [],
            "total_findings": 0,
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "pre_auth_count": 0,
            "post_auth_count": 0,
            "total_js_files": 0,
            "files_with_secrets": 0,
            "security_score": 100.0,
            "issues": [],
            "total_lines_scanned": 0,
            "largest_files": []
        }

    # Scan each JS file
    files_with_secrets = set()
    for js_file in js_files:
        file_findings = scan_content_for_secrets(
            content=js_file["content"],
            url=js_file["url"],
            pre_auth=pre_auth
        )

        # Limit findings per file to avoid spam
        if len(file_findings) > max_findings_per_file:
            file_findings = file_findings[:max_findings_per_file]

        if file_findings:
            files_with_secrets.add(js_file["url"])

        all_findings.extend(file_findings)

    # Convert to dicts for JSON serialization
    findings_list = [asdict(finding) for finding in all_findings]

    # Calculate statistics
    critical_count = sum(1 for f in findings_list if f.get("severity") == "CRITICAL")
    high_count = sum(1 for f in findings_list if f.get("severity") == "HIGH")
    medium_count = sum(1 for f in findings_list if f.get("severity") == "MEDIUM")
    low_count = sum(1 for f in findings_list if f.get("severity") == "LOW")
    pre_auth_count = sum(1 for f in findings_list if f.get("pre_auth", True))
    post_auth_count = len(findings_list) - pre_auth_count

    # Calculate security score (0-100, lower is worse)
    security_score = 100.0
    if findings_list:
        # Deduct points based on severity
        security_score -= critical_count * 30  # -30 per critical
        security_score -= high_count * 15      # -15 per high
        security_score -= medium_count * 5     # -5 per medium
        security_score -= low_count * 1        # -1 per low
        security_score = max(0.0, security_score)  # Don't go below 0

    # Build issues list
    issues = []
    if critical_count > 0:
        issues.append(f"{critical_count} CRITICAL secret(s) detected")
    if high_count > 0:
        issues.append(f"{high_count} HIGH severity secret(s) detected")
    if pre_auth_count > 0:
        issues.append(f"{pre_auth_count} secret(s) exposed pre-authentication")

    # Calculate scanning statistics
    total_lines_scanned = sum(len(js_file["content"].splitlines()) for js_file in js_files)

    # Get top 5 largest files with their info
    files_with_info = [
        {
            "name": js_file["url"].split("/")[-1].split("?")[0] or "unknown.js",
            "lines": len(js_file["content"].splitlines()),
            "size_bytes": js_file["size"]
        }
        for js_file in js_files
    ]
    largest_files = sorted(files_with_info, key=lambda f: f["size_bytes"], reverse=True)[:5]

    # Return JSSecretsAnalysis structure
    return {
        "findings": findings_list,
        "total_findings": len(findings_list),
        "critical_count": critical_count,
        "high_count": high_count,
        "medium_count": medium_count,
        "low_count": low_count,
        "pre_auth_count": pre_auth_count,
        "post_auth_count": post_auth_count,
        "total_js_files": total_js_files,
        "files_with_secrets": len(files_with_secrets),
        "security_score": security_score,
        "issues": issues,
        "total_lines_scanned": total_lines_scanned,
        "largest_files": largest_files
    }


def get_summary_stats(findings: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Generate summary statistics for findings.

    Args:
        findings: List of finding dicts

    Returns:
        Dict with counts by severity, pre/post auth, etc.
    """
    if not findings:
        return {
            "total": 0,
            "by_severity": {},
            "by_type": {},
            "pre_auth_count": 0,
            "post_auth_count": 0
        }

    by_severity = {}
    by_type = {}
    pre_auth_count = 0
    post_auth_count = 0

    for finding in findings:
        # Count by severity
        severity = finding.get("severity", "UNKNOWN")
        by_severity[severity] = by_severity.get(severity, 0) + 1

        # Count by type
        secret_type = finding.get("type", "Unknown")
        by_type[secret_type] = by_type.get(secret_type, 0) + 1

        # Count pre vs post auth
        if finding.get("pre_auth", True):
            pre_auth_count += 1
        else:
            post_auth_count += 1

    return {
        "total": len(findings),
        "by_severity": by_severity,
        "by_type": by_type,
        "pre_auth_count": pre_auth_count,
        "post_auth_count": post_auth_count
    }
