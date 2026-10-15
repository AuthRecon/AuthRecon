"""
Learning Service - Phase 4 Historical Learning

Extracts successful authentication patterns from completed runs and stores them
as playbooks for deterministic reuse.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

from sqlalchemy.orm import Session

from app.models.playbook import TenantPlaybook
from app.models.run import Run

LOGGER = logging.getLogger(__name__)

# Different code paths name the same auth flow differently; playbooks are
# stored and looked up under one canonical name so they're actually reused.
_AUTH_TYPE_ALIASES = {
    "form_based": ("form_based", "form_auth", "form_post", "form_login", "form"),
    "basic_auth": ("basic_auth", "http_basic", "basic"),
    "ldap": ("ldap", "ldap_form"),
}


def canonical_auth_type(auth_type: str | None) -> str:
    value = (auth_type or "unknown").strip().lower()
    for canonical, aliases in _AUTH_TYPE_ALIASES.items():
        if value in aliases:
            return canonical
    return value


def _auth_type_variants(auth_type: str | None) -> tuple[str, ...]:
    canonical = canonical_auth_type(auth_type)
    return _AUTH_TYPE_ALIASES.get(canonical, (canonical,))


def _is_generic(selectors: dict | None) -> bool:
    return not selectors or bool(selectors.get("is_generic") or selectors.get("incomplete"))


def extract_domain(url: str) -> str:
    """
    Extract domain from URL for playbook matching.

    Args:
        url: Full URL (e.g., "https://partner.acme.com/login")

    Returns:
        Domain (e.g., "partner.acme.com")
    """
    parsed = urlparse(url)
    return parsed.netloc or parsed.path


def extract_selectors_from_run(run: Run, db: Session) -> dict[str, str] | None:
    """
    Extract authentication selectors from a successful run.

    Looks in:
    1. Timeline events for selector discovery
    2. Pattern field for stored selectors
    3. Security context for additional metadata

    Args:
        run: Completed Run object
        db: Database session

    Returns:
        Dictionary of selectors or None if extraction failed
    """
    selectors = {}

    # Check if run has pattern data (Selenium .side file info)
    if run.pattern:
        try:
            import json
            pattern_data = json.loads(run.pattern) if isinstance(run.pattern, str) else run.pattern

            # Extract selectors from pattern if available
            if isinstance(pattern_data, dict):
                # Pattern structure varies, try common keys
                if "username_selector" in pattern_data:
                    selectors["username_selector"] = pattern_data["username_selector"]
                if "password_selector" in pattern_data:
                    selectors["password_selector"] = pattern_data["password_selector"]
                if "submit_selector" in pattern_data:
                    selectors["submit_selector"] = pattern_data["submit_selector"]

        except Exception as e:
            LOGGER.debug(f"Failed to parse pattern data: {e}")

    # Check timeline events for discovery results
    for event in run.timeline_events:
        if hasattr(event, 'message'):
            msg = event.message
        else:
            msg = str(event)

        # Look for selector discoveries in timeline
        if "selector" in msg.lower() or "discovered" in msg.lower():
            # Extract selectors from discovery messages
            # Example: "Discovered username field: #username"
            if "username" in msg.lower() and "#" in msg:
                parts = msg.split("#")
                if len(parts) > 1:
                    selector = "#" + parts[1].split()[0]
                    selectors["username_selector"] = selector

            elif "password" in msg.lower() and "#" in msg:
                parts = msg.split("#")
                if len(parts) > 1:
                    selector = "#" + parts[1].split()[0]
                    selectors["password_selector"] = selector

    # Fallback: Use common form-based selectors if auth_type is form_based
    if not selectors and run.auth_type == "form_based":
        # These are generic fallbacks, not ideal but better than nothing
        selectors = {
            "username_selector": "input[type='text'], input[type='email'], input[name*='user'], input[name*='email']",
            "password_selector": "input[type='password']",
            "submit_selector": "button[type='submit'], input[type='submit']",
            "is_generic": True,  # Mark as generic fallback
        }
        LOGGER.info(f"Using generic fallback selectors for {run.id}")

    # Return None if no selectors found
    if not selectors:
        return None

    return selectors


def extract_endpoints_from_run(run: Run) -> dict[str, Any] | None:
    """
    Extract authentication endpoints from a successful run.

    Args:
        run: Completed Run object

    Returns:
        Dictionary of endpoints or None
    """
    endpoints = {}

    # Primary endpoint from final_url
    if run.final_url:
        endpoints["final_url"] = run.final_url

    # Check security context for HAR insights
    if run.security_context and isinstance(run.security_context, dict):
        har_insights = run.security_context.get("har_insights")
        if har_insights and isinstance(har_insights, dict):
            # Extract login endpoints
            login_endpoints = har_insights.get("login_endpoints", [])
            if login_endpoints:
                endpoints["primary_endpoint"] = login_endpoints[0]
                endpoints["all_login_endpoints"] = login_endpoints

            # Extract logout endpoints
            logout_endpoints = har_insights.get("logout_endpoints", [])
            if logout_endpoints:
                endpoints["logout_endpoint"] = logout_endpoints[0]

    # Return None if no meaningful endpoints found
    if not endpoints or (len(endpoints) == 1 and "final_url" in endpoints):
        return None

    return endpoints


def extract_metadata_from_run(run: Run) -> dict[str, Any] | None:
    """
    Extract additional context/metadata from a successful run.

    Args:
        run: Completed Run object

    Returns:
        Dictionary of metadata or None
    """
    metadata = {}

    # Tech fingerprint data
    if run.tech_fingerprint:
        metadata["tech_stack"] = run.tech_fingerprint.get("js_frameworks", [])
        metadata["cms"] = run.tech_fingerprint.get("cms", [])
        metadata["security_headers"] = run.tech_fingerprint.get("security_headers", [])

    # Auth type
    if run.auth_type:
        metadata["detected_auth_type"] = run.auth_type

    # Pattern used
    if run.pattern:
        metadata["pattern_used"] = True

    return metadata if metadata else None


def learn_from_successful_run(
    run: Run,
    db: Session,
    profile_id: str | None = None,
    selectors: dict[str, Any] | None = None,
    success_already_recorded: bool = False,
) -> TenantPlaybook | None:
    """
    Learn authentication pattern from a successful run and store as playbook.

    Args:
        run: Successful Run object to learn from
        db: Database session
        profile_id: Optional profile ID for multi-tenant isolation
        selectors: The selectors the successful login actually used (preferred
            over guessing them from the run afterwards)
        success_already_recorded: The run already counted a success on the
            playbook it used; don't count it twice

    Returns:
        Created TenantPlaybook or None if learning failed
    """
    # Only learn from successful runs
    if run.status.value != "succeeded":
        LOGGER.debug(f"Skipping learning from non-successful run {run.id}")
        return None

    # Extract domain
    domain = extract_domain(run.target_url)
    if not domain:
        LOGGER.warning(f"Could not extract domain from {run.target_url}")
        return None

    auth_type = canonical_auth_type(run.auth_type)

    # Prefer what the login actually used (as plain CSS); fall back to extraction
    if selectors:
        from app.services.automation.selectors import plain_css

        selectors = {
            key: (plain_css(value) if key.endswith("_selector") else value)
            for key, value in selectors.items()
        }
        selectors = {key: value for key, value in selectors.items() if value}
    if not (selectors and selectors.get("password_selector")):
        selectors = extract_selectors_from_run(run, db)
    if not selectors:
        LOGGER.info(f"Could not extract selectors from run {run.id}")
        # We'll still create a playbook but mark it as incomplete
        selectors = {"incomplete": True}

    # Check if playbook already exists for this domain
    existing = db.query(TenantPlaybook).filter(
        TenantPlaybook.domain == domain,
        TenantPlaybook.profile_id == profile_id,
        TenantPlaybook.auth_type.in_(_auth_type_variants(auth_type))
    ).first()

    if existing:
        # Update existing playbook. The form handler already counted this run if
        # it used the playbook's selectors, so only count it here otherwise.
        if not success_already_recorded:
            existing.record_success(datetime.now(timezone.utc))
        if not _is_generic(selectors) or _is_generic(existing.selectors):
            existing.selectors = selectors  # never replace real selectors with generic guesses
        existing.auth_type = auth_type
        existing.endpoints = extract_endpoints_from_run(run) or existing.endpoints
        existing.context_data = extract_metadata_from_run(run) or existing.context_data

        db.commit()
        LOGGER.info(
            f"Updated existing playbook {existing.id} for {domain} "
            f"(success_count: {existing.success_count}, confidence: {existing.confidence_score}%)"
        )
        return existing

    # Create new playbook
    playbook = TenantPlaybook(
        id=str(uuid.uuid4()),
        domain=domain,
        profile_id=profile_id,
        auth_type=auth_type,
        selectors=selectors,
        endpoints=extract_endpoints_from_run(run),
        confidence_score=100,  # Start with 100% on first success
        success_count=1,
        failure_count=0,
        learned_from_run_id=run.id,
        created_at=datetime.now(timezone.utc),
        last_successful_at=datetime.now(timezone.utc),
        context_data=extract_metadata_from_run(run),
    )

    db.add(playbook)
    db.commit()

    LOGGER.info(
        f"Created new playbook {playbook.id} for {domain} "
        f"(auth_type: {playbook.auth_type}, learned from: {run.id})"
    )

    return playbook


def lookup_playbook(
    target_url: str,
    auth_type: str | None,
    db: Session,
    profile_id: str | None = None,
    min_confidence: int = 70
) -> TenantPlaybook | None:
    """
    Lookup existing playbook for deterministic execution.

    Args:
        target_url: Target URL to authenticate to
        auth_type: Expected auth type (optional filter)
        db: Database session
        profile_id: Optional profile ID for multi-tenant isolation
        min_confidence: Minimum confidence threshold (default: 70%)

    Returns:
        TenantPlaybook if found and reliable, None otherwise
    """
    domain = extract_domain(target_url)
    if not domain:
        return None

    # Build query
    query = db.query(TenantPlaybook).filter(
        TenantPlaybook.domain == domain
    )

    # Handle profile_id filtering (NULL requires IS NULL, not ==)
    if profile_id is None:
        query = query.filter(TenantPlaybook.profile_id.is_(None))
    else:
        query = query.filter(TenantPlaybook.profile_id == profile_id)

    # Filter by auth_type if provided (any alias of the same flow)
    if auth_type:
        query = query.filter(TenantPlaybook.auth_type.in_(_auth_type_variants(auth_type)))

    # Order by success rate (most reliable first)
    query = query.order_by(
        TenantPlaybook.success_count.desc(),
        TenantPlaybook.last_successful_at.desc()
    )

    # Get best match
    playbook = query.first()

    if not playbook:
        LOGGER.debug(f"No playbook found for {domain}")
        return None

    # Check reliability
    if not playbook.is_reliable(min_confidence):
        LOGGER.info(
            f"Playbook {playbook.id} for {domain} not reliable "
            f"(confidence: {playbook.confidence_score}%, threshold: {min_confidence}%)"
        )
        return None

    LOGGER.info(
        f"Found reliable playbook {playbook.id} for {domain} "
        f"(auth_type: {playbook.auth_type}, confidence: {playbook.confidence_score}%, "
        f"success: {playbook.success_count}, failures: {playbook.failure_count})"
    )

    return playbook


def record_playbook_usage(
    playbook: TenantPlaybook,
    success: bool,
    db: Session
) -> None:
    """
    Record the result of using a playbook for authentication.

    Args:
        playbook: Playbook that was used
        success: Whether authentication succeeded
        db: Database session
    """
    timestamp = datetime.now(timezone.utc)

    if success:
        playbook.record_success(timestamp)
        LOGGER.info(f"Playbook {playbook.id} succeeded (new confidence: {playbook.confidence_score}%)")
    else:
        playbook.record_failure(timestamp)
        LOGGER.warning(f"Playbook {playbook.id} failed (new confidence: {playbook.confidence_score}%)")

    db.commit()
