from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import Iterable, Any
from urllib.parse import urlparse, urljoin

import requests
from requests import Response

from app.services.hints import match_hint, HintDecision
from app.services.tech_fingerprint import analyze_tech_fingerprint
from app.services.har_analyzer import analyze_har, HARAuthInsight, get_primary_auth_endpoint
from app.services.scoring import (
    ScoringMatrix,
    analyze_headers_for_signals,
    analyze_url_for_signals,
    analyze_html_for_signals,
    analyze_tech_fingerprint_for_signals,
    analyze_har_insights_for_signals,
    WEIGHT_DEFINITIVE,
)

LOGGER = logging.getLogger(__name__)

USER_AGENT = "AuthReconWeb/1.0 (+https://example.internal)"
# Asymmetric timeout: the URL the operator actually submitted gets more
# patience (enterprise/government targets are often slow — a timeout here
# shouldn't look identical to "the site doesn't exist"), while the guessed
# common-login-path probes stay fast since they're speculative and we don't
# want detection to crawl just because an unrelated guessed path is slow.
TIMEOUT_SECONDS = 10  # For the actual submitted URL
GUESS_TIMEOUT_SECONDS = 5  # For speculative common-path probes
MAX_CONSECUTIVE_NETWORK_ERRORS = 3  # Stop probing after this many consecutive failures
ORIGINAL_URL_TIMEOUT_RETRIES = 1  # Slow sites: retry the submitted URL once on a timeout
DISCOVERY_PATHS = (
    "/login",
    "/signin",
    "/sign-in",
    "/account/login",
    "/user/login",
    "/auth/login",
    "/auth/signin",
    "/users/sign_in",
)


@dataclass
class AuthDetectionResult:
    auth_type: str
    final_url: str | None = None
    evidence: str | None = None
    error: str | None = None
    signals: list[dict[str, str]] = None
    redirect_chain: list[str] | None = None
    probed_urls: list[str] | None = None
    confidence: int = 50  # 0-100 confidence score
    detection_method: str = "http"  # "http" or "browser"
    is_definitive: bool = False  # True if backed by a verifiable fact (e.g. an
    # actual WWW-Authenticate header), not just heuristic inference (URL
    # pattern match, HTML form shape). Matters when the result came from a
    # guessed common path rather than the submitted URL — see detect_auth_type.
    tech_fingerprint: dict[str, Any] | None = None  # Technology fingerprinting data
    har_insights: dict[str, Any] | None = None  # HAR analysis insights (from Playwright capture)

    def to_dict(self) -> dict[str, str | list[str] | int | None]:
        return {
            "auth_type": self.auth_type,
            "final_url": self.final_url,
            "evidence": self.evidence,
            "error": self.error,
            "signals": self.signals or [],
            "redirect_chain": self.redirect_chain or [],
            "probed_urls": self.probed_urls or [],
            "confidence": self.confidence,
            "detection_method": self.detection_method,
            "tech_fingerprint": self.tech_fingerprint,
            "har_insights": self.har_insights,
        }


def _get_with_timeout_retry(
    session: requests.Session,
    url: str,
    *,
    timeout: float,
    retries: int,
    on_retry=None,
) -> requests.Response:
    """GET ``url``, retrying up to ``retries`` times only when the request times out.

    Other failures (DNS, refused, TLS) are raised immediately, as is the final timeout.
    """
    for attempt in range(retries + 1):
        try:
            return session.get(url, timeout=timeout, allow_redirects=True)
        except requests.Timeout:
            if attempt >= retries:
                raise
            LOGGER.info("Detection probe timed out; retrying once (attempt %d)", attempt + 2)
            if on_retry:
                on_retry()
    raise AssertionError("unreachable")  # pragma: no cover


def detect_auth_type(
    target_url: str,
    *,
    login_hint: str | None = None,
    use_browser: bool = False,
) -> AuthDetectionResult:
    """
    Attempt to infer the authentication flow for the supplied URL.

    The detector now probes a handful of common login paths in addition to the
    requested URL. Each probe records redirect chains, response metadata, and
    HTML clues so downstream automation can make more informed decisions.

    Args:
        target_url: The URL to detect authentication for
        login_hint: Optional operator-provided hint (e.g., "partner", "okta") to influence detection
        use_browser: If True, use headless browser for JavaScript execution (slower but more accurate)
    """
    session = requests.Session()
    session.headers.update({"User-Agent": USER_AGENT})
    signals: list[dict[str, str]] = []
    hint_decision = match_hint(login_hint)
    if hint_decision:
        signals.append(
            {
                "type": "hint_match",
                "hint": (login_hint or "").strip(),
                "profile": hint_decision.profile.profile_id,
                "auth_type": hint_decision.auth_type,
                "confidence": str(hint_decision.confidence),
            }
        )
    probed_urls: list[str] = []
    last_error: str | None = None
    fallback_result: AuthDetectionResult | None = None
    consecutive_network_errors = 0  # Track consecutive failures for early termination

    for candidate, is_original in _build_candidate_urls(target_url):
        try:
            response = _get_with_timeout_retry(
                session,
                candidate,
                timeout=TIMEOUT_SECONDS if is_original else GUESS_TIMEOUT_SECONDS,
                # Only the submitted URL is worth waiting for; guessed paths stay fast.
                retries=ORIGINAL_URL_TIMEOUT_RETRIES if is_original else 0,
                on_retry=lambda url=candidate: signals.append({"type": "timeout_retry", "url": url}),
            )
            consecutive_network_errors = 0  # Reset on successful request
        except requests.RequestException as exc:
            last_error = str(exc)
            signals.append(
                {
                    "type": "network_error",
                    "url": candidate,
                    "detail": last_error,
                    "guessed_path": str(not is_original),
                }
            )
            # A connection-level failure (DNS, refused, reset, timeout) on
            # the URL the operator actually submitted means there's nothing
            # to probe guesses against — stop immediately, don't wait for a
            # count. A failure on a GUESSED path is a different story: it's
            # normal for most of the common paths not to exist, and on a
            # real enterprise/government target with a defensive WAF, a few
            # rapid sequential probes can get rate-limited or reset without
            # the actual target being unreachable at all. Guess failures
            # must never be able to produce a false "target unreachable"
            # conclusion about a target that already responded successfully
            # to the real request.
            if is_original:
                LOGGER.warning(f"Submitted URL unreachable, stopping detection: {last_error}")
                signals.append({
                    "type": "early_termination",
                    "reason": "The submitted URL itself could not be reached",
                    "last_error": last_error,
                })
                break
            consecutive_network_errors += 1
            if consecutive_network_errors >= MAX_CONSECUTIVE_NETWORK_ERRORS:
                LOGGER.info(
                    f"Stopping common-path guessing after {consecutive_network_errors} consecutive "
                    f"failures (the submitted URL itself was already reachable)."
                )
                signals.append({
                    "type": "guess_probing_stopped",
                    "reason": (
                        f"{consecutive_network_errors} consecutive guessed-path failures — "
                        "stopping speculative probing, not because the target is unreachable"
                    ),
                })
                break
            continue

        probed_urls.append(candidate)
        redirect_chain = _build_redirect_chain(response)
        signals.append(
            {
                "type": "probe",
                "url": candidate,
                "status": str(response.status_code),
                "final_url": response.url or candidate,
                "guessed_path": str(not is_original),
            }
        )

        result = _classify_response(response, candidate)
        result.redirect_chain = redirect_chain

        # Add technology fingerprinting to enhance detection
        result = _enhance_with_tech_fingerprint(result, response, candidate, signals)

        if result.auth_type != "generic":
            if not is_original and not result.is_definitive:
                # A GUESSED common path (not the submitted URL) classified as
                # non-generic, but only on heuristic inference (URL looks
                # login-shaped, page has form-like fields) — not a verifiable
                # fact. Confirmed empirically: this scores IDENTICALLY
                # whether the guess is genuinely related to the submitted
                # URL (a bare domain root where /login really is the site's
                # login page) or coincidentally unrelated (a demo/testing
                # site where /login is a completely different exercise than
                # whatever page was actually submitted) — there is no HTTP
                # signal that tells them apart. Letting an unverifiable
                # guess fully override "generic" for the URL the operator
                # actually submitted produces a confident-looking WRONG
                # answer. Keep auth_type honest (generic) and surface the
                # finding as a side note instead of the headline result.
                signals.append({
                    "type": "unconfirmed_login_candidate",
                    "candidate_url": candidate,
                    "candidate_auth_type": result.auth_type,
                    "candidate_confidence": str(result.confidence),
                    "submitted_url": target_url,
                    "note": (
                        "A possible login page was found at a guessed common path, but this "
                        "is inference, not a verified fact, and cannot be confirmed to relate "
                        "to the submitted URL. Not used as the primary classification."
                    ),
                })
                note = (
                    f"A possible login page was found at {candidate} "
                    f"({result.auth_type}, unconfirmed — not used as the primary "
                    f"classification since it can't be confirmed to relate to the "
                    f"submitted URL). Review manually if relevant."
                )
                if fallback_result is not None:
                    # Enrich the result already captured from the submitted
                    # URL's own (generic) response — don't fabricate a new
                    # one, which would lose its real final_url/evidence.
                    fallback_result.evidence = (
                        f"{fallback_result.evidence or ''} {note}".strip()
                    )
                else:
                    # Submitted URL itself errored out before classification
                    # (shouldn't normally happen, since it's always probed
                    # first) — still don't lose this finding.
                    fallback_result = AuthDetectionResult(
                        auth_type="generic",
                        final_url=target_url,
                        evidence=note,
                        confidence=30,
                        tech_fingerprint=result.tech_fingerprint,
                    )
                # Stop here rather than probing the remaining guesses too —
                # DISCOVERY_PATHS has 16 candidates (8 paths x 2 for hash
                # routes) and most real sites' /login, /signin, /sign-in
                # etc. all point at the same actual page, so continuing
                # would just pile up near-duplicate notes for the same
                # finding instead of adding anything useful. Matches this
                # function's existing "first match wins" design elsewhere.
                break
            if not is_original:
                # Guess backed by a verifiable fact (e.g. an actual
                # WWW-Authenticate header at the guessed path) — real
                # evidence about that path regardless of whether it relates
                # to the submitted URL, so it's worth surfacing, but still
                # discounted and labeled since it's about a different URL
                # than the one submitted.
                result.confidence = max(0, int(result.confidence * 0.7))
                result.evidence = (
                    f"[Based on a guessed common path ({candidate}), not the "
                    f"submitted URL — treat with reduced confidence] {result.evidence or ''}"
                ).strip()
                signals.append({
                    "type": "guessed_path_classification",
                    "guessed_url": candidate,
                    "submitted_url": target_url,
                    "note": "Classification derived from a probed common path, not the operator's own URL.",
                })
            result.probed_urls = probed_urls
            return _finalize_detection_result(result, signals, hint_decision, login_hint)

        fallback_result = result

    # If we got "generic" result and browser detection is enabled, retry with browser
    if fallback_result and fallback_result.auth_type == "generic" and use_browser:
        try:
            browser_result = _detect_with_browser(target_url)
            if browser_result and browser_result.auth_type != "generic":
                browser_result.probed_urls = probed_urls
                # Tech fingerprint was likely captured in browser detection, preserve it
                if fallback_result.tech_fingerprint and not browser_result.tech_fingerprint:
                    browser_result.tech_fingerprint = fallback_result.tech_fingerprint
                return _finalize_detection_result(browser_result, signals, hint_decision, login_hint)
        except Exception as e:
            LOGGER.warning(f"Browser-based detection failed: {e}")

    if fallback_result:
        fallback_result.probed_urls = probed_urls
        if last_error and not fallback_result.error:
            fallback_result.error = last_error
        return _finalize_detection_result(fallback_result, signals, hint_decision, login_hint)

    result = AuthDetectionResult(
        auth_type="unknown",
        final_url=None,
        evidence=None,
        error=last_error or "Unable to detect authentication flow",
        signals=signals,
        redirect_chain=[],
        probed_urls=probed_urls,
        confidence=0,
    )
    return _finalize_detection_result(result, signals, hint_decision, login_hint)


def _finalize_detection_result(
    result: AuthDetectionResult,
    signals: list[dict[str, str]],
    hint_decision: HintDecision | None,
    login_hint: str | None,
) -> AuthDetectionResult:
    if hint_decision:
        forced = result.auth_type in {"generic", "unknown"} or hint_decision.force
        signals.append(
            {
                "type": "hint_applied" if forced else "hint_reference",
                "hint": (login_hint or "").strip(),
                "profile": hint_decision.profile.profile_id,
                "auth_type": hint_decision.auth_type,
            }
        )
        if forced:
            result.auth_type = hint_decision.auth_type
            result.evidence = hint_decision.reason
            result.confidence = max(result.confidence, hint_decision.confidence)
            result.detection_method = "hint"
    result.signals = signals
    return result


def _safe_body_text(response: Response) -> str | None:
    content_type = response.headers.get("Content-Type", "").lower()
    if "text/html" not in content_type and "application/xhtml+xml" not in content_type:
        return None
    try:
        response.encoding = response.encoding or "utf-8"
        return response.text
    except Exception:  # pragma: no cover - defensive
        return None


def _contains_any(haystack: str, needles: Iterable[str]) -> bool:
    return any(needle in haystack for needle in needles)


def _build_candidate_urls(target_url: str) -> list[tuple[str, bool]]:
    """
    Returns (url, is_original_target) pairs. The caller MUST use this flag —
    a classification based on a guessed common path (e.g. a site that
    happens to also host an unrelated /login demo page) is materially less
    trustworthy evidence about the URL the operator actually submitted than
    a classification based on that URL directly, and must never be allowed
    to look identical to it.
    """
    parsed = urlparse(target_url)
    scheme = parsed.scheme or "http"
    netloc = parsed.netloc or parsed.path  # Handles bare domains
    base = f"{scheme}://{netloc}"
    candidates: list[tuple[str, bool]] = []
    seen: set[str] = set()

    def _add(url: str, is_original: bool) -> None:
        normalized = url.rstrip("/") or base
        if normalized not in seen:
            candidates.append((url, is_original))
            seen.add(normalized)

    original = target_url
    if not parsed.netloc and parsed.path:
        original = f"{scheme}://{parsed.path}"
    _add(original, True)

    # Add standard path-based routes
    for path in DISCOVERY_PATHS:
        candidate = urljoin(base + "/", path.lstrip("/"))
        _add(candidate, False)

    # Add hash-based routes for SPAs (React, Vue, Angular)
    # These apps use client-side routing with #/route syntax
    for path in DISCOVERY_PATHS:
        hash_route = f"{base}/#{path}"
        _add(hash_route, False)

    return candidates


def _build_redirect_chain(response: Response) -> list[str]:
    chain = [hop.url for hop in response.history if hop.url] if response.history else []
    if response.url:
        chain.append(response.url)
    return chain


def _enhance_with_tech_fingerprint(
    result: AuthDetectionResult,
    response: Response,
    target_url: str,
    signals: list[dict[str, str]],
) -> AuthDetectionResult:
    """
    Enhance auth detection with technology fingerprinting.

    Phase 3: Tech fingerprint signals are now integrated into scoring matrix
    in _classify_response(). This function just adds telemetry signals for
    the timeline, reusing tech_data already captured during classification.
    """
    try:
        # Reuse tech_data from _classify_response if available
        tech_data = result.tech_fingerprint

        # If not available (shouldn't happen), run fingerprinting
        if not tech_data:
            body = _safe_body_text(response)
            if not body:
                return result

            tech_data = analyze_tech_fingerprint(
                target_url,
                html_samples=[body],
                cookies=None,
                timeout=3.0
            )

            if not tech_data:
                return result

            # Store tech fingerprint in result
            result.tech_fingerprint = tech_data

        # Extract key indicators for telemetry signals
        frameworks = tech_data.get("js_frameworks", [])
        cms = tech_data.get("cms", [])
        auth_cookies = tech_data.get("auth_cookies", [])

        if frameworks or cms:
            signals.append({
                "type": "tech_fingerprint",
                "frameworks": ",".join(frameworks) if frameworks else "none",
                "cms": ",".join(cms) if cms else "none",
                "observations": "; ".join(tech_data.get("observations", [])),
            })

        # SPA Framework Detection → Add telemetry signal
        spa_frameworks = {"React", "Angular", "Vue.js", "Svelte", "Ember.js"}
        detected_spa_frameworks = [f for f in frameworks if f in spa_frameworks]

        if detected_spa_frameworks:
            signals.append({
                "type": "spa_detected",
                "frameworks": ",".join(detected_spa_frameworks),
                "recommendation": "Consider browser-based detection for JavaScript-rendered content",
            })

            # If we classified as generic but SPA detected, suggest browser detection
            if result.auth_type == "generic":
                result.evidence = (result.evidence or "") + f" [SPA framework detected: {', '.join(detected_spa_frameworks)}]"
                LOGGER.info(f"SPA framework detected ({detected_spa_frameworks}) - may need browser-based detection")

        # Add auth cookie telemetry
        if auth_cookies:
            signals.append({
                "type": "auth_cookies_found",
                "cookies": ",".join(auth_cookies[:5]),  # First 5 cookies
                "count": str(len(auth_cookies)),
            })

    except Exception as e:
        LOGGER.debug(f"Tech fingerprinting failed: {e}", exc_info=True)
        # Don't fail detection if fingerprinting fails

    return result


def _classify_response(response: Response, fallback_url: str) -> AuthDetectionResult:
    """
    Classify authentication type using weighted scoring matrix.

    Replaced hardcoded if/else logic with evidence-based scoring system (Phase 3).
    All signals are collected and scored, then the highest scoring auth type wins.
    """
    final_url = response.url or fallback_url
    matrix = ScoringMatrix()

    # Extract headers from redirect chain
    header_sources: Iterable[Response] = list(response.history) + [response]
    history_headers = [hop.headers for hop in response.history] if response.history else []

    # Build redirect chain for URL analysis
    redirect_chain = _build_redirect_chain(response)

    # Signal collection phase: gather all signals from different sources

    # 1. Analyze HTTP headers (WWW-Authenticate, Set-Cookie, Location, CSP)
    header_signals = analyze_headers_for_signals(
        response_headers=dict(response.headers),
        history_headers=[dict(h) for h in history_headers] if history_headers else None
    )
    for signal in header_signals:
        matrix.add_signal(signal)

    # 2. Analyze URL patterns and redirect chains
    url_signals = analyze_url_for_signals(
        url=final_url,
        redirect_chain=redirect_chain
    )
    for signal in url_signals:
        matrix.add_signal(signal)

    # 3. Analyze HTML content
    body = _safe_body_text(response)
    tech_data = None  # Initialize before HTML analysis to prevent UnboundLocalError
    if body:
        html_signals = analyze_html_for_signals(html=body, url=final_url)
        for signal in html_signals:
            matrix.add_signal(signal)

        # 4. Analyze tech fingerprint (Phase 1 integration)
        try:
            tech_data = analyze_tech_fingerprint(
                final_url,
                html_samples=[body],
                cookies=None,  # Could extract from response.cookies
                timeout=3.0
            )

            if tech_data:
                tech_signals = analyze_tech_fingerprint_for_signals(tech_data)
                for signal in tech_signals:
                    matrix.add_signal(signal)
        except Exception as e:
            LOGGER.debug(f"Tech fingerprinting failed during classification: {e}")

    # Get best match from scoring matrix
    best_match = matrix.get_best_match(threshold=30)

    if best_match:
        auth_type, confidence, signals = best_match

        # Build evidence string from signals
        evidence_parts = [s.evidence for s in signals[:3]]  # Top 3 signals
        evidence = "; ".join(evidence_parts)

        LOGGER.info(
            f"Classification: {auth_type} (confidence={confidence}%, "
            f"signals={len(signals)}, scores={matrix.get_all_scores()})"
        )

        result = AuthDetectionResult(
            auth_type=auth_type,
            final_url=final_url,
            evidence=evidence,
            confidence=confidence,
            tech_fingerprint=tech_data,  # Store tech data to avoid re-running
            # A verifiable fact (an actual auth challenge header exists) vs.
            # pure heuristic inference (a URL looks login-shaped, a page has
            # form-like fields). This distinction only matters when the
            # candidate being classified is a guessed common path rather
            # than the submitted URL — see detect_auth_type's main loop.
            is_definitive=any(s.weight >= WEIGHT_DEFINITIVE for s in signals),
        )
        return result

    # No auth type scored above threshold - return generic, but don't discard
    # what we did find. A near-miss (e.g. 25/30) and total silence look
    # identical to a flat "generic" otherwise, which gives a human or the
    # ai_fallback/MCP-assisted path nothing to work from when detection
    # fails. Surface the closest candidate as a sub-threshold hint instead.
    all_scores = matrix.get_all_scores()
    LOGGER.info(f"No auth type scored above threshold, returning generic (scores={all_scores})")

    evidence = "No explicit authentication markers detected (scored below threshold)"
    if all_scores:
        near_miss_type, near_miss_score = max(all_scores.items(), key=lambda item: item[1])
        if near_miss_score > 0:
            evidence = (
                f"No auth type reached the confidence threshold. Closest candidate: "
                f"{near_miss_type} (score {near_miss_score}/30 needed) — "
                f"{evidence}"
            )

    result = AuthDetectionResult(
        auth_type="generic",
        final_url=final_url,
        evidence=evidence,
        confidence=30,
        tech_fingerprint=tech_data,  # Store tech data even for generic
    )
    return result


def _detect_with_browser(target_url: str) -> AuthDetectionResult | None:
    """
    Browser-based detection for JavaScript-rendered content (SPAs).
    Falls back to this when HTTP detection returns "generic".

    Uses smart waiting to handle React, Vue, Angular apps that take time to render.
    """
    try:
        from selenium import webdriver
        from selenium.webdriver.common.by import By
        from selenium.webdriver.support.ui import WebDriverWait
        from selenium.webdriver.support import expected_conditions as EC
        from selenium.common.exceptions import TimeoutException
        import time

        # Import browser setup from automation module
        try:
            from app.services.automation.browser import create_chrome_options, create_webdriver
        except ImportError:
            # Fallback if automation module not available
            options = webdriver.ChromeOptions()
            options.add_argument("--headless")
            options.add_argument("--no-sandbox")
            driver = webdriver.Chrome(options=options)
        else:
            options = create_chrome_options(headless=True)
            driver = create_webdriver(options)

        try:
            driver.set_page_load_timeout(20)  # Increased for SPAs
            driver.get(target_url)

            # Wait for password field to appear (smart waiting for SPAs)
            # Most SPAs render the login form within 10 seconds
            try:
                WebDriverWait(driver, 10).until(
                    EC.presence_of_element_located((By.CSS_SELECTOR, "input[type='password']"))
                )
                LOGGER.info("Password field detected via smart waiting")
            except TimeoutException:
                # No password field appeared, fall back to fixed wait for other content
                time.sleep(3)
                LOGGER.info("No password field found, checking for other auth indicators")

            # Get rendered HTML
            html = driver.page_source.lower()
            current_url = driver.current_url.lower()

            # Check for password fields (most reliable indicator)
            try:
                password_fields = driver.find_elements(By.CSS_SELECTOR, "input[type='password']")
                username_fields = driver.find_elements(By.CSS_SELECTOR,
                    "input[type='email'], input[type='text'], input[name*='user'], input[name*='email']")

                if password_fields:
                    if username_fields and len(username_fields) > 0 and len(password_fields) > 0:
                        # Wait a bit more to ensure form is fully rendered
                        time.sleep(0.5)

                        # Check if both are visible (single-step form)
                        try:
                            if password_fields[0].is_displayed() and username_fields[0].is_displayed():
                                return AuthDetectionResult(
                                    auth_type="form_based",
                                    final_url=driver.current_url,
                                    evidence="JavaScript-rendered SPA form with username and password fields",
                                    confidence=90,
                                    detection_method="browser",
                                )
                        except Exception:
                            # Element might be stale, still likely a form
                            return AuthDetectionResult(
                                auth_type="form_based",
                                final_url=driver.current_url,
                                evidence="JavaScript-rendered form detected (visibility check failed but fields exist)",
                                confidence=80,
                                detection_method="browser",
                            )

                        # Two-step form (password exists but not visible)
                        return AuthDetectionResult(
                            auth_type="two_step_form",
                            final_url=driver.current_url,
                            evidence="JavaScript-rendered two-step form (SPA)",
                            confidence=85,
                            detection_method="browser",
                        )

                # No password field found, but username field exists
                # This is likely step 1 of a two-step flow (username → continue → password)
                elif username_fields and len(username_fields) > 0:
                    # Check for "Continue", "Next", or similar buttons (not "Submit"/"Sign In")
                    try:
                        buttons = driver.find_elements(By.CSS_SELECTOR,
                            "button, input[type='submit'], input[type='button'], a[role='button']")
                        button_texts = []
                        for btn in buttons:
                            text = (btn.text or "").lower()
                            value = (btn.get_attribute("value") or "").lower()
                            aria_label = (btn.get_attribute("aria-label") or "").lower()
                            button_texts.extend([text, value, aria_label])

                        # Strong indicators of two-step flow
                        two_step_keywords = ["continue", "next", "proceed"]
                        if any(keyword in " ".join(button_texts) for keyword in two_step_keywords):
                            return AuthDetectionResult(
                                auth_type="two_step_form",
                                final_url=driver.current_url,
                                evidence="Username-only form with Continue/Next button (two-step authentication)",
                                confidence=88,
                                detection_method="browser",
                            )
                    except Exception:
                        pass

                    # Generic username-only page (likely two-step)
                    return AuthDetectionResult(
                        auth_type="two_step_form",
                        final_url=driver.current_url,
                        evidence="Username field without password field (likely two-step authentication)",
                        confidence=75,
                        detection_method="browser",
                    )

            except Exception as e:
                LOGGER.debug(f"Error checking form fields: {e}")

            # Check URL for OAuth/SSO indicators
            if "oauth" in current_url or "authorize" in current_url:
                return AuthDetectionResult(
                    auth_type="oauth",
                    final_url=driver.current_url,
                    evidence="OAuth flow detected via browser",
                    confidence=88,
                    detection_method="browser",
                )

            return None

        finally:
            driver.quit()

    except Exception as e:
        LOGGER.warning(f"Browser detection failed: {e}")
        return None


def enhance_with_har_insights(
    result: AuthDetectionResult,
    har_bytes: bytes | None,
    signals: list[dict[str, str]] | None = None,
) -> AuthDetectionResult:
    """
    Enhance auth detection result with HAR analysis insights.

    This function should be called AFTER Playwright automation completes and HAR
    data is available. It extracts network intelligence that can:
    - Validate/adjust the detected auth type
    - Identify API-first flows missed by HTML analysis
    - Detect multi-step authentication patterns
    - Capture actual endpoints used (not just guessed)

    Args:
        result: Initial AuthDetectionResult from detect_auth_type()
        har_bytes: HAR file bytes captured by Playwright
        signals: Optional signals list to append HAR insights to

    Returns:
        Enhanced AuthDetectionResult with har_insights populated
    """
    if not har_bytes:
        return result

    if signals is None:
        signals = result.signals or []

    try:
        # Parse HAR and extract auth intelligence
        insight = analyze_har(har_bytes)

        if not insight:
            LOGGER.debug("HAR analysis produced no insights")
            return result

        # Store full insights in result
        result.har_insights = {
            "login_endpoints": insight.login_endpoints,
            "logout_endpoints": insight.logout_endpoints,
            "api_endpoints": insight.api_endpoints,
            "successful_posts": [
                {"url": p["url"], "status": p["status"]}
                for p in insight.successful_posts[:5]  # Limit to first 5
            ],
            "has_api_auth": insight.has_api_auth,
            "has_multi_step": insight.has_multi_step,
            "has_session_refresh": insight.has_session_refresh,
            "total_requests": insight.total_requests,
            "auth_related_requests": insight.auth_related_requests,
        }

        # Add HAR summary signal
        signals.append({
            "type": "har_analysis",
            "total_requests": str(insight.total_requests),
            "auth_requests": str(insight.auth_related_requests),
            "login_endpoints": str(len(insight.login_endpoints)),
            "api_endpoints": str(len(insight.api_endpoints)),
        })

        # API-First Flow Detection
        if insight.has_api_auth and not insight.login_endpoints:
            signals.append({
                "type": "api_first_flow",
                "api_endpoints": ",".join(insight.api_endpoints[:3]),
                "recommendation": "API-first authentication detected (no form submission)",
            })

            # If we classified as form_based but HAR shows API-only, adjust
            if result.auth_type == "form_based":
                LOGGER.info("HAR shows API-first flow, but classified as form_based - keeping original")
                signals.append({
                    "type": "har_conflict",
                    "detected_type": result.auth_type,
                    "har_suggests": "api_based",
                    "note": "Keeping original classification but flagging discrepancy",
                })

        # Multi-Step Authentication Detection
        if insight.has_multi_step:
            signals.append({
                "type": "multi_step_detected",
                "successful_posts": str(len(insight.successful_posts)),
                "recommendation": "Multiple POST requests suggest multi-step flow (MFA, consent, etc.)",
            })

            # Boost confidence if we detected two_step_form
            if result.auth_type == "two_step_form":
                result.confidence = min(result.confidence + 15, 100)  # +15 confidence
                LOGGER.info("HAR confirms multi-step flow, boosting confidence")

        # Session Refresh Detection
        if insight.has_session_refresh:
            signals.append({
                "type": "session_refresh_detected",
                "recommendation": "Token refresh endpoint found - session management active",
            })

        # Primary Endpoint Extraction
        primary_endpoint = get_primary_auth_endpoint(insight)
        if primary_endpoint:
            signals.append({
                "type": "primary_auth_endpoint",
                "endpoint": primary_endpoint,
                "note": "Most likely authentication endpoint from HAR analysis",
            })

        # Cookie Intelligence
        if insight.cookies_set:
            auth_related_cookies = [
                c for c in insight.cookies_set
                if any(keyword in c.get("name", "").lower()
                       for keyword in ["auth", "session", "token", "sid", "jwt"])
            ]

            if auth_related_cookies:
                signals.append({
                    "type": "auth_cookies_set",
                    "count": str(len(auth_related_cookies)),
                    "cookies": ",".join(c["name"] for c in auth_related_cookies[:5]),
                    "secure": str(sum(1 for c in auth_related_cookies if c.get("secure", False))),
                    "httpOnly": str(sum(1 for c in auth_related_cookies if c.get("httpOnly", False))),
                })

        # WWW-Authenticate / Authorization Headers
        if insight.auth_headers:
            for auth_header in insight.auth_headers[:5]:  # Limit to first 5
                signals.append({
                    "type": "auth_header_detected",
                    "header": auth_header["header_type"],
                    "direction": auth_header["direction"],
                    "url": auth_header["url"][:80],  # Truncate URL
                })

        # Update result signals
        result.signals = signals

        LOGGER.info(
            f"HAR insights: {len(insight.login_endpoints)} login endpoints, "
            f"{len(insight.api_endpoints)} API endpoints, "
            f"multi-step={insight.has_multi_step}"
        )

    except Exception as e:
        LOGGER.warning(f"HAR enhancement failed: {e}", exc_info=True)
        # Don't fail if HAR analysis fails

    return result
