"""Selector format helpers shared by login handlers and playbook learning."""
from __future__ import annotations


def plain_css(selector: str | None) -> str | None:
    """A CSS selector usable with By.CSS_SELECTOR / page.locator.

    Handlers record Selenium IDE locators ("css=input#username") for .side
    files; playbooks need the bare CSS. Other IDE locator kinds (xpath=, id=,
    name=, linkText=) aren't CSS, so they're dropped rather than misused.
    """
    if not selector:
        return None
    value = selector.strip()
    if value.startswith("css="):
        return value[4:] or None
    head, sep, _ = value.partition("=")
    if sep and head.isalpha() and head in {"xpath", "id", "name", "linkText", "partialLinkText"}:
        return None
    return value
