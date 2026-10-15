"""Username formatting utilities for handling domain prefixes."""


def format_username(username: str, domain_prefix: str | None = None) -> tuple[str, str, str]:
    """
    Format username with optional domain prefix.

    Returns tuple of (formatted_username, domain_backslash_format, domain_at_format)

    Examples:
        format_username("jdoe", "COMPANY")
        -> ("jdoe", "COMPANY\\jdoe", "jdoe@COMPANY")

        format_username("jdoe@example.com", None)
        -> ("jdoe@example.com", "jdoe@example.com", "jdoe@example.com")
    """
    original = username.strip()

    if not domain_prefix:
        return (original, original, original)

    domain = domain_prefix.strip()

    # If username already has domain format, return as-is
    if "\\" in original or "@" in original:
        return (original, original, original)

    # Generate both common formats
    backslash_format = f"{domain}\\{original}"
    at_format = f"{original}@{domain}"

    return (original, backslash_format, at_format)


def get_username_variants(username: str, domain_prefix: str | None = None) -> list[str]:
    """
    Get all username format variants to try.

    Returns list of username formats ordered by likelihood:
    1. Domain\\username (most common for enterprise)
    2. username@domain
    3. Plain username
    """
    plain, backslash, at_format = format_username(username, domain_prefix)

    if not domain_prefix:
        return [plain]

    # If already formatted, just return it
    if "\\" in username or "@" in username:
        return [username]

    # Try domain formats first (more likely for enterprise sites)
    return [backslash, at_format, plain]
