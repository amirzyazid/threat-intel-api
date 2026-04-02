from urllib.parse import urlparse
import re


def extract_domain_from_url(url_input: str) -> str:
    """
    Extract domain/hostname from various URL formats.

    Handles:
    - Full URLs: https://example.com/path?query=1
    - Domains: example.com
    - Subdomains: subdomain.example.com
    - With ports: example.com:8080

    Args:
        url_input: URL or domain string

    Returns:
        str: Extracted domain without scheme, path, or port

    Raises:
        ValueError: If input cannot be parsed as valid domain/URL
    """
    url_input = url_input.strip()

    # Check if input looks like a URL with scheme
    if "://" in url_input:
        try:
            parsed = urlparse(url_input)
            netloc = parsed.netloc
        except Exception as e:
            raise ValueError(f"Failed to parse URL: {url_input}") from e
    else:
        # Assume it's a domain or domain:port
        netloc = url_input

    # Remove port if present
    if ":" in netloc:
        domain = netloc.rsplit(":", 1)[0]
    else:
        domain = netloc

    # Validate domain format
    if not _is_valid_domain(domain):
        raise ValueError(f"Invalid domain format: {domain}")

    return domain.lower()


def _is_valid_domain(domain: str) -> bool:
    """
    Validate if string is a valid domain name.

    Args:
        domain: Domain string to validate

    Returns:
        bool: True if valid domain format
    """
    # Basic domain validation pattern
    # Allows: letters, digits, hyphens, dots
    # TLD must be at least 2 characters
    pattern = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"

    if not re.match(pattern, domain):
        return False

    # Additional checks
    if domain.startswith("-") or domain.endswith("-"):
        return False

    if domain.startswith(".") or domain.endswith("."):
        return False

    if ".." in domain:
        return False

    if len(domain) > 253:
        return False

    return True
