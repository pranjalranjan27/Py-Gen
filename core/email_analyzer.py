"""
email_analyzer.py — Email analysis logic.

Examines a generated email address and extracts properties
like username, domain, format type, and character composition.
"""

from utils.constants import FIRST_NAMES, LAST_NAMES


def analyze_email(email):
    """
    Analyze the generated email for various properties.

    Args:
        email: The email string to analyze.

    Returns:
        A dict with keys: total_length, username, domain, username_length,
        has_numbers, has_special, format_type.
    """
    info = {
        "total_length": len(email),
        "username": "",
        "domain": "",
        "username_length": 0,
        "has_numbers": False,
        "has_special": False,
        "format_type": "random",
    }

    if "@" in email:
        parts = email.split("@")
        info["username"] = parts[0]
        info["domain"] = "@" + parts[1]
        info["username_length"] = len(parts[0])
        info["has_numbers"] = any(c.isdigit() for c in parts[0])
        info["has_special"] = any(c in "._-" for c in parts[0])

        if "." in parts[0] or "_" in parts[0]:
            info["format_type"] = "name-based"
        elif any(name in parts[0].lower() for name in FIRST_NAMES + LAST_NAMES):
            info["format_type"] = "name-based"
        else:
            info["format_type"] = "random"

    return info
