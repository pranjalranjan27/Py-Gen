"""
email_generator.py — Email address generation logic.

Supports two modes:
  - Random: fully random alphanumeric usernames
  - Name-based: realistic usernames from name pools or custom input
"""

import random
import string

from utils.constants import FIRST_NAMES, LAST_NAMES


def generate_random_email(length, domain, include_digits=True):
    """
    Generate a completely random email address.

    Args:
        length:         Length of the random username portion.
        domain:         Email domain string (e.g. "@gmail.com").
        include_digits: Whether to include digits in the username.

    Returns:
        A randomly generated email string.
    """
    chars = string.ascii_lowercase
    if include_digits:
        chars += string.digits

    username = "".join(random.choice(chars) for _ in range(length))
    return username + domain


def generate_name_based_email(domain, use_dot=True, add_numbers=True, custom_first="", custom_last=""):
    """
    Generate a name-based email address.

    Uses custom names if provided, otherwise picks from the built-in pools.
    Applies a random formatting pattern and optionally appends numbers.

    Args:
        domain:       Email domain string (e.g. "@gmail.com").
        use_dot:      (Reserved) Whether to prefer dot-separated formats.
        add_numbers:  Whether to append a random number suffix.
        custom_first: Optional custom first name override.
        custom_last:  Optional custom last name override.

    Returns:
        A name-based email string.
    """
    first = custom_first.lower().strip() if custom_first.strip() else random.choice(FIRST_NAMES)
    last = custom_last.lower().strip() if custom_last.strip() else random.choice(LAST_NAMES)

    first = ''.join(c for c in first if c.isalnum())
    last = ''.join(c for c in last if c.isalnum())

    if not first:
        first = random.choice(FIRST_NAMES)
    if not last:
        last = random.choice(LAST_NAMES)

    formats = [
        f"{first}{last}",
        f"{first}.{last}",
        f"{first}_{last}",
        f"{first[0]}{last}",
        f"{first}{last[0]}",
        f"{last}{first}",
        f"{last}.{first}",
        f"{first}{last[:3]}",
    ]

    username = random.choice(formats)

    if add_numbers:
        num_style = random.choice([
            str(random.randint(1, 99)),
            str(random.randint(100, 999)),
            str(random.randint(1990, 2010)),
            str(random.randint(1, 9)) + str(random.randint(1, 9)),
        ])
        username += num_style

    return username + domain
