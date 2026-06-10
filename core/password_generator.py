"""
password_generator.py — Password generation logic.

Provides functions to build a character pool from user options
and generate a random password from that pool.
"""

import random
import string

from utils.constants import AMBIGUOUS


def build_charset(use_lower, use_upper, use_digits, use_symbols, avoid_ambiguous):
    """
    Build a character pool based on selected options.

    Args:
        use_lower:       Include lowercase letters.
        use_upper:       Include uppercase letters.
        use_digits:      Include digits 0-9.
        use_symbols:     Include special symbols.
        avoid_ambiguous: Remove easily confused characters (l, 1, I, 0, O).

    Returns:
        A string of characters to choose from.
    """
    chars = []

    if use_lower:
        chars += list(string.ascii_lowercase)
    if use_upper:
        chars += list(string.ascii_uppercase)
    if use_digits:
        chars += list(string.digits)
    if use_symbols:
        chars += list("!@#$%^&*()-_=+[]{}<>?/")

    if avoid_ambiguous:
        chars = [c for c in chars if c not in AMBIGUOUS]

    if not chars:
        chars = list(string.ascii_lowercase)

    return "".join(chars)


def generate_password(length, pool):
    """
    Generate a random password of the given length from the character pool.

    Args:
        length: Desired password length (minimum 1; defaults to 8 if <= 0).
        pool:   String of characters to pick from.

    Returns:
        A randomly generated password string.
    """
    if length <= 0:
        length = 8
    return "".join(random.choice(pool) for _ in range(length))
