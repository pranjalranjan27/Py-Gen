"""
password_analyzer.py — Password strength analysis logic.

Evaluates a password's strength based on length, character diversity,
uniqueness, and produces a score with a human-readable verdict.
"""

from utils.constants import CHARSETS


def analyze_password(pwd):
    """
    Analyze password strength and return a detailed report.

    Args:
        pwd: The password string to analyze.

    Returns:
        A dict with keys: length, classes, unique, repeats, score, verdict, reasons.
    """
    length = len(pwd)

    classes = {
        "lower": any(c.islower() for c in pwd),
        "upper": any(c.isupper() for c in pwd),
        "digit": any(c.isdigit() for c in pwd),
        "symbol": any(c in CHARSETS[3][1] for c in pwd),
    }

    unique_chars = len(set(pwd))
    repeats = length - unique_chars

    score = 0
    reasons = []

    if length >= 16:
        score += 40
    elif length >= 12:
        score += 30
    elif length >= 8:
        score += 20
    else:
        score += 10
        reasons.append("Too short (< 8)")

    diversity = sum(classes.values())
    score += diversity * 15

    if diversity == 1:
        reasons.append("Only one character type")
    elif diversity == 2:
        reasons.append("Consider adding more types")
    elif diversity >= 3:
        reasons.append("Good variety")

    if repeats >= 4:
        score -= 15
        reasons.append("Too many repeated characters")

    score = max(0, min(100, score))

    if score >= 80:
        verdict = "Strong"
    elif score >= 60:
        verdict = "Good"
    elif score >= 40:
        verdict = "Fair"
        reasons.append("Low entropy, try mixing more characters")
    else:
        verdict = "Weak"

    return {
        "length": length,
        "classes": classes,
        "unique": unique_chars,
        "repeats": repeats,
        "score": score,
        "verdict": verdict,
        "reasons": reasons,
    }
