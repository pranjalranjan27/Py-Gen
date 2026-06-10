"""
file_handler.py — Utility functions for saving generated data to files.

Handles writing passwords and emails to their respective text files
inside the 'data/' directory.
"""

import os
import time


# Resolve path relative to the project root (where app.py lives)
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_DATA_DIR = os.path.join(_PROJECT_ROOT, "data")


def _ensure_data_dir():
    """Create the data/ directory if it doesn't exist."""
    os.makedirs(_DATA_DIR, exist_ok=True)


def save_password(password, score, verdict):
    """
    Append a password entry to data/passwords.txt.

    Args:
        password: The generated password string.
        score:    Numeric strength score (0–100).
        verdict:  Human-readable strength verdict.

    Raises:
        OSError: If the file cannot be written.
    """
    _ensure_data_dir()
    filepath = os.path.join(_DATA_DIR, "passwords.txt")
    with open(filepath, "a", encoding="utf-8") as f:
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{ts}] {password}  |  score={score} verdict={verdict}\n")


def save_email(email, style):
    """
    Append an email entry to data/emails.txt.

    Args:
        email: The generated email string.
        style: Generation style used ("random" or "name").

    Raises:
        OSError: If the file cannot be written.
    """
    _ensure_data_dir()
    filepath = os.path.join(_DATA_DIR, "emails.txt")
    with open(filepath, "a", encoding="utf-8") as f:
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        f.write(f"[{ts}] {email}  |  type={style}\n")
