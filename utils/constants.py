"""
constants.py — All shared data constants used across the application.

Includes character sets, email domains, and name pools.
"""

import string

# ─── Password Character Sets ─────────────────────────────────────────

CHARSETS = (
    ("lowercase", string.ascii_lowercase),
    ("uppercase", string.ascii_uppercase),
    ("digits", string.digits),
    ("symbols", "!@#$%^&*()-_=+[]{}<>?/"),
)

AMBIGUOUS = set("l1I0O")

# ─── Email Domains ───────────────────────────────────────────────────

EMAIL_DOMAINS = [
    "@gmail.com",
    "@yahoo.com",
    "@hotmail.com",
    "@outlook.com",
    "@edu.in",
    "Custom..."
]

# ─── Name Pools (for name-based email generation) ────────────────────

FIRST_NAMES = [
    "pranjal", "samar", "aman", "aditya", "mike", "naitik", "nikhil", "simran", 
    "deepak", "maaya", "jatin", "abhishek", "robert", "eshita", "william",
    "osil", "shekhar", "shikha", "suraksha", "ruchi", "akshara", "divya",
    "aniket", "khushi", "satish", "akriti", "rehan", "hopper", "kunal",
    "kuldeep", "brian", "grace", "jason", "chloe", "peter", "victoria"
]

LAST_NAMES = [
    "kumar", "singh", "kumari", "yadav", "raj", "sharma", "srivastav",
    "jha", "pathak", "thakur", "anand", "taylor", "kohli",
    "chawla", "luthra", "khan", "lee", "chauhan", "suryavanshi", "kapoor",
    "rathore", "lewis", "harrington", "wheeler", "byers", "allen", "king",
    "wright", "scott", "solanki", "shukla", "hill", "flores", "green"
]
