"""
config/settings.py
------------------
Central configuration for SFTMS.
Edit this file to adapt the monitor to your environment.
Secrets (SMTP password, etc.) are loaded from environment variables — never hardcoded here.
"""

import os
from pathlib import Path

# ─── Paths ────────────────────────────────────────────────────────────────────

# Root directory of the project (two levels up from this file)
BASE_DIR = Path(__file__).resolve().parent.parent

# Directory to watch — change to the real target path in production
WATCH_PATH = str(BASE_DIR / "test_watch")

# Where logs and data files are written
DATA_DIR = str(BASE_DIR / "data")
LOG_FILE = os.path.join(DATA_DIR, "transfer_log.csv")
VIOLATIONS_FILE = os.path.join(DATA_DIR, "violations.csv")
BASELINE_FILE = os.path.join(DATA_DIR, "baseline_hashes.json")

# Where generated reports are saved
REPORTS_DIR = str(BASE_DIR / "reports")

# ─── Monitoring settings ──────────────────────────────────────────────────────

# Watch subdirectories recursively
WATCH_RECURSIVE = True

# File extensions to ignore completely (temp files, OS artefacts)
IGNORED_EXTENSIONS = {".tmp", ".swp", ".DS_Store", "~", ".part"}

# ─── Access control ───────────────────────────────────────────────────────────

# Users permitted to transfer files without triggering a violation.
# Keep lowercase. In production, load from a database or LDAP instead.
WHITELIST_USERS = {
    "admin",
    "security_team",
}

# Destination path fragments considered sensitive.
# Any transfer whose destination contains one of these strings is flagged.
SENSITIVE_DESTINATIONS = [
    "/media/",       # removable media / USB drives
    "/mnt/usb",      # mounted USB
    "/tmp/",         # temp directories
    "\\AppData\\Roaming",  # Windows roaming profile
    "dropbox",       # cloud sync folders
    "google drive",
    "onedrive",
]

# ─── Violation thresholds ─────────────────────────────────────────────────────

# Maximum files a single user may transfer within RATE_WINDOW_SECONDS
# before a rate-limit violation fires.
MAX_FILES_PER_WINDOW = 20
RATE_WINDOW_SECONDS = 60

# ─── Alert settings ───────────────────────────────────────────────────────────

# Minimum severity that triggers an email alert.
# Options: "LOW", "MEDIUM", "HIGH", "CRITICAL"
ALERT_SEVERITY_THRESHOLD = "MEDIUM"

# Seconds to wait before re-alerting the same user for the same issue.
ALERT_COOLDOWN_SECONDS = 60

# SMTP configuration — values come from environment variables.
SMTP_HOST = os.environ.get("SFTMS_SMTP_HOST", "smtp.gmail.com")
SMTP_PORT = int(os.environ.get("SFTMS_SMTP_PORT", "465"))
SMTP_USER = os.environ.get("SFTMS_SMTP_USER", "")
SMTP_PASSWORD = os.environ.get("SFTMS_SMTP_PASSWORD", "")
ALERT_RECIPIENT = os.environ.get("SFTMS_ALERT_RECIPIENT", "")

# ─── Logging / display ────────────────────────────────────────────────────────

# Print every event to console (useful during development, disable in production)
VERBOSE_CONSOLE = True

# Colour-code console output
USE_COLOUR = True
