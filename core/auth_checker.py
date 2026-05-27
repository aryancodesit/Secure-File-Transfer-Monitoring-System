"""
core/auth_checker.py
--------------------
Phase 4 — Authorisation Check & Violation Flagging.

Runs four checks on every EventRecord. Each check independently evaluates the
event and produces a (severity, reason) result. The highest-severity finding
is stamped onto the record. If any check fires, record.is_violation = True.

Check order (escalating severity):
  1. LOW      — file moved to an unrecognised / unknown destination type
  2. MEDIUM   — acting user is not on the whitelist
  3. HIGH     — file transferred to a sensitive destination (USB, cloud, /tmp…)
  4. HIGH     — user exceeded the per-window file-transfer rate limit
  5. CRITICAL — integrity hash mismatch detected by Phase 3 (integrity_ok=False)

Design notes:
  - check_authorisation() is the single public entry point. It mutates the
    EventRecord in-place and returns nothing — consistent with other pipeline stages.
  - Rate limiting uses a collections.deque per user. Each entry is a timestamp.
    On every event the deque is pruned of entries older than RATE_WINDOW_SECONDS,
    then the length is compared to MAX_FILES_PER_WINDOW. No database needed.
  - The severity ladder is defined as a list so comparisons are O(1) index lookups
    and new levels can be inserted without changing comparison logic.
  - Deletions are NOT flagged as violations by default — removing files from the
    watched directory is treated as a cleanup action unless the user is unlisted.
    Adjust _SKIP_VIOLATION_EVENTS to change this policy.
"""

import threading
from collections import deque
from dataclasses import dataclass
from datetime import datetime
from typing import Optional

from config import settings
from core.watcher import EventRecord


# ─── Severity ladder ─────────────────────────────────────────────────────────

SEVERITY_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

def _severity_gte(a: str, b: str) -> bool:
    """Returns True if severity a is greater than or equal to b."""
    return SEVERITY_LEVELS.index(a) >= SEVERITY_LEVELS.index(b)

def _higher(a: Optional[str], b: str) -> str:
    """Returns whichever severity string is higher."""
    if a is None:
        return b
    return a if _severity_gte(a, b) else b


# ─── Violation result ─────────────────────────────────────────────────────────

@dataclass
class ViolationResult:
    is_violation: bool
    severity: str        # "LOW" | "MEDIUM" | "HIGH" | "CRITICAL"
    reason: str          # human-readable description for the log/alert


# ─── Rate-limit state ─────────────────────────────────────────────────────────
# { username: deque([datetime, datetime, ...]) }  — one deque per user

_rate_state: dict[str, deque] = {}
_rate_lock = threading.Lock()


def _check_rate(username: str, now: datetime) -> Optional[ViolationResult]:
    """
    Returns a HIGH violation if the user has exceeded MAX_FILES_PER_WINDOW
    events within the last RATE_WINDOW_SECONDS seconds, otherwise None.
    """
    window   = settings.RATE_WINDOW_SECONDS
    max_hits = settings.MAX_FILES_PER_WINDOW

    with _rate_lock:
        if username not in _rate_state:
            _rate_state[username] = deque()

        dq = _rate_state[username]
        dq.append(now)

        # Prune events outside the time window
        cutoff = now.timestamp() - window
        while dq and dq[0].timestamp() < cutoff:
            dq.popleft()

        count = len(dq)

    if count > max_hits:
        return ViolationResult(
            is_violation=True,
            severity="HIGH",
            reason=(
                f"Rate limit exceeded: {count} file events in {window}s "
                f"(threshold={max_hits})"
            ),
        )
    return None


# ─── Individual checks ────────────────────────────────────────────────────────

def _check_user(username: str) -> Optional[ViolationResult]:
    """MEDIUM — user not in whitelist."""
    whitelist = {u.lower() for u in settings.WHITELIST_USERS}
    if username.lower() not in whitelist:
        return ViolationResult(
            is_violation=True,
            severity="MEDIUM",
            reason=f"Unlisted user '{username}' performed a file transfer",
        )
    return None


def _check_destination(dest_path: Optional[str], dest_type: str) -> Optional[ViolationResult]:
    """
    HIGH  — destination path contains a sensitive fragment (USB, cloud, /tmp…).
    LOW   — dest_type is 'n/a' (no destination captured, unknown target).
    """
    if not dest_path:
        return None

    p = dest_path.lower()
    for fragment in settings.SENSITIVE_DESTINATIONS:
        if fragment.lower() in p:
            return ViolationResult(
                is_violation=True,
                severity="HIGH",
                reason=(
                    f"File transferred to sensitive destination "
                    f"[{dest_type}]: {dest_path}"
                ),
            )

    if dest_type == "n/a":
        return ViolationResult(
            is_violation=True,
            severity="LOW",
            reason=f"File moved to unrecognised destination: {dest_path}",
        )

    return None


def _check_integrity(integrity_ok: Optional[bool], src_path: str) -> Optional[ViolationResult]:
    """CRITICAL — Phase 3 detected a hash mismatch."""
    if integrity_ok is False:
        return ViolationResult(
            is_violation=True,
            severity="CRITICAL",
            reason=f"Integrity hash mismatch — possible tampering: {src_path}",
        )
    return None


# ─── Events that skip certain checks ─────────────────────────────────────────

# Deletions are exempt from destination and rate checks —
# removing a file is treated as cleanup, not exfiltration.
# User-whitelist and integrity checks still apply to deletions.
_SKIP_DESTINATION_CHECK = {"deleted"}
_SKIP_RATE_CHECK         = {"deleted"}


# ─── Colour helpers ───────────────────────────────────────────────────────────

_SEV_COLOUR = {
    "LOW":      "\033[93m",   # yellow
    "MEDIUM":   "\033[93m",   # yellow
    "HIGH":     "\033[91m",   # red
    "CRITICAL": "\033[91m\033[1m",  # bold red
}
_RESET = "\033[0m"

def _c(text: str, sev: str) -> str:
    if not settings.USE_COLOUR:
        return text
    return f"{_SEV_COLOUR.get(sev, '')}{text}{_RESET}"


# ─── Public pipeline function ─────────────────────────────────────────────────

def check_authorisation(record: EventRecord) -> None:
    """
    Phase 4 pipeline stage.

    Runs all applicable checks for the event type. Combines results by taking
    the highest severity. Stamps record.is_violation, record.severity, and
    record.violation_reason in-place.

    Multiple violations are joined with ' | ' in violation_reason so the full
    picture is preserved in the CSV/alert even when only one severity is shown.

    Args:
        record: EventRecord enriched by classifier (Phase 2) and hasher (Phase 3).
                Mutated in-place.
    """
    findings: list[ViolationResult] = []
    now = record.timestamp

    # ── Run each check ────────────────────────────────────────────────────────

    # 1. Integrity check (always runs — applies to all event types)
    r = _check_integrity(record.integrity_ok, record.src_path)
    if r:
        findings.append(r)

    # 2. User whitelist check (always runs)
    r = _check_user(record.username)
    if r:
        findings.append(r)

    # 3. Destination sensitivity check (skipped for deletions)
    if record.event_type not in _SKIP_DESTINATION_CHECK:
        r = _check_destination(record.dest_path, record.dest_type)
        if r:
            findings.append(r)

    # 4. Rate limit check (skipped for deletions)
    if record.event_type not in _SKIP_RATE_CHECK:
        r = _check_rate(record.username, now)
        if r:
            findings.append(r)

    # ── Combine findings ──────────────────────────────────────────────────────

    if not findings:
        record.is_violation    = False
        record.severity        = ""
        record.violation_reason = ""
        return

    # Highest severity wins; all reasons are preserved
    top_severity = findings[0].severity
    for f in findings[1:]:
        top_severity = _higher(top_severity, f.severity)

    record.is_violation     = True
    record.severity         = top_severity
    record.violation_reason = " | ".join(f.reason for f in findings)

    # ── Console output ────────────────────────────────────────────────────────

    if settings.VERBOSE_CONSOLE:
        checks_str = "  +  ".join(
            f"{_c(f.severity, f.severity)}: {f.reason[:60]}" for f in findings
        )
        print(f"         ↳ auth    │ {checks_str}")
