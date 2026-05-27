"""
core/alert.py
-------------
Phase 5 — Alert Engine & Email Notifications.

Responsibilities:
  1. Receive a violation EventRecord and decide whether to send an alert,
     based on severity threshold and per-user cooldown.
  2. Format a structured plain-text email body with all relevant event details.
  3. Send the email via smtplib in a background daemon thread so the watchdog
     observer loop is never blocked by SMTP latency or failures.
  4. Maintain an in-memory alert log for the session (no disk I/O needed here —
     violations.csv already provides the persistent audit trail).

Severity gating:
  Only violations at or above ALERT_SEVERITY_THRESHOLD (default: MEDIUM) trigger
  an email. LOW violations are logged to CSV but do not send alerts.

Cooldown logic:
  A dict keyed by (username, severity) tracks the last alert time. If the same
  user triggers another violation of the same severity within ALERT_COOLDOWN_SECONDS
  the alert is suppressed. This prevents inbox flooding during burst events.

SMTP configuration:
  All credentials come from environment variables — never hardcoded.
  Supports both SSL (port 465) and STARTTLS (port 587) automatically.

  Gmail quick-start:
    export SFTMS_SMTP_HOST=smtp.gmail.com
    export SFTMS_SMTP_PORT=465
    export SFTMS_SMTP_USER=you@gmail.com
    export SFTMS_SMTP_PASSWORD=your_app_password   # not your account password
    export SFTMS_ALERT_RECIPIENT=security@yourorg.com

  Mailtrap sandbox (development):
    export SFTMS_SMTP_HOST=sandbox.smtp.mailtrap.io
    export SFTMS_SMTP_PORT=587
    export SFTMS_SMTP_USER=<mailtrap_user>
    export SFTMS_SMTP_PASSWORD=<mailtrap_password>
    export SFTMS_ALERT_RECIPIENT=test@test.com
"""

import smtplib
import threading
import traceback
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

from config import settings
from core.watcher import EventRecord


# ─── Severity ladder (mirrors auth_checker) ───────────────────────────────────

_SEVERITY_LEVELS = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]

def _severity_gte(a: str, b: str) -> bool:
    try:
        return _SEVERITY_LEVELS.index(a) >= _SEVERITY_LEVELS.index(b)
    except ValueError:
        return False


# ─── Cooldown state ───────────────────────────────────────────────────────────
# key: (username, severity) → datetime of last alert sent

_cooldown_state: dict[tuple, datetime] = {}
_cooldown_lock  = threading.Lock()


def _is_on_cooldown(username: str, severity: str, now: datetime) -> bool:
    """Returns True if this (user, severity) pair is still within cooldown."""
    key = (username.lower(), severity)
    with _cooldown_lock:
        last = _cooldown_state.get(key)
        if last is None:
            return False
        elapsed = (now - last).total_seconds()
        return elapsed < settings.ALERT_COOLDOWN_SECONDS


def _record_alert(username: str, severity: str, now: datetime) -> None:
    """Stamp the current time for this (user, severity) pair."""
    key = (username.lower(), severity)
    with _cooldown_lock:
        _cooldown_state[key] = now


# ─── Session alert log ────────────────────────────────────────────────────────
# Lightweight in-memory record of alerts sent this session.

_session_alerts: list[dict] = []
_session_lock   = threading.Lock()


def get_session_alerts() -> list[dict]:
    """Returns a copy of all alerts sent this session (for reporting)."""
    with _session_lock:
        return list(_session_alerts)


# ─── Email formatters ─────────────────────────────────────────────────────────

_SEV_LABELS = {
    "LOW":      "🔵 LOW",
    "MEDIUM":   "🟡 MEDIUM",
    "HIGH":     "🔴 HIGH",
    "CRITICAL": "🚨 CRITICAL",
}

_RECOMMENDED_ACTIONS = {
    "LOW":      "Monitor the situation. No immediate action required.",
    "MEDIUM":   "Investigate the user's recent activity and verify intent.",
    "HIGH":     "Review immediately. Consider locking the user account pending investigation.",
    "CRITICAL": "URGENT: Isolate the affected files. Preserve evidence. Escalate to security team.",
}


def _format_subject(record: EventRecord) -> str:
    label = _SEV_LABELS.get(record.severity, record.severity)
    return f"[SFTMS ALERT] {label} — {record.event_type.upper()}: {record.file_name}"


def _format_body(record: EventRecord) -> str:
    """Builds a structured plain-text email body from the EventRecord."""
    ts       = record.timestamp.strftime("%Y-%m-%d %H:%M:%S")
    dest     = record.dest_path or "—"
    size     = f"{record.file_size_kb} KB" if record.file_size_kb else "—"
    category = record.transfer_category or record.event_type
    integrity_str = (
        "FAIL ✗" if record.integrity_ok is False
        else "PASS ✓" if record.integrity_ok is True
        else "N/A"
    )
    action = _RECOMMENDED_ACTIONS.get(record.severity, "Review the event.")
    reasons = record.violation_reason.replace(" | ", "\n              ")

    body = f"""
╔══════════════════════════════════════════════════════════════╗
║        SFTMS — SECURITY ALERT NOTIFICATION                   ║
╚══════════════════════════════════════════════════════════════╝

Severity     : {_SEV_LABELS.get(record.severity, record.severity)}
Time         : {ts}
Event type   : {record.event_type.upper()} ({category})

──────────────────────────────────────────────────────────────
FILE DETAILS
──────────────────────────────────────────────────────────────
File name    : {record.file_name}
Extension    : {record.file_ext or "—"}
Source path  : {record.src_path}
Destination  : {dest}
Dest type    : {record.dest_type or "—"}
Size         : {size}

──────────────────────────────────────────────────────────────
USER & INTEGRITY
──────────────────────────────────────────────────────────────
Username     : {record.username}
Integrity    : {integrity_str}

──────────────────────────────────────────────────────────────
VIOLATION DETAILS
──────────────────────────────────────────────────────────────
Reason(s)    : {reasons}

──────────────────────────────────────────────────────────────
RECOMMENDED ACTION
──────────────────────────────────────────────────────────────
{action}

──────────────────────────────────────────────────────────────
This alert was generated automatically by the Secure File
Transfer Monitoring System (SFTMS). All events are logged to
transfer_log.csv and violations.csv for audit purposes.
""".strip()

    return body


# ─── SMTP send ────────────────────────────────────────────────────────────────

def _send_smtp(subject: str, body: str) -> None:
    """
    Send a plain-text email via SMTP.
    Automatically selects SSL (port 465) or STARTTLS (port 587+).
    Raises on failure — caller handles gracefully.
    """
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = settings.SMTP_USER
    msg["To"]      = settings.ALERT_RECIPIENT
    msg.attach(MIMEText(body, "plain"))

    if settings.SMTP_PORT == 465:
        # SSL from the start
        with smtplib.SMTP_SSL(settings.SMTP_HOST, settings.SMTP_PORT) as server:
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.sendmail(settings.SMTP_USER, settings.ALERT_RECIPIENT, msg.as_string())
    else:
        # STARTTLS (587 or custom port)
        with smtplib.SMTP(settings.SMTP_HOST, settings.SMTP_PORT) as server:
            server.ehlo()
            server.starttls()
            server.ehlo()
            server.login(settings.SMTP_USER, settings.SMTP_PASSWORD)
            server.sendmail(settings.SMTP_USER, settings.ALERT_RECIPIENT, msg.as_string())


# ─── Background sender ────────────────────────────────────────────────────────

def _send_in_background(record: EventRecord) -> None:
    """
    Worker function that runs in a daemon thread.
    Formats and sends the alert, updates session log, handles errors gracefully.
    Never raises — a failed alert must not crash the monitoring loop.
    """
    subject = _format_subject(record)
    body    = _format_body(record)

    # Check SMTP is configured before attempting send
    if not all([settings.SMTP_USER, settings.SMTP_PASSWORD, settings.ALERT_RECIPIENT]):
        # No SMTP configured — log to console only (useful in development)
        if settings.VERBOSE_CONSOLE:
            print(
                f"         ↳ alert   │ ⚠  SMTP not configured — alert would send:\n"
                f"                   │   To      : {settings.ALERT_RECIPIENT or '(not set)'}\n"
                f"                   │   Subject : {subject}"
            )
        _log_session(record, sent=False, error="SMTP credentials not set")
        return

    try:
        _send_smtp(subject, body)
        _log_session(record, sent=True)

        if settings.VERBOSE_CONSOLE:
            print(
                f"         ↳ alert   │ ✉  sent → {settings.ALERT_RECIPIENT}"
                f"  [{record.severity}] {record.file_name}"
            )

    except smtplib.SMTPAuthenticationError:
        err = "SMTP authentication failed — check SFTMS_SMTP_USER / SFTMS_SMTP_PASSWORD"
        print(f"         ↳ alert   │ ✗  {err}")
        _log_session(record, sent=False, error=err)

    except smtplib.SMTPException as exc:
        err = f"SMTP error: {exc}"
        print(f"         ↳ alert   │ ✗  {err}")
        _log_session(record, sent=False, error=err)

    except Exception:
        err = traceback.format_exc().splitlines()[-1]
        print(f"         ↳ alert   │ ✗  Unexpected error: {err}")
        _log_session(record, sent=False, error=err)


def _log_session(record: EventRecord, sent: bool, error: str = "") -> None:
    entry = {
        "timestamp":  record.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "file_name":  record.file_name,
        "username":   record.username,
        "severity":   record.severity,
        "sent":       sent,
        "error":      error,
        "recipient":  settings.ALERT_RECIPIENT,
    }
    with _session_lock:
        _session_alerts.append(entry)


# ─── Public pipeline function ─────────────────────────────────────────────────

def send_alert(record: EventRecord) -> None:
    """
    Phase 5 pipeline entry point. Called from main.py only when
    record.is_violation is True.

    Guards:
      1. Severity threshold  — skip if below ALERT_SEVERITY_THRESHOLD
      2. Cooldown            — skip if same (user, severity) alerted recently

    Dispatches the actual send to a background daemon thread so the watchdog
    observer thread is never blocked waiting on SMTP.

    Args:
        record: Fully-enriched EventRecord (all prior stages complete).
    """
    now = record.timestamp

    # ── Guard 1: severity threshold ───────────────────────────────────────────
    threshold = settings.ALERT_SEVERITY_THRESHOLD
    if not _severity_gte(record.severity, threshold):
        if settings.VERBOSE_CONSOLE:
            print(
                f"         ↳ alert   │ ○  skipped "
                f"({record.severity} < threshold {threshold})"
            )
        return

    # ── Guard 2: cooldown ─────────────────────────────────────────────────────
    if _is_on_cooldown(record.username, record.severity, now):
        remaining = int(
            settings.ALERT_COOLDOWN_SECONDS
            - (now - _cooldown_state.get((record.username.lower(), record.severity), now)).total_seconds()
        )
        if settings.VERBOSE_CONSOLE:
            print(
                f"         ↳ alert   │ ○  cooldown active for '{record.username}'"
                f" [{record.severity}] — {remaining}s remaining"
            )
        return

    # ── Stamp cooldown & dispatch ─────────────────────────────────────────────
    _record_alert(record.username, record.severity, now)

    thread = threading.Thread(
        target=_send_in_background,
        args=(record,),
        daemon=True,   # won't block process shutdown
        name=f"alert-{record.file_name}-{record.severity}",
    )
    thread.start()

    if settings.VERBOSE_CONSOLE:
        print(
            f"         ↳ alert   │ ↗  dispatched [{record.severity}]"
            f" for '{record.username}' — {record.file_name}"
        )
