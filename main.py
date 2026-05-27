"""
main.py
-------
Entry point for the Secure File Transfer Monitoring System (SFTMS).

Usage:
    python main.py               # start live monitoring
    python main.py --setup       # create test_watch/ with sample files
    python main.py --report      # generate audit report from existing logs (Phase 6)

Full pipeline (all 5 phases active):
    classify        → enrich record with category/dest_type
    verify_integrity→ SHA-256 hash check, set integrity_ok
    check_auth      → run violation checks, set is_violation + severity
    log_record      → write complete row to transfer_log.csv / violations.csv
    send_alert      → email alert if violation meets threshold (background thread)
"""

import sys
import time
import signal
import argparse
import os
from pathlib import Path

from watchdog.observers import Observer

from config import settings
from core.watcher import SFTMSHandler, EventRecord


# ─── Ensure required directories exist ───────────────────────────────────────

def _ensure_dirs() -> None:
    for d in (settings.DATA_DIR, settings.REPORTS_DIR):
        Path(d).mkdir(parents=True, exist_ok=True)


# ─── Event pipeline ───────────────────────────────────────────────────────────

def on_event(record: EventRecord) -> None:
    """
    Full 5-stage pipeline. Order is fixed — do not rearrange.
    classify must run before auth (needs dest_type).
    log_record must run after auth (needs is_violation + severity).
    send_alert must run after log_record (record fully enriched).
    """
    # Stage 1 — classify event type + destination     ✓ ACTIVE
    from core.classifier import classify
    classify(record)

    # Stage 2 — integrity hash check                  ✓ ACTIVE
    from core.hasher import verify_integrity
    verify_integrity(record)

    # Stage 3 — authorisation + violation check       ✓ ACTIVE
    from core.auth_checker import check_authorisation
    check_authorisation(record)

    # Stage 4 — write fully-enriched row to CSV       ✓ ACTIVE
    from core.classifier import log_record
    log_record(record)

    # Stage 5 — email alert on violation              ✓ ACTIVE
    if record.is_violation:
        from core.alert import send_alert
        send_alert(record)


# ─── Setup helper ─────────────────────────────────────────────────────────────

def setup_test_environment() -> None:
    watch = Path(settings.WATCH_PATH)
    watch.mkdir(parents=True, exist_ok=True)

    samples = {
        "readme.txt":            "This is a test file.\n",
        "report.pdf.txt":        "Simulated PDF content.\n",
        "confidential.docx.txt": "Top secret data.\n",
        "notes.txt":             "Just some notes.\n",
    }
    for name, content in samples.items():
        target = watch / name
        if not target.exists():
            target.write_text(content)
            print(f"  created  {target}")

    print(f"\n✓ Test environment ready at: {watch}")
    print("  Run 'python main.py' then modify files inside test_watch/ to see events.\n")


# ─── Graceful shutdown ────────────────────────────────────────────────────────

_observer: Observer = None  # type: ignore

def _shutdown(sig, frame) -> None:
    from core.alert import get_session_alerts
    alerts = get_session_alerts()

    print("\n\n[SFTMS] Stopping observer…")
    if _observer:
        _observer.stop()
        _observer.join()

    # Print session alert summary
    if alerts:
        sent    = sum(1 for a in alerts if a["sent"])
        skipped = len(alerts) - sent
        print(f"\n[SFTMS] Alert session summary: {len(alerts)} triggered"
              f" | {sent} sent | {skipped} suppressed (cooldown/threshold)")
        for a in alerts:
            status = "✉  sent" if a["sent"] else f"○  suppressed ({a['error']})"
            print(f"         [{a['severity']}] {a['file_name']} — {status}")

    print("\n[SFTMS] Shutdown complete.")
    sys.exit(0)


# ─── Main ─────────────────────────────────────────────────────────────────────

def main() -> None:
    global _observer

    parser = argparse.ArgumentParser(description="Secure File Transfer Monitoring System")
    parser.add_argument("--setup",  action="store_true", help="Create test_watch/ with sample files")
    parser.add_argument("--report", action="store_true", help="Generate audit report from existing logs")
    args = parser.parse_args()

    _ensure_dirs()

    if args.setup:
        setup_test_environment()
        return

    if args.report:
        try:
            from reports.report_generator import generate_report
            generate_report()
        except ImportError:
            print("[SFTMS] Report generator not yet implemented (Phase 6).")
        return

    # ── Build or load baseline ────────────────────────────────────────────────
    from core.hasher import build_baseline, _load_baseline
    baseline_path = Path(settings.BASELINE_FILE)
    if not baseline_path.exists() or baseline_path.stat().st_size == 0:
        print("[SFTMS] No baseline found — building now…")
        build_baseline()
    else:
        _load_baseline()

    # ── Check alert config and warn if unconfigured ───────────────────────────
    if not settings.SMTP_USER or not settings.ALERT_RECIPIENT:
        print("[SFTMS] ⚠  SMTP not configured — alerts will be console-only.")
        print("           Set SFTMS_SMTP_USER, SFTMS_SMTP_PASSWORD, SFTMS_ALERT_RECIPIENT")
        print("           as environment variables to enable email alerts.\n")

    # ── Start observer ────────────────────────────────────────────────────────
    watch_path = Path(settings.WATCH_PATH)
    if not watch_path.exists():
        print(f"[SFTMS] Watch path does not exist: {watch_path}")
        print("        Run 'python main.py --setup' to create a test environment.\n")
        sys.exit(1)

    handler = SFTMSHandler(on_event=on_event)
    _observer = Observer()
    _observer.schedule(handler, str(watch_path), recursive=settings.WATCH_RECURSIVE)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    smtp_status = settings.SMTP_USER or "(not configured)"
    threshold   = settings.ALERT_SEVERITY_THRESHOLD
    cooldown    = settings.ALERT_COOLDOWN_SECONDS

    print("=" * 60)
    print("  SFTMS — Secure File Transfer Monitoring System  [Phase 5]")
    print("=" * 60)
    print(f"  Watching   : {watch_path}")
    print(f"  Log file   : {settings.LOG_FILE}")
    print(f"  Baseline   : {settings.BASELINE_FILE}")
    print(f"  Whitelist  : {sorted(settings.WHITELIST_USERS)}")
    print(f"  Alert from : {threshold} and above")
    print(f"  Cooldown   : {cooldown}s per user/severity")
    print(f"  SMTP       : {smtp_status}")
    print("=" * 60)
    print("  Press Ctrl+C to stop.\n")

    _observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        _shutdown(None, None)


if __name__ == "__main__":
    main()
