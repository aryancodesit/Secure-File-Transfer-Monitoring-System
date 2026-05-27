"""
core/hasher.py
--------------
Phase 3 — File Integrity Hashing.

Responsibilities:
  1. Build a baseline hash store (SHA-256 per file) on first run by scanning
     WATCH_PATH and saving results to baseline_hashes.json.
  2. On every file event, compute the current hash and compare it against the
     baseline to detect tampering or unexpected modification.
  3. Set record.integrity_ok on the EventRecord so downstream stages
     (auth_checker, alert) can act on integrity failures.
  4. Keep the baseline in sync:
       created  → add new entry
       modified → compare, flag if mismatch, update if user is whitelisted
       moved    → rename entry (old path out, new path in)
       deleted  → remove entry

Design notes:
  - The baseline is loaded into memory once at module import and written back
    to disk only when it changes — minimises I/O on every event.
  - A threading.Lock protects the in-memory baseline dict and all disk writes,
    since the watchdog observer fires events on its own thread.
  - Hashing reads files in 64 KB chunks to handle large files without loading
    them fully into RAM.
  - Files that cannot be read (permissions, deleted mid-event) are handled
    gracefully — integrity_ok is set to None rather than crashing.
"""

import hashlib
import json
import os
import threading
from pathlib import Path
from typing import Optional

from config import settings
from core.watcher import EventRecord


# ─── Constants ────────────────────────────────────────────────────────────────

CHUNK_SIZE = 65_536   # 64 KB read chunks


# ─── Colour helpers (reuse from watcher pattern) ─────────────────────────────

_C = {
    "reset":  "\033[0m",
    "green":  "\033[92m",
    "yellow": "\033[93m",
    "red":    "\033[91m",
    "grey":   "\033[90m",
    "cyan":   "\033[96m",
}

def _c(text: str, colour: str) -> str:
    if not settings.USE_COLOUR:
        return text
    return f"{_C.get(colour, '')}{text}{_C['reset']}"


# ─── Baseline store ───────────────────────────────────────────────────────────

_baseline: dict[str, str] = {}   # { absolute_path: sha256_hex }
_baseline_lock = threading.Lock()
_baseline_loaded = False


def _load_baseline() -> None:
    """
    Load baseline_hashes.json into memory.
    If the file does not exist, initialise with an empty dict.
    Called once at module level on first use.
    """
    global _baseline, _baseline_loaded
    with _baseline_lock:
        if _baseline_loaded:
            return
        path = settings.BASELINE_FILE
        if os.path.isfile(path) and os.path.getsize(path) > 0:
            with open(path, "r", encoding="utf-8") as f:
                _baseline = json.load(f)
            print(f"[hasher] Loaded baseline: {len(_baseline)} file(s) from {path}")
        else:
            _baseline = {}
            print(f"[hasher] No baseline found at {path} — will build on first scan.")
        _baseline_loaded = True


def _save_baseline() -> None:
    """Persist the in-memory baseline to disk. Must be called with _baseline_lock held."""
    with open(settings.BASELINE_FILE, "w", encoding="utf-8") as f:
        json.dump(_baseline, f, indent=2)


# ─── Hash computation ─────────────────────────────────────────────────────────

def compute_hash(filepath: str) -> Optional[str]:
    """
    Compute the SHA-256 digest of a file, reading in 64 KB chunks.

    Returns:
        Hex digest string, or None if the file is unreadable.
    """
    h = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for chunk in iter(lambda: f.read(CHUNK_SIZE), b""):
                h.update(chunk)
        return h.hexdigest()
    except (OSError, PermissionError):
        return None


# ─── Baseline builder ─────────────────────────────────────────────────────────

def build_baseline() -> int:
    """
    Scan WATCH_PATH recursively and hash every non-ignored file.
    Overwrites the existing baseline. Called once on startup if no
    baseline file exists yet.

    Returns:
        Number of files hashed.
    """
    _load_baseline()
    watch = Path(settings.WATCH_PATH)
    count = 0

    with _baseline_lock:
        _baseline.clear()
        for file_path in watch.rglob("*"):
            if not file_path.is_file():
                continue
            ext  = file_path.suffix.lower()
            name = file_path.name
            # Skip ignored extensions (same rules as watcher)
            if ext in settings.IGNORED_EXTENSIONS or name.startswith("."):
                continue
            digest = compute_hash(str(file_path))
            if digest:
                _baseline[str(file_path)] = digest
                count += 1
        _save_baseline()

    print(f"[hasher] Baseline built: {count} file(s) hashed → {settings.BASELINE_FILE}")
    return count


# ─── Per-event integrity check ────────────────────────────────────────────────

def _is_whitelisted(username: str) -> bool:
    """Returns True if the user is in the configured whitelist."""
    return username.lower() in {u.lower() for u in settings.WHITELIST_USERS}


def verify_integrity(record: EventRecord) -> None:
    """
    Phase 3 pipeline stage.

    Handles each event type:

      created  → Hash the new file and add it to baseline. No violation
                 (creation itself is handled by auth_checker in Phase 4).
                 integrity_ok = True (new file; nothing to compare against).

      modified → Recompute hash and compare against baseline.
                 Match   → integrity_ok = True,  update baseline for whitelist users.
                 Mismatch→ integrity_ok = False, sets record for violation flagging.

      moved    → Transfer baseline entry to new path, hash new location.
                 integrity_ok reflects whether dest hash matches src baseline.

      deleted  → Remove entry from baseline.
                 integrity_ok = None (file is gone; not applicable).

    Mutates record.integrity_ok in-place. Does NOT set record.is_violation —
    that is auth_checker's job in Phase 4; it will read integrity_ok.

    Args:
        record: EventRecord from classifier. Mutated in-place.
    """
    global _baseline_loaded
    if not _baseline_loaded:
        _load_baseline()

    event   = record.event_type
    src     = record.src_path
    dest    = record.dest_path

    # ── CREATED ──────────────────────────────────────────────────────────────
    if event == "created":
        digest = compute_hash(src)
        if digest:
            with _baseline_lock:
                _baseline[src] = digest
                _save_baseline()
            record.integrity_ok = True
            _console(record, "new", src, None, None, digest)
        else:
            record.integrity_ok = None   # unreadable — skip silently

    # ── MODIFIED ─────────────────────────────────────────────────────────────
    elif event == "modified":
        current_digest = compute_hash(src)

        if current_digest is None:
            record.integrity_ok = None   # file vanished between event and hash
            return

        with _baseline_lock:
            baseline_digest = _baseline.get(src)

            if baseline_digest is None:
                # File not in baseline (e.g. appeared before monitoring started)
                # Register it now; treat as clean.
                _baseline[src] = current_digest
                _save_baseline()
                record.integrity_ok = True
                _console(record, "registered", src, None, None, current_digest)

            elif current_digest == baseline_digest:
                # Hash unchanged — legitimate edit by a known user, update baseline
                if _is_whitelisted(record.username):
                    _baseline[src] = current_digest
                    _save_baseline()
                record.integrity_ok = True
                _console(record, "ok", src, baseline_digest, current_digest, None)

            else:
                # Hash changed — potential tampering
                record.integrity_ok = False
                _console(record, "tampered", src, baseline_digest, current_digest, None)
                # Do NOT update baseline on a mismatch — preserve evidence

    # ── MOVED ────────────────────────────────────────────────────────────────
    elif event == "moved" and dest:
        new_digest = compute_hash(dest)

        with _baseline_lock:
            old_digest = _baseline.pop(src, None)   # remove old path

            if new_digest:
                if old_digest and new_digest == old_digest:
                    record.integrity_ok = True
                    _console(record, "moved_ok", dest, old_digest, new_digest, None)
                elif old_digest and new_digest != old_digest:
                    # File content changed during the move — suspicious
                    record.integrity_ok = False
                    _console(record, "moved_tampered", dest, old_digest, new_digest, None)
                else:
                    # No prior baseline entry; register destination as new
                    record.integrity_ok = True
                    _console(record, "new", dest, None, None, new_digest)

                _baseline[dest] = new_digest   # always register dest
            else:
                record.integrity_ok = None

            _save_baseline()

    # ── DELETED ──────────────────────────────────────────────────────────────
    elif event == "deleted":
        with _baseline_lock:
            removed = _baseline.pop(src, None)
            if removed:
                _save_baseline()
        record.integrity_ok = None   # not applicable for deletions
        _console(record, "removed", src, None, None, None)


# ─── Console output helper ────────────────────────────────────────────────────

def _console(
    record: EventRecord,
    status: str,
    path: str,
    baseline_hash: Optional[str],
    current_hash: Optional[str],
    new_hash: Optional[str],
) -> None:
    """Prints a one-line integrity status line below the watcher's event line."""
    if not settings.VERBOSE_CONSOLE:
        return

    short_path = Path(path).name

    if status == "ok":
        icon  = _c("✓", "green")
        label = _c("intact   ", "green")
        detail = f"hash={_c(current_hash[:12] + '…', 'grey')}"

    elif status == "tampered":
        icon  = _c("✗", "red")
        label = _c("TAMPERED ", "red")
        detail = (
            f"baseline={_c(baseline_hash[:12] + '…', 'grey')}  "
            f"current={_c(current_hash[:12] + '…', 'yellow')}"
        )

    elif status == "new":
        icon  = _c("+", "cyan")
        label = _c("new      ", "cyan")
        detail = f"hash={_c((new_hash or '')[:12] + '…', 'grey')}"

    elif status == "registered":
        icon  = _c("~", "yellow")
        label = _c("late-reg ", "yellow")
        detail = f"hash={_c((current_hash or '')[:12] + '…', 'grey')} (not in prior baseline)"

    elif status == "moved_ok":
        icon  = _c("✓", "green")
        label = _c("moved-ok ", "green")
        detail = f"hash={_c(current_hash[:12] + '…', 'grey')} unchanged"

    elif status == "moved_tampered":
        icon  = _c("✗", "red")
        label = _c("MV-TAMPER", "red")
        detail = (
            f"baseline={_c(baseline_hash[:12] + '…', 'grey')}  "
            f"dest={_c(current_hash[:12] + '…', 'yellow')}"
        )

    elif status == "removed":
        icon  = _c("−", "grey")
        label = _c("removed  ", "grey")
        detail = "entry removed from baseline"

    else:
        return

    print(f"         ↳ hash    │ {icon} {label} │ {short_path}  {detail}")
