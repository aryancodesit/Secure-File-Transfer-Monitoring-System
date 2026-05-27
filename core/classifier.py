"""
core/classifier.py
------------------
Phase 2 — Event Classification & Transfer Logging.

Responsibilities:
  1. classify(record)   — enriches EventRecord with transfer_category and
                          dest_type. Runs early in the pipeline so downstream
                          stages (hasher, auth_checker) can read those fields.
  2. log_record(record) — writes the fully-enriched record to transfer_log.csv
                          and, if flagged, to violations.csv. Runs last so all
                          phase results (integrity_ok, is_violation, severity)
                          are captured in a single CSV row.

Design notes:
  - Splitting classify / log is intentional: the old combined classify_and_log()
    was called before auth_checker ran, so is_violation was always False in the CSV.
  - CSV writes use mode='a' with a header guard — always append-only.
  - threading.Lock protects all disk writes from concurrent watchdog callbacks.
"""

import os
import threading
import pandas as pd
from typing import Optional

from config import settings
from core.watcher import EventRecord


# ─── Transfer category mapping ───────────────────────────────────────────────

TRANSFER_CATEGORIES = {
    "created":  "copy_in",
    "modified": "edit",
    "moved":    "transfer",
    "deleted":  "removal",
}

_DEST_TYPE_RULES = [
    ("usb",     ["/media/", "/mnt/usb", "\\removable", "\\usb"]),
    ("cloud",   ["dropbox", "google drive", "onedrive", "icloud", "box"]),
    ("temp",    ["/tmp/", "\\temp\\", "\\appdata\\local\\temp"]),
    ("network", ["/net/", "\\\\", "smb://", "nfs://"]),
    ("local",   []),
]


def _classify_dest_type(path: Optional[str]) -> str:
    if not path:
        return "n/a"
    p = path.lower()
    for label, fragments in _DEST_TYPE_RULES:
        if label == "local":
            return "local"
        if any(f in p for f in fragments):
            return label
    return "local"


# ─── Thread-safe CSV writer ───────────────────────────────────────────────────

_write_lock = threading.Lock()


def _append_to_csv(filepath: str, row: dict) -> None:
    with _write_lock:
        file_exists = os.path.isfile(filepath) and os.path.getsize(filepath) > 0
        pd.DataFrame([row]).to_csv(
            filepath,
            mode="a",
            header=not file_exists,
            index=False,
        )


# ─── Column definitions ───────────────────────────────────────────────────────

LOG_COLUMNS = [
    "timestamp", "event_type", "transfer_category", "file_name", "file_ext",
    "src_path", "dest_path", "dest_type", "file_size_kb", "username",
    "is_violation", "violation_reason", "severity", "integrity_ok",
]

VIOLATION_COLUMNS = [
    "timestamp", "event_type", "transfer_category", "file_name",
    "src_path", "dest_path", "dest_type", "file_size_kb",
    "username", "violation_reason", "severity", "integrity_ok",
]


# ─── Pipeline stage 1 of 2: Classify ─────────────────────────────────────────

def classify(record: EventRecord) -> None:
    """
    Enrich record with transfer_category and dest_type.
    Called FIRST in the pipeline so hasher and auth_checker can read dest_type.
    Does NOT write to disk.
    """
    record.transfer_category = TRANSFER_CATEGORIES.get(record.event_type, "unknown")
    record.dest_type = _classify_dest_type(record.dest_path or record.src_path)


# ─── Pipeline stage 2 of 2: Log ──────────────────────────────────────────────

def log_record(record: EventRecord) -> None:
    """
    Write the fully-enriched EventRecord to transfer_log.csv.
    If record.is_violation is True, also write to violations.csv.
    Called LAST in the pipeline, after hasher and auth_checker have run.
    """
    size = record.file_size_kb if record.file_size_kb is not None else ""
    integrity = "" if record.integrity_ok is None else record.integrity_ok

    log_row = {
        "timestamp":         record.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
        "event_type":        record.event_type,
        "transfer_category": record.transfer_category,
        "file_name":         record.file_name,
        "file_ext":          record.file_ext,
        "src_path":          record.src_path,
        "dest_path":         record.dest_path or "",
        "dest_type":         record.dest_type,
        "file_size_kb":      size,
        "username":          record.username,
        "is_violation":      record.is_violation,
        "violation_reason":  record.violation_reason,
        "severity":          record.severity,
        "integrity_ok":      integrity,
    }

    _append_to_csv(settings.LOG_FILE, log_row)

    if record.is_violation:
        violation_row = {k: log_row[k] for k in VIOLATION_COLUMNS}
        _append_to_csv(settings.VIOLATIONS_FILE, violation_row)

    if settings.VERBOSE_CONSOLE:
        size_str = f"{record.file_size_kb} KB" if record.file_size_kb else "—"
        flag = ""
        if record.is_violation:
            sev_colours = {
                "LOW": "\033[93m", "MEDIUM": "\033[93m",
                "HIGH": "\033[91m", "CRITICAL": "\033[91m",
            }
            col   = sev_colours.get(record.severity, "")
            reset = "\033[0m" if settings.USE_COLOUR else ""
            col   = col if settings.USE_COLOUR else ""
            flag  = f"  {col}[{record.severity} VIOLATION]{reset}"
        print(
            f"         ↳ logged  │ {record.transfer_category:<10s}"
            f" │ dest={record.dest_type:<8s}"
            f" │ size={size_str}{flag}"
        )
