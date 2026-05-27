"""
core/watcher.py
---------------
File system event handler built on watchdog.
Captures create / modify / move / delete events and emits structured
EventRecord objects for downstream processing (logging, hashing, alerting).
"""

import os
import getpass
import datetime
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Callable

from watchdog.events import (
    FileSystemEventHandler,
    FileCreatedEvent,
    FileModifiedEvent,
    FileMovedEvent,
    FileDeletedEvent,
)

from config import settings


# ─── Colour helpers (console only) ───────────────────────────────────────────

_COLOURS = {
    "reset":   "\033[0m",
    "green":   "\033[92m",
    "yellow":  "\033[93m",
    "red":     "\033[91m",
    "cyan":    "\033[96m",
    "magenta": "\033[95m",
    "grey":    "\033[90m",
}

_EVENT_COLOURS = {
    "created":  "green",
    "modified": "yellow",
    "moved":    "cyan",
    "deleted":  "red",
}

def _colour(text: str, colour: str) -> str:
    if not settings.USE_COLOUR:
        return text
    return f"{_COLOURS.get(colour, '')}{text}{_COLOURS['reset']}"


# ─── EventRecord dataclass ────────────────────────────────────────────────────

@dataclass
class EventRecord:
    """
    Structured representation of a single file system event.
    Passed between pipeline stages (logger → hasher → auth_checker → alerter).
    """
    timestamp: datetime.datetime
    event_type: str          # created | modified | moved | deleted
    src_path: str
    dest_path: Optional[str] # populated for 'moved' events only
    file_name: str
    file_ext: str
    username: str

    # Populated by later pipeline stages
    file_size_kb: Optional[float] = None
    transfer_category: str = ""            # set by classifier  (Phase 2)
    dest_type: str = ""                    # set by classifier  (Phase 2)
    integrity_ok: Optional[bool] = None   # set by hasher      (Phase 3)
    is_violation: bool = False             # set by auth_checker (Phase 4)
    violation_reason: str = ""
    severity: str = ""

    def display_line(self) -> str:
        """Returns a formatted single-line summary for console output."""
        ts = self.timestamp.strftime("%H:%M:%S")
        colour = _EVENT_COLOURS.get(self.event_type, "grey")
        event_tag = _colour(f"[{self.event_type.upper():8s}]", colour)
        path_info = self.src_path
        if self.dest_path:
            path_info += _colour(f"  →  {self.dest_path}", "cyan")
        return f"{_colour(ts, 'grey')}  {event_tag}  {path_info}  {_colour('(' + self.username + ')', 'magenta')}"


# ─── Event handler ────────────────────────────────────────────────────────────

class SFTMSHandler(FileSystemEventHandler):
    """
    Watchdog handler that intercepts file system events and:
      1. Filters out ignored extensions and directory-level events.
      2. Builds an EventRecord with metadata.
      3. Calls the registered on_event callback for downstream processing.
    """

    def __init__(self, on_event: Callable[[EventRecord], None]):
        """
        Args:
            on_event: Callback invoked with each EventRecord. Called from the
                      watchdog observer thread — keep it fast; offload heavy
                      work (SMTP, disk writes) to background threads.
        """
        super().__init__()
        self._on_event = on_event
        self._username = self._resolve_username()

    # ── Internal helpers ──────────────────────────────────────────────────────

    @staticmethod
    def _resolve_username() -> str:
        """Best-effort current username — graceful fallback."""
        try:
            return getpass.getuser()
        except Exception:
            return os.environ.get("USER", os.environ.get("USERNAME", "unknown"))

    @staticmethod
    def _should_ignore(path: str) -> bool:
        """Returns True for temp/OS artefact files that should be skipped."""
        ext = Path(path).suffix.lower()
        name = Path(path).name
        return (
            ext in settings.IGNORED_EXTENSIONS
            or name in settings.IGNORED_EXTENSIONS
            or name.startswith(".")
        )

    @staticmethod
    def _file_size_kb(path: str) -> Optional[float]:
        """Safely returns file size in KB, or None if unreadable."""
        try:
            return round(os.path.getsize(path) / 1024, 2)
        except OSError:
            return None

    def _build_record(self, event_type: str, src: str, dest: Optional[str] = None) -> EventRecord:
        p = Path(src)
        return EventRecord(
            timestamp=datetime.datetime.now(),
            event_type=event_type,
            src_path=src,
            dest_path=dest,
            file_name=p.name,
            file_ext=p.suffix.lower(),
            username=self._username,
            file_size_kb=self._file_size_kb(dest or src),
        )

    def _handle(self, record: EventRecord) -> None:
        """Prints to console (if verbose) then fires the callback."""
        if settings.VERBOSE_CONSOLE:
            print(record.display_line())
        self._on_event(record)

    # ── Watchdog event overrides ──────────────────────────────────────────────

    def on_created(self, event: FileCreatedEvent) -> None:
        if event.is_directory or self._should_ignore(event.src_path):
            return
        self._handle(self._build_record("created", event.src_path))

    def on_modified(self, event: FileModifiedEvent) -> None:
        if event.is_directory or self._should_ignore(event.src_path):
            return
        self._handle(self._build_record("modified", event.src_path))

    def on_moved(self, event: FileMovedEvent) -> None:
        if event.is_directory or self._should_ignore(event.src_path):
            return
        self._handle(self._build_record("moved", event.src_path, event.dest_path))

    def on_deleted(self, event: FileDeletedEvent) -> None:
        if event.is_directory or self._should_ignore(event.src_path):
            return
        self._handle(self._build_record("deleted", event.src_path))
