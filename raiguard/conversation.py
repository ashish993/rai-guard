"""
Per-session conversation buffer for multi-turn context tracking.

Keeps a sliding window of recent turns per session so intent checks
(especially the LLM-based one) can evaluate accumulated context rather
than a single message in isolation.

Usage::

    from raiguard.conversation import ConversationBuffer

    buf = ConversationBuffer()
    buf.add_turn("session-123", role="user", content="Hi, I'm just testing")
    history = buf.get_history("session-123")
    # -> [{"role": "user", "content": "Hi, I'm just testing"}]

Environment variables
---------------------
RAI_CONV_MAX_TURNS   Max turns to keep per session (default: 20).
RAI_CONV_TTL_SECONDS Session expiry after last activity in seconds (default: 1800 / 30 min).
"""

from __future__ import annotations

import os
import threading
import time
from collections import deque
from typing import TypedDict


class Turn(TypedDict):
    role: str       # "user" | "assistant" | "system"
    content: str


_MAX_TURNS: int = int(os.getenv("RAI_CONV_MAX_TURNS", "20"))
_TTL_SECONDS: float = float(os.getenv("RAI_CONV_TTL_SECONDS", "1800"))


class _Session:
    __slots__ = ("turns", "last_active")

    def __init__(self) -> None:
        self.turns: deque[Turn] = deque(maxlen=_MAX_TURNS)
        self.last_active: float = time.monotonic()

    def touch(self) -> None:
        self.last_active = time.monotonic()


class ConversationBuffer:
    """
    Thread-safe, in-memory multi-turn conversation buffer.

    For production deployments with multiple workers, replace with a
    shared store (Redis, etc.) by subclassing and overriding
    ``add_turn`` / ``get_history`` / ``clear``.
    """

    def __init__(
        self,
        max_turns: int = _MAX_TURNS,
        ttl_seconds: float = _TTL_SECONDS,
    ) -> None:
        self._max_turns = max_turns
        self._ttl = ttl_seconds
        self._sessions: dict[str, _Session] = {}
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def add_turn(self, session_id: str, *, role: str, content: str) -> None:
        """Append a turn to the session's history."""
        with self._lock:
            session = self._sessions.setdefault(session_id, _Session())
            session.turns.append(Turn(role=role, content=content))
            session.touch()
            self._evict_expired()

    def get_history(self, session_id: str) -> list[Turn]:
        """Return a snapshot of the session's turn history (oldest first)."""
        with self._lock:
            session = self._sessions.get(session_id)
            if session is None:
                return []
            session.touch()
            return list(session.turns)

    def clear(self, session_id: str) -> None:
        """Remove a session entirely."""
        with self._lock:
            self._sessions.pop(session_id, None)

    def session_count(self) -> int:
        """Return the number of active sessions (for monitoring)."""
        with self._lock:
            return len(self._sessions)

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _evict_expired(self) -> None:
        """Remove sessions that have been idle longer than TTL.

        Called inside the lock — keep it O(n) but it only runs on writes.
        """
        now = time.monotonic()
        expired = [
            sid
            for sid, sess in self._sessions.items()
            if now - sess.last_active > self._ttl
        ]
        for sid in expired:
            del self._sessions[sid]


# Module-level default buffer — shared across middleware and AIGuard instances.
_default_buffer: ConversationBuffer | None = None
_buf_lock = threading.Lock()


def get_default_buffer() -> ConversationBuffer:
    """Return the module-level default ConversationBuffer (lazy singleton)."""
    global _default_buffer
    if _default_buffer is None:
        with _buf_lock:
            if _default_buffer is None:
                _default_buffer = ConversationBuffer()
    return _default_buffer
