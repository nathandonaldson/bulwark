"""Event system for Bulwark observability.

Each defense layer emits BulwarkEvents via a pluggable EventEmitter.
Default is NullEmitter (zero overhead). Plug in WebhookEmitter,
StdoutJsonEmitter, or CallbackEmitter for observability.
"""
from __future__ import annotations

import json
import time
import threading
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Callable, Optional, Protocol, runtime_checkable


class Layer(Enum):
    SANITIZER = "sanitizer"
    TRUST_BOUNDARY = "trust_boundary"
    ANALYSIS_GUARD = "analysis_guard"
    CANARY = "canary"
    ISOLATOR = "isolator"


class Verdict(Enum):
    PASSED = "passed"
    BLOCKED = "blocked"
    MODIFIED = "modified"


@dataclass
class BulwarkEvent:
    """A single observability event from a defense layer."""
    timestamp: float  # time.time()
    layer: Layer
    verdict: Verdict
    source_id: str = ""  # e.g., "email:19d75895a", "calendar:gcal"
    detail: str = ""  # human-readable description
    duration_ms: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["layer"] = self.layer.value
        d["verdict"] = self.verdict.value
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict())


def _now() -> float:
    return time.time()


# ---------------------------------------------------------------------------
# Emitter protocol and implementations
# ---------------------------------------------------------------------------

@runtime_checkable
class EventEmitter(Protocol):
    def emit(self, event: BulwarkEvent) -> None: ...


class NullEmitter:
    """Default emitter — discards all events. Zero overhead."""
    def emit(self, event: BulwarkEvent) -> None:
        pass


class CallbackEmitter:
    """Calls a function for each event. Useful for testing and custom integrations."""
    def __init__(self, callback: Callable[[BulwarkEvent], None]):
        self._callback = callback

    def emit(self, event: BulwarkEvent) -> None:
        self._callback(event)


class CollectorEmitter:
    """Collects events in a list. Useful for testing."""
    def __init__(self):
        self.events: list[BulwarkEvent] = []

    def emit(self, event: BulwarkEvent) -> None:
        self.events.append(event)

    def clear(self) -> None:
        self.events.clear()


class StdoutJsonEmitter:
    """Prints each event as a JSON line to stdout."""
    def emit(self, event: BulwarkEvent) -> None:
        print(event.to_json(), flush=True)


class WebhookEmitter:
    """Posts events to an HTTP endpoint.

    Default is synchronous (safe for short-lived scripts like heredocs).
    Set async_send=True for long-running processes where you don't want
    to block on each event.

    Args:
        url: The endpoint to POST events to. Must use http:// or https://.
        timeout: HTTP timeout in seconds.
        batch_size: Buffer events and send in batches. 1 = send immediately.
        async_send: If True, send in daemon threads (fire-and-forget).
                    If False (default), send synchronously.
    """
    def __init__(self, url: str, timeout: float = 5.0, batch_size: int = 1,
                 async_send: bool = False):
        from urllib.parse import urlparse
        parsed = urlparse(url)
        if parsed.scheme not in ("http", "https"):
            raise ValueError(f"WebhookEmitter url must use http or https scheme, got {parsed.scheme!r}")
        self._url = url
        self._timeout = timeout
        self._batch_size = batch_size
        self._async = async_send
        self._buffer: list[dict] = []
        self._lock = threading.Lock()

    def emit(self, event: BulwarkEvent) -> None:
        if self._batch_size <= 1:
            events = [event.to_dict()]
            if self._async:
                self._send_async(events)
            else:
                self._post(events)
        else:
            with self._lock:
                self._buffer.append(event.to_dict())
                if len(self._buffer) >= self._batch_size:
                    batch = self._buffer[:]
                    self._buffer.clear()
                    if self._async:
                        self._send_async(batch)
                    else:
                        self._post(batch)

    def flush(self) -> None:
        """Send any buffered events immediately."""
        with self._lock:
            if self._buffer:
                batch = self._buffer[:]
                self._buffer.clear()
                self._send_async(batch)

    def _send_async(self, events: list[dict]) -> None:
        thread = threading.Thread(target=self._post, args=(events,), daemon=True)
        thread.start()

    def _post(self, events: list[dict]) -> None:
        try:
            import urllib.request
            data = json.dumps({"events": events}).encode()
            req = urllib.request.Request(
                self._url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=self._timeout)
        except Exception:
            pass  # fire-and-forget


class MultiEmitter:
    """Fan-out to multiple emitters."""
    def __init__(self, emitters: list[EventEmitter]):
        self._emitters = emitters

    def emit(self, event: BulwarkEvent) -> None:
        for emitter in self._emitters:
            emitter.emit(event)
