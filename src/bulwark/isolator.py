"""Map-reduce isolator: process untrusted items individually in complete isolation."""
from __future__ import annotations

import json
import re
import concurrent.futures
from dataclasses import dataclass, field
from typing import Any, Callable, Optional

from bulwark.events import EventEmitter, BulwarkEvent, Layer, Verdict, _now
from bulwark.sanitizer import Sanitizer
from bulwark.trust_boundary import TrustBoundary


@dataclass
class ItemResult:
    """Result from processing a single item."""
    index: int
    output: str
    parsed: Optional[Any] = None  # Parsed JSON if output_parser succeeded
    error: Optional[str] = None  # Error message if processing failed
    suspicious: bool = False


@dataclass
class IsolatorResult:
    """Result from processing a batch of items."""
    items: list[ItemResult]

    @property
    def successful(self) -> list[ItemResult]:
        return [i for i in self.items if i.error is None]

    @property
    def failed(self) -> list[ItemResult]:
        return [i for i in self.items if i.error is not None]

    @property
    def suspicious_items(self) -> list[ItemResult]:
        return [i for i in self.items if i.suspicious]


# Type alias: takes item text, returns LLM response string
MapFn = Callable[[str], str]


@dataclass
class MapReduceIsolator:
    """Process untrusted items individually in complete isolation.

    Each item is sanitized, wrapped in trust boundaries, and processed
    by a map function (typically a cheap/fast LLM call) in complete
    isolation. No item can see or influence any other item's processing.

    This prevents cross-contamination attacks where injection in one
    email/document attempts to manipulate the processing of another.

    Args:
        map_fn: Function that processes a single tagged item. Typically calls
                a cheap LLM (Haiku) with the item and a classification prompt.
        sanitizer: Optional Sanitizer to clean each item before processing.
        trust_boundary: Optional TrustBoundary to wrap each item.
        concurrency: Max parallel workers for map phase.
        timeout: Per-item timeout in seconds.
        output_parser: Optional function to parse each map output (e.g., json.loads).
        prompt_template: Template for the map prompt. Use {tagged_item} as placeholder.
    """
    map_fn: MapFn
    sanitizer: Optional[Sanitizer] = None
    trust_boundary: Optional[TrustBoundary] = None
    concurrency: int = 5
    timeout: float = 30.0
    output_parser: Optional[Callable[[str], Any]] = None
    prompt_template: str = "{tagged_item}"
    emitter: Optional[EventEmitter] = None

    def process(self, items: list[str],
                source: str = "external",
                label: Optional[str] = None) -> IsolatorResult:
        """Process a batch of untrusted items in isolation.

        Args:
            items: List of untrusted text items to process
            source: Source identifier for trust boundary tags
            label: Optional label for trust boundary tags

        Returns:
            IsolatorResult with per-item results
        """
        if not isinstance(items, (list, tuple)):
            raise TypeError(f"Expected list, got {type(items).__name__}")
        if not items:
            return IsolatorResult(items=[])

        _start = _now() if self.emitter else 0

        # Pre-process each item (sanitize, wrap, template) before submitting
        # to the executor. This keeps the map_fn call as the only work inside
        # the thread, so per-item timeout on future.result() works correctly.
        prompts: dict[int, str] = {}
        pre_errors: dict[int, str] = {}
        for i, raw_item in enumerate(items):
            try:
                item = raw_item
                if self.sanitizer:
                    item = self.sanitizer.clean(item)
                if self.trust_boundary:
                    item = self.trust_boundary.wrap(item, source=source, label=label)
                prompts[i] = self.prompt_template.format(tagged_item=item)
            except Exception as e:
                pre_errors[i] = str(e)

        # Process items in parallel with concurrency limit
        results: list[ItemResult] = []

        # Add pre-processing errors immediately
        for idx, err in pre_errors.items():
            results.append(ItemResult(index=idx, output="", error=err))

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.concurrency) as executor:
            index_future_pairs = [
                (idx, executor.submit(self.map_fn, prompt))
                for idx, prompt in prompts.items()
            ]
            for idx, future in index_future_pairs:
                try:
                    output = future.result(timeout=self.timeout)

                    # Parse output if parser provided
                    parsed = None
                    suspicious = False
                    if self.output_parser:
                        parsed = self.output_parser(output)
                        if isinstance(parsed, dict) and parsed.get('suspicious'):
                            suspicious = True

                    results.append(ItemResult(
                        index=idx,
                        output=output,
                        parsed=parsed,
                        suspicious=suspicious,
                    ))
                except concurrent.futures.TimeoutError:
                    results.append(ItemResult(
                        index=idx, output="", error="Timeout"
                    ))
                except Exception as e:
                    results.append(ItemResult(
                        index=idx, output="", error=f"{type(e).__name__}: {e}"
                    ))

        # Sort by original index to maintain order
        results.sort(key=lambda r: r.index)

        result = IsolatorResult(items=results)

        if self.emitter:
            self.emitter.emit(BulwarkEvent(
                timestamp=_now(), layer=Layer.ISOLATOR,
                verdict=Verdict.PASSED,
                detail=f"{len(result.successful)} processed, {len(result.failed)} failed, {len(result.suspicious_items)} suspicious",
                duration_ms=(_now() - _start) * 1000,
                metadata={"total": len(items), "suspicious": len(result.suspicious_items)},
            ))

        return result

    def process_single(self, item: str, source: str = "external",
                       label: Optional[str] = None) -> ItemResult:
        """Process a single item. Convenience for one-off classification."""
        result = self.process([item], source=source, label=label)
        return result.items[0] if result.items else ItemResult(index=0, output="", error="Empty")
