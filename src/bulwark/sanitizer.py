"""Input sanitization for prompt injection defense."""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass, field
from typing import Optional

from bulwark.events import EventEmitter, BulwarkEvent, Layer, Verdict, _now


@dataclass
class Sanitizer:
    """Strip steganography, hidden text, and control characters from untrusted input.

    All options default to True for maximum protection. Disable selectively
    if you have specific needs.
    """

    strip_zero_width: bool = True
    strip_html: bool = True
    strip_scripts: bool = True
    strip_css_hidden: bool = True
    strip_control_chars: bool = True
    strip_bidi: bool = True
    strip_emoji_smuggling: bool = True
    normalize_unicode: bool = False
    collapse_whitespace: bool = True
    max_length: Optional[int] = 3000
    custom_patterns: list[str] = field(default_factory=list)
    emitter: Optional[EventEmitter] = None

    def __post_init__(self):
        """Pre-compile custom patterns at init time to catch invalid regexes early."""
        self._compiled_custom_patterns: list[re.Pattern] = []
        for pattern in self.custom_patterns:
            try:
                self._compiled_custom_patterns.append(re.compile(pattern))
            except re.error as e:
                raise ValueError(f"Invalid custom pattern {pattern!r}: {e}") from e

    def clean(self, text: str) -> str:
        """Sanitize a single text input. Returns cleaned text."""
        if not text:
            return text

        _start = _now() if self.emitter else 0
        _original = text if self.emitter else ""

        # Apply each cleaning step in order
        if self.strip_zero_width:
            text = self._strip_zero_width(text)
        if self.strip_scripts:
            text = self._strip_scripts(text)
        if self.strip_html:
            text = self._strip_html(text)
        if self.strip_css_hidden:
            text = self._strip_css_hidden(text)
        if self.strip_control_chars:
            text = self._strip_control_chars(text)
        if self.strip_bidi:
            text = self._strip_bidi(text)
        if self.strip_emoji_smuggling:
            text = self._strip_emoji_smuggling(text)
        if self.normalize_unicode:
            text = self._normalize_unicode(text)
        for pattern in self._compiled_custom_patterns:
            text = pattern.sub('', text)
        if self.collapse_whitespace:
            text = self._collapse_whitespace(text)
        if self.max_length:
            text = text[:self.max_length]

        result = text.strip()

        if self.emitter:
            changed = result != _original
            self.emitter.emit(BulwarkEvent(
                timestamp=_now(), layer=Layer.SANITIZER,
                verdict=Verdict.MODIFIED if changed else Verdict.PASSED,
                detail=f"{'Modified' if changed else 'Clean'}: {len(_original)} -> {len(result)} chars",
                duration_ms=(_now() - _start) * 1000,
            ))

        return result

    def clean_batch(self, texts: list[str]) -> list[str]:
        """Sanitize a list of texts."""
        return [self.clean(t) for t in texts]

    @staticmethod
    def _strip_zero_width(text: str) -> str:
        """Remove zero-width characters used for steganography."""
        return re.sub(r'[\u200b\u200c\u200d\u200e\u200f\ufeff\u2060-\u2064]', '', text)

    @staticmethod
    def _strip_scripts(text: str) -> str:
        """Remove <script> and <style> tags and their content."""
        text = re.sub(r'<script[^>]*>.*?</script>', '', text, flags=re.DOTALL | re.IGNORECASE)
        text = re.sub(r'<style[^>]*>.*?</style>', '', text, flags=re.DOTALL | re.IGNORECASE)
        return text

    @staticmethod
    def _strip_html(text: str) -> str:
        """Remove HTML tags."""
        return re.sub(r'<[^>]+>', '', text)

    @staticmethod
    def _strip_css_hidden(text: str) -> str:
        """Remove CSS patterns commonly used to hide text."""
        text = re.sub(r'(?i)display\s*:\s*none[^;]*;?', '', text)
        text = re.sub(r'(?i)font-size\s*:\s*0[^;]*;?', '', text)
        text = re.sub(
            r'(?i)color\s*:\s*(?:white|#fff(?:fff)?|rgb\(255,\s*255,\s*255\))[^;]*;?',
            '',
            text,
        )
        return text

    @staticmethod
    def _strip_control_chars(text: str) -> str:
        """Remove Unicode control characters, keeping normal whitespace."""
        return ''.join(
            c for c in text
            if unicodedata.category(c) not in ('Cc', 'Cf') or c in '\n\r\t '
        )

    @staticmethod
    def _strip_bidi(text: str) -> str:
        """Remove bidirectional override and embedding characters."""
        # LRE, RLE, PDF, LRO, RLO, LRI, RLI, FSI, PDI
        return re.sub(r'[\u202a-\u202e\u2066-\u2069]', '', text)

    @staticmethod
    def _strip_emoji_smuggling(text: str) -> str:
        """Remove emoji variation selectors and Unicode tag characters used for smuggling."""
        # Variation selectors (U+FE00-U+FE0F)
        text = re.sub(r'[\ufe00-\ufe0f]', '', text)
        # Variation selectors supplement (U+E0100-U+E01EF)
        text = re.sub(r'[\U000e0100-\U000e01ef]', '', text)
        # Tag characters (U+E0001-U+E007F) — used for emoji smuggling
        text = re.sub(r'[\U000e0001-\U000e007f]', '', text)
        return text

    def _normalize_unicode(self, text: str) -> str:
        """NFKC normalization — maps homoglyphs to canonical forms."""
        return unicodedata.normalize('NFKC', text)

    @staticmethod
    def _collapse_whitespace(text: str) -> str:
        """Normalize excessive whitespace while preserving paragraph breaks."""
        text = re.sub(r' +', ' ', text)  # collapse spaces (preserve tabs)
        text = re.sub(r'\n{3,}', '\n\n', text)  # collapse 3+ newlines to 2
        return text
