"""Input sanitization for prompt injection defense."""
from __future__ import annotations

import html
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import unquote

from bulwark.events import EventEmitter, BulwarkEvent, Layer, Verdict, _now

# Pre-compiled regex for control character stripping (Cc and Cf categories)
# excluding normal whitespace (\n, \r, \t, space).
# Cc: C0 controls (U+0000-U+001F except \t\n\r, U+007F, U+0080-U+009F)
# Cf: format characters (U+00AD soft hyphen, U+0600-U+0605, U+061C, U+06DD,
#     U+070F, U+0890-U+0891, U+08E2, U+180E, U+200B-U+200F, U+202A-U+202E,
#     U+2060-U+2064, U+2066-U+206F, U+FEFF, U+FFF9-U+FFFB,
#     U+110BD, U+110CD, U+13430-U+1345F, U+1BCA0-U+1BCA3,
#     U+1D173-U+1D17A, U+E0001, U+E0020-U+E007F)
# This regex matches all Cc/Cf characters EXCEPT \n \r \t and space,
# which is equivalent to the original char-by-char filter but runs ~20x faster.
_CONTROL_CHAR_RE = re.compile(
    r'[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f'
    r'\xad'
    r'\u0600-\u0605\u061c\u06dd\u070f\u0890\u0891\u08e2'
    r'\u180e'
    r'\u200b-\u200f'
    r'\u202a-\u202e'
    r'\u2060-\u2064\u2066-\u206f'
    r'\ufeff\ufff9-\ufffb'
    r'\U000110bd\U000110cd'
    r'\U00013430-\U0001345f'
    r'\U0001bca0-\U0001bca3'
    r'\U0001d173-\U0001d17a'
    r'\U000e0001\U000e0020-\U000e007f]'
)

# Pre-compiled regexes for all sanitizer sub-steps to avoid
# re.sub() cache lookups on every call.
_ZERO_WIDTH_RE = re.compile(r'[\u200b\u200c\u200d\u200e\u200f\ufeff\u2060-\u2064]')
_SCRIPT_RE = re.compile(r'<script[^>]*>.*?</script>', re.DOTALL | re.IGNORECASE)
_STYLE_RE = re.compile(r'<style[^>]*>.*?</style>', re.DOTALL | re.IGNORECASE)
_HTML_TAG_RE = re.compile(r'<[^>]+>')
_CSS_DISPLAY_NONE_RE = re.compile(r'(?i)display\s*:\s*none[^;]*;?')
_CSS_FONT_ZERO_RE = re.compile(r'(?i)font-size\s*:\s*0[^;]*;?')
_CSS_COLOR_WHITE_RE = re.compile(
    r'(?i)color\s*:\s*(?:white|#fff(?:fff)?|rgb\(255,\s*255,\s*255\))[^;]*;?'
)
_BIDI_RE = re.compile(r'[\u202a-\u202e\u2066-\u2069]')
_VARIATION_SELECTOR_RE = re.compile(r'[\ufe00-\ufe0f]')
_VARIATION_SUPP_RE = re.compile(r'[\U000e0100-\U000e01ef]')
_TAG_CHARS_RE = re.compile(r'[\U000e0001-\U000e007f]')
_COLLAPSE_SPACES_RE = re.compile(r' +')
_COLLAPSE_NEWLINES_RE = re.compile(r'\n{3,}')


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
    decode_encodings: bool = False
    """ADR-038/B1: decode HTML entities and percent-encoding BEFORE the
    rest of the pipeline. Catches encoded payloads (`%3Cscript%3E`,
    `&#60;`, `&lt;`) that would otherwise survive the strip steps because
    the strippers only see the encoded form. Off by default for backwards
    compatibility; the dashboard sets this from config.encoding_resistant."""
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
        if not isinstance(text, str):
            raise TypeError(f"Expected str, got {type(text).__name__}")
        if not text:
            return text

        _start = _now() if self.emitter else 0
        _original = text if self.emitter else ""

        # Apply each cleaning step in order
        if self.decode_encodings:
            # B1 / encoding_resistant: decode encoded payloads first so the
            # downstream strippers see the real characters. Two passes catch
            # one level of nested encoding (e.g. &amp;lt; → &lt; → <).
            text = self._decode_encodings(text)
            text = self._decode_encodings(text)
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
        return _ZERO_WIDTH_RE.sub('', text)

    @staticmethod
    def _strip_scripts(text: str) -> str:
        """Remove <script> and <style> tags and their content."""
        text = _SCRIPT_RE.sub('', text)
        text = _STYLE_RE.sub('', text)
        return text

    @staticmethod
    def _strip_html(text: str) -> str:
        """Remove HTML tags."""
        return _HTML_TAG_RE.sub('', text)

    @staticmethod
    def _strip_css_hidden(text: str) -> str:
        """Remove CSS patterns commonly used to hide text."""
        text = _CSS_DISPLAY_NONE_RE.sub('', text)
        text = _CSS_FONT_ZERO_RE.sub('', text)
        text = _CSS_COLOR_WHITE_RE.sub('', text)
        return text

    @staticmethod
    def _strip_control_chars(text: str) -> str:
        """Remove Unicode control characters, keeping normal whitespace.

        Uses a pre-compiled regex covering Cc and Cf Unicode categories
        (excluding \\n, \\r, \\t, and space) instead of per-character
        unicodedata.category() lookups — ~20x faster on large inputs.
        """
        return _CONTROL_CHAR_RE.sub('', text)

    @staticmethod
    def _strip_bidi(text: str) -> str:
        """Remove bidirectional override and embedding characters."""
        # LRE, RLE, PDF, LRO, RLO, LRI, RLI, FSI, PDI
        return _BIDI_RE.sub('', text)

    @staticmethod
    def _strip_emoji_smuggling(text: str) -> str:
        """Remove emoji variation selectors and Unicode tag characters used for smuggling."""
        text = _VARIATION_SELECTOR_RE.sub('', text)
        text = _VARIATION_SUPP_RE.sub('', text)
        text = _TAG_CHARS_RE.sub('', text)
        return text

    def _normalize_unicode(self, text: str) -> str:
        """NFKC normalization — maps homoglyphs to canonical forms."""
        return unicodedata.normalize('NFKC', text)

    @staticmethod
    def _decode_encodings(text: str) -> str:
        """Decode HTML entities and percent-encoding (B1 / encoding_resistant).

        Runs html.unescape and urllib.parse.unquote. unquote is safe on
        ordinary text — `%` followed by non-hex is left alone — so an
        unencoded payload passes through unchanged. We catch the common
        attack-evasion shapes:
          - `&#60;script&#62;` → `<script>`
          - `&lt;script&gt;`   → `<script>`
          - `%3Cscript%3E`     → `<script>`
        Two-level encoding (`&amp;lt;` → `&lt;` → `<`) is handled by
        clean() running this method twice.
        """
        return unquote(html.unescape(text))

    @staticmethod
    def _collapse_whitespace(text: str) -> str:
        """Normalize excessive whitespace while preserving paragraph breaks."""
        text = _COLLAPSE_SPACES_RE.sub(' ', text)  # collapse spaces (preserve tabs)
        text = _COLLAPSE_NEWLINES_RE.sub('\n\n', text)  # collapse 3+ newlines to 2
        return text
