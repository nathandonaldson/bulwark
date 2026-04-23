"""Load + validate the benign corpus (ADR-036, G-FP-005)."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class CorpusEmail:
    id: str
    category: str
    subject: str
    body: str

    @property
    def text(self) -> str:
        """Concatenated subject + body — what /v1/clean sees."""
        return f"Subject: {self.subject}\n\n{self.body}"


def load_corpus(path: Path | str) -> list[CorpusEmail]:
    """Load a JSONL corpus file. Skips blank lines; raises on malformed entries."""
    p = Path(path)
    out: list[CorpusEmail] = []
    seen_ids: set[str] = set()
    with p.open(encoding="utf-8") as f:
        for lineno, raw in enumerate(f, start=1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{p}:{lineno}: invalid JSON: {exc}") from exc
            for k in ("id", "category", "subject", "body"):
                if k not in obj:
                    raise ValueError(f"{p}:{lineno}: missing field {k!r}")
            email = CorpusEmail(
                id=str(obj["id"]),
                category=str(obj["category"]),
                subject=str(obj["subject"]),
                body=str(obj["body"]),
            )
            if email.id in seen_ids:
                raise ValueError(f"{p}:{lineno}: duplicate id {email.id!r}")
            seen_ids.add(email.id)
            out.append(email)
    if not out:
        raise ValueError(f"{p}: corpus is empty")
    return out


def categories(corpus: Iterable[CorpusEmail]) -> dict[str, int]:
    """Return {category: count} for a loaded corpus."""
    counts: dict[str, int] = {}
    for email in corpus:
        counts[email.category] = counts.get(email.category, 0) + 1
    return counts
