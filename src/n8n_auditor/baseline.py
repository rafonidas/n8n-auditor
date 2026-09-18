"""Baseline support: suppress already-known findings by fingerprint."""
from __future__ import annotations

import json
from pathlib import Path

from .model import Finding


def load(path: str | Path) -> set[str]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(data, dict):
        entries = data.get("findings", data.get("fingerprints", []))
    else:
        entries = data
    fingerprints: set[str] = set()
    for entry in entries:
        if isinstance(entry, str):
            fingerprints.add(entry)
        elif isinstance(entry, dict) and entry.get("fingerprint"):
            fingerprints.add(entry["fingerprint"])
    return fingerprints


def apply(findings: list[Finding], fingerprints: set[str]) -> tuple[list[Finding], int]:
    kept = [f for f in findings if f.fingerprint not in fingerprints]
    return kept, len(findings) - len(kept)


def write(findings: list[Finding], path: str | Path) -> None:
    doc = {"fingerprints": sorted({f.fingerprint for f in findings})}
    Path(path).write_text(json.dumps(doc, indent=2), encoding="utf-8")
