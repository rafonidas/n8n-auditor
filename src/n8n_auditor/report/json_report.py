"""Stable, versioned JSON output."""
from __future__ import annotations

import json
from typing import Any

from ..model import Finding

SCHEMA_VERSION = "1.0"


def render(
    findings: list[Finding],
    llm_results: dict[str, Any] | None = None,
    skipped_rules: list[str] | None = None,
) -> str:
    doc: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "findings": [f.to_dict() for f in findings],
    }
    if skipped_rules:
        doc["skipped_rules"] = sorted(skipped_rules)
    if llm_results:
        doc["llm"] = llm_results
    return json.dumps(doc, indent=2, ensure_ascii=False)
