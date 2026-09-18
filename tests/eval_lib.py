"""Shared fixture-evaluation machinery for the precision/recall test suite.

A *fixture unit* is either:
  - a single ``foo.json`` workflow with a ``foo.expected.json`` beside it, or
  - a directory containing several ``*.json`` workflows plus one ``expected.json``
    (used by cross-workflow rules, which need the full set).

``expected.json`` format::

    {
      "options": {"allowed_domains": [...], "expected_timezone": "...", ...},
      "expected": [{"rule_id": "SEC-001", "node_name": "...", "severity": "high"}]
    }

Scoring: an expected entry is a TP when at least one finding matches it
(rule_id, plus node_name/severity when given). Unmatched non-``info`` findings
count as FP; ``info`` findings are inventory, not defects, and are never FPs
(but they can still satisfy an expected entry, so recall on info rules works).
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path

from n8n_auditor.engine import scan
from n8n_auditor.loader import load_file
from n8n_auditor.model import Finding
from n8n_auditor.rules import ScanContext

FIXTURES = Path(__file__).parent / "fixtures"


@dataclass
class Unit:
    name: str
    workflows: list
    expected: list[dict]
    options: dict


@dataclass
class Score:
    tp: int = 0
    fp: int = 0
    fn: int = 0

    @property
    def precision(self) -> float:
        return self.tp / (self.tp + self.fp) if (self.tp + self.fp) else 1.0

    @property
    def recall(self) -> float:
        return self.tp / (self.tp + self.fn) if (self.tp + self.fn) else 1.0


@dataclass
class EvalResult:
    per_rule: dict[str, Score] = field(default_factory=lambda: defaultdict(Score))
    total: Score = field(default_factory=Score)
    failures: list[str] = field(default_factory=list)


def discover_units(subdir: str) -> list[Unit]:
    root = FIXTURES / subdir
    units: list[Unit] = []
    if not root.exists():
        return units
    for entry in sorted(root.iterdir()):
        if entry.is_dir():
            exp_file = entry / "expected.json"
            wf_files = [f for f in sorted(entry.glob("*.json")) if f.name != "expected.json"]
            if not exp_file.exists() or not wf_files:
                continue
            spec = json.loads(exp_file.read_text(encoding="utf-8"))
            units.append(Unit(entry.name, [load_file(f) for f in wf_files],
                              spec.get("expected", []), spec.get("options", {})))
        elif entry.suffix == ".json" and not entry.name.endswith(".expected.json"):
            exp_file = entry.with_name(entry.stem + ".expected.json")
            if not exp_file.exists():
                continue
            spec = json.loads(exp_file.read_text(encoding="utf-8"))
            units.append(Unit(entry.stem, [load_file(entry)],
                              spec.get("expected", []), spec.get("options", {})))
    return units


def run_unit(unit: Unit) -> list[Finding]:
    ctx = ScanContext(full_set=len(unit.workflows) > 1)
    for key, value in unit.options.items():
        setattr(ctx, key, value)
    findings, _ = scan(unit.workflows, ctx)
    return findings


def _matches(expected: dict, finding: Finding) -> bool:
    if expected["rule_id"] != finding.rule_id:
        return False
    if "node_name" in expected and expected["node_name"] != finding.node_name:
        return False
    if "severity" in expected and expected["severity"] != finding.severity:
        return False
    if "workflow_name" in expected and expected["workflow_name"] != finding.workflow_name:
        return False
    return True


def evaluate(units: list[Unit]) -> EvalResult:
    result = EvalResult()
    for unit in units:
        findings = run_unit(unit)
        matched_findings: set[int] = set()
        for exp in unit.expected:
            hit = next(
                (i for i, f in enumerate(findings) if i not in matched_findings and _matches(exp, f)),
                None,
            )
            rule_id = exp["rule_id"]
            if hit is None:
                result.per_rule[rule_id].fn += 1
                result.total.fn += 1
                result.failures.append(f"{unit.name}: MISSED {exp}")
            else:
                matched_findings.add(hit)
                result.per_rule[rule_id].tp += 1
                result.total.tp += 1
        for i, f in enumerate(findings):
            if i in matched_findings or f.severity == "info":
                continue
            result.per_rule[f.rule_id].fp += 1
            result.total.fp += 1
            result.failures.append(
                f"{unit.name}: UNEXPECTED {f.rule_id} [{f.severity}] on "
                f"'{f.workflow_name}' node '{f.node_name}' ({f.evidence})"
            )
    return result


def print_table(name: str, results: dict[str, EvalResult]) -> None:
    """Print a combined precision/recall table across eval sets."""
    rules: set[str] = set()
    for res in results.values():
        rules.update(res.per_rule)
    print(f"\n=== {name} ===")
    header = f"{'rule':10}" + "".join(f"{s + ' P':>10}{s + ' R':>10}" for s in results)
    print(header)
    for rule_id in sorted(rules):
        row = f"{rule_id:10}"
        for res in results.values():
            s = res.per_rule.get(rule_id)
            row += f"{s.precision:>10.2f}{s.recall:>10.2f}" if s else f"{'—':>10}{'—':>10}"
        print(row)
    row = f"{'TOTAL':10}"
    for res in results.values():
        row += f"{res.total.precision:>10.2f}{res.total.recall:>10.2f}"
    print(row)
