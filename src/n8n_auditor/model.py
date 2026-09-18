"""Core data model: Workflow, Node, Finding."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterator

SEVERITIES = ["info", "low", "medium", "high", "critical"]


def severity_rank(sev: str) -> int:
    return SEVERITIES.index(sev)


@dataclass
class Node:
    name: str
    type: str
    type_version: float | int | None
    parameters: dict[str, Any]
    credentials: dict[str, Any]
    disabled: bool
    notes: str
    raw: dict[str, Any]

    @classmethod
    def from_json(cls, data: dict[str, Any]) -> "Node":
        return cls(
            name=data.get("name", ""),
            type=data.get("type", ""),
            type_version=data.get("typeVersion"),
            parameters=data.get("parameters") or {},
            credentials=data.get("credentials") or {},
            disabled=bool(data.get("disabled", False)),
            notes=data.get("notes") or "",
            raw=data,
        )

    @property
    def base_type(self) -> str:
        """Node type without package prefix, e.g. 'webhook' for 'n8n-nodes-base.webhook'."""
        return self.type.rsplit(".", 1)[-1]


@dataclass
class Workflow:
    name: str
    id: str | None
    active: bool
    nodes: list[Node]
    connections: dict[str, Any]
    settings: dict[str, Any]
    pin_data: dict[str, Any]
    meta: dict[str, Any]
    source_path: str | None
    raw: dict[str, Any]

    @classmethod
    def from_json(cls, data: dict[str, Any], source_path: str | None = None) -> "Workflow":
        return cls(
            name=data.get("name", "(unnamed)"),
            id=data.get("id"),
            active=bool(data.get("active", False)),
            nodes=[Node.from_json(n) for n in data.get("nodes") or [] if isinstance(n, dict)],
            connections=data.get("connections") or {},
            settings=data.get("settings") or {},
            pin_data=data.get("pinData") or {},
            meta=data.get("meta") or {},
            source_path=source_path,
            raw=data,
        )

    def node(self, name: str) -> Node | None:
        return next((n for n in self.nodes if n.name == name), None)

    def successors(self, node_name: str) -> Iterator[Node]:
        """Yield all nodes reachable downstream of node_name (any output, any connection type)."""
        seen: set[str] = set()
        stack = [node_name]
        while stack:
            current = stack.pop()
            conns = self.connections.get(current)
            if not isinstance(conns, dict):
                continue
            for outputs in conns.values():
                if not isinstance(outputs, list):
                    continue
                for branch in outputs:
                    if not isinstance(branch, list):
                        continue
                    for link in branch:
                        target = link.get("node") if isinstance(link, dict) else None
                        if target and target not in seen:
                            seen.add(target)
                            stack.append(target)
                            node = self.node(target)
                            if node:
                                yield node

    @property
    def trigger_nodes(self) -> list[Node]:
        return [n for n in self.nodes if "trigger" in n.base_type.lower() or n.base_type == "webhook"]


@dataclass
class Finding:
    rule_id: str
    severity: str
    category: str
    title: str
    description: str
    workflow_id: str | None
    workflow_name: str
    node_name: str | None = None
    node_type: str | None = None
    path: str | None = None
    evidence: str | None = None
    fix: str | None = None
    confidence: str = "high"
    source: str = "static"
    extra: dict[str, Any] = field(default_factory=dict)

    @property
    def fingerprint(self) -> str:
        return "|".join(
            [self.rule_id, self.workflow_id or self.workflow_name, self.node_name or "", self.path or ""]
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "category": self.category,
            "title": self.title,
            "description": self.description,
            "workflow_id": self.workflow_id,
            "workflow_name": self.workflow_name,
            "node": {"name": self.node_name, "type": self.node_type} if self.node_name else None,
            "path": self.path,
            "evidence": self.evidence,
            "fix": self.fix,
            "confidence": self.confidence,
            "source": self.source,
            "fingerprint": self.fingerprint,
        }
