"""Cross-workflow indexing helpers used by cross-workflow rules."""
from __future__ import annotations

from .model import Node, Workflow


def index_by_id(workflows: list[Workflow]) -> dict[str, Workflow]:
    return {wf.id: wf for wf in workflows if wf.id}


def all_credentials(workflows: list[Workflow]) -> list[tuple[Workflow, Node, str, str, str]]:
    """Yield (workflow, node, cred_type, cred_id, cred_name) for every credential reference."""
    out = []
    for wf in workflows:
        for node in wf.nodes:
            for cred_type, cred in node.credentials.items():
                if isinstance(cred, dict):
                    out.append((wf, node, cred_type, str(cred.get("id", "")), cred.get("name", "")))
    return out


def error_trigger_ok(wf: Workflow) -> bool:
    return any(
        n.base_type == "errorTrigger" and not n.disabled for n in wf.nodes
    )
