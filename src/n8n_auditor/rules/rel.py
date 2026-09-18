"""REL — reliability rules."""
from __future__ import annotations

import re

from ..crossref import error_trigger_ok, index_by_id
from ..jsonwalk import walk_strings
from ..model import Finding, Workflow
from . import REGISTRY, ScanContext, make_finding, rule

FLAKY_NODE_TYPES = {
    "httpRequest", "postgres", "mySql", "microsoftSql", "mongoDb", "supabase", "redis",
    "ftp", "ssh", "emailSend", "gmail", "microsoftOutlook",
}

DB_NODE_TYPES = {"postgres", "mySql", "microsoftSql", "mongoDb", "supabase"}

TODO_MARKER = re.compile(r"(?i)\b(todo|fixme|pending|wip)\b")
EMPTY_REQUIRED_KEYS = {"dataTableId", "workflowId", "tableId", "documentId", "sheetId", "baseId"}

WORKFLOW_NAME_ROUTING = re.compile(r"\$workflow\.name|\$json(?:\.workflow)?\.workflow[._]?name|workflow\.name", re.IGNORECASE)

DATEISH_FIELD = re.compile(r"(?i)(date|fecha|created|updated|time|timestamp)")

POLLABLE_SERVICES_WITH_WEBHOOKS = {
    "github", "gitlab", "stripe", "slack", "shopify", "typeform", "calendly", "hubspot",
    "jira", "trello", "airtable", "chatwoot", "telegram", "intercom", "zendesk",
}


@rule(
    id="REL-001", severity="high", category="reliability",
    title="Active workflow without error workflow",
    description="The workflow is active but settings.errorWorkflow is not set: failures die "
    "silently with no notification path.",
)
def rel_001(wf: Workflow, ctx: ScanContext) -> list[Finding]:
    r = REGISTRY["REL-001"]
    if wf.active and not wf.settings.get("errorWorkflow"):
        return [make_finding(
            r, wf, path="/settings/errorWorkflow",
            evidence="active: true, errorWorkflow: (not set)",
            fix="Create an error workflow (Error Trigger → notification) and set it in "
                "workflow settings.",
        )]
    return []


@rule(
    id="REL-002", severity="high", category="reliability",
    title="Error workflow broken or missing",
    description="settings.errorWorkflow points to a workflow id that does not exist in the set, "
    "or exists but has no enabled Error Trigger node.",
    cross_workflow=True,
)
def rel_002(workflows: list[Workflow], ctx: ScanContext) -> list[Finding]:
    r = REGISTRY["REL-002"]
    findings: list[Finding] = []
    by_id = index_by_id(workflows)
    for wf in workflows:
        target_id = wf.settings.get("errorWorkflow")
        if not target_id:
            continue
        target = by_id.get(str(target_id))
        if target is None:
            findings.append(make_finding(
                r, wf, path="/settings/errorWorkflow",
                evidence=f"errorWorkflow: {target_id} (not found in scanned set)",
                fix="Point errorWorkflow at an existing workflow with an Error Trigger.",
            ))
        elif not error_trigger_ok(target):
            findings.append(make_finding(
                r, wf, path="/settings/errorWorkflow",
                evidence=f"errorWorkflow: {target_id} ('{target.name}') has no enabled Error Trigger",
                fix="Add (or re-enable) an Error Trigger node in the target workflow.",
            ))
    return findings


@rule(
    id="REL-003", severity="medium", category="reliability",
    title="Network/DB node without retry or error handling",
    description="An HTTP/DB/FTP/mail node has neither retryOnFail nor an onError strategy: a "
    "transient 500 kills the whole execution.",
)
def rel_003(wf: Workflow, ctx: ScanContext) -> list[Finding]:
    r = REGISTRY["REL-003"]
    findings: list[Finding] = []
    for node in wf.nodes:
        if node.base_type not in FLAKY_NODE_TYPES or node.disabled:
            continue
        raw = node.raw
        has_retry = bool(raw.get("retryOnFail"))
        on_error = raw.get("onError", "")
        has_on_error = on_error in ("continueErrorOutput", "continueRegularOutput") or bool(
            raw.get("continueOnFail")
        )
        if not has_retry and not has_on_error:
            findings.append(make_finding(
                r, wf,
                node_name=node.name, node_type=node.type, path="/retryOnFail",
                evidence="retryOnFail: false, onError: stopWorkflow (default)",
                fix="Enable Retry On Fail (2-3 tries with wait) and/or route the error output.",
            ))
    return findings


@rule(
    id="REL-004", severity="high", category="reliability",
    title="Required parameter left empty (inert logic)",
    description="A required id parameter is empty (dataTableId, workflowId, tableId...) or a "
    "TODO/FIXME note references the node: the branch looks alive but does nothing.",
)
def rel_004(wf: Workflow, ctx: ScanContext) -> list[Finding]:
    r = REGISTRY["REL-004"]
    findings: list[Finding] = []
    sticky_todos = " ".join(
        str(n.parameters.get("content", "")) for n in wf.nodes
        if n.base_type == "stickyNote" and TODO_MARKER.search(str(n.parameters.get("content", "")))
    )
    for node in wf.nodes:
        if node.disabled:
            continue
        for pointer, key, value in walk_strings(node.parameters):
            bare = value.strip()
            is_empty_required = key in EMPTY_REQUIRED_KEYS and bare == ""
            # Also catch resource locator shape: {"__rl": true, "value": ""}
            if not is_empty_required and key == "value" and bare == "" and pointer.endswith("/value"):
                parent = pointer.rsplit("/", 1)[0].rsplit("/", 1)[-1]
                is_empty_required = parent in EMPTY_REQUIRED_KEYS
            if is_empty_required:
                findings.append(make_finding(
                    r, wf,
                    node_name=node.name, node_type=node.type,
                    path=f"/parameters{pointer}",
                    evidence=f"{key}: \"\" (empty)",
                    fix="Fill in the required id or remove the node; empty ids silently no-op "
                        "or fail at runtime.",
                ))
        if TODO_MARKER.search(node.notes or "") or (sticky_todos and node.name in sticky_todos):
            findings.append(make_finding(
                r, wf, severity="medium",
                node_name=node.name, node_type=node.type, path="/notes",
                evidence="TODO/FIXME marker referencing this node",
                fix="Resolve the TODO or track it outside the production workflow.",
                confidence="medium",
            ))
    return findings


@rule(
    id="REL-005", severity="medium", category="reliability",
    title="Routing by workflow name",
    description="An If/Switch compares $workflow.name against a literal. Names change; ids "
    "don't. Renaming the workflow silently breaks the route.",
)
def rel_005(wf: Workflow, ctx: ScanContext) -> list[Finding]:
    r = REGISTRY["REL-005"]
    findings: list[Finding] = []
    for node in wf.nodes:
        if node.base_type not in {"if", "switch", "filter"} or node.disabled:
            continue
        for pointer, _key, value in walk_strings(node.parameters):
            if WORKFLOW_NAME_ROUTING.search(value):
                findings.append(make_finding(
                    r, wf,
                    node_name=node.name, node_type=node.type,
                    path=f"/parameters{pointer}",
                    evidence=value[:80],
                    fix="Route by $workflow.id (stable) instead of the display name.",
                ))
                break
    return findings


@rule(
    id="REL-006", severity="low", category="reliability",
    title="Duplicate triggers with identical configuration",
    description="Two or more triggers of the same type share the same configuration (identical "
    "cron, same webhook path): double executions or dead code.",
)
def rel_006(wf: Workflow, ctx: ScanContext) -> list[Finding]:
    import json

    r = REGISTRY["REL-006"]
    findings: list[Finding] = []
    seen: dict[tuple[str, str], str] = {}
    for node in wf.trigger_nodes:
        if node.disabled:
            continue
        key = (node.type, json.dumps(node.parameters, sort_keys=True))
        if key in seen:
            findings.append(make_finding(
                r, wf,
                node_name=node.name, node_type=node.type, path="/parameters",
                evidence=f"same type and config as trigger '{seen[key]}'",
                fix="Remove the duplicate trigger or differentiate its configuration.",
            ))
        else:
            seen[key] = node.name
    return findings


@rule(
    id="REL-007", severity="low", category="reliability",
    title="Timezone not set or unexpected",
    description="settings.timezone is absent (falls back to instance default) or differs from "
    "the expected timezone: cron schedules drift.",
)
def rel_007(wf: Workflow, ctx: ScanContext) -> list[Finding]:
    r = REGISTRY["REL-007"]
    tz = wf.settings.get("timezone")
    has_cron = any(n.base_type in {"scheduleTrigger", "cron"} for n in wf.nodes)
    if not has_cron:
        return []
    if not tz:
        return [make_finding(
            r, wf, path="/settings/timezone",
            evidence="timezone: (not set)",
            fix="Set an explicit timezone in workflow settings so schedules survive instance "
                "moves.",
            confidence="medium",
        )]
    if ctx.expected_timezone and tz != ctx.expected_timezone:
        return [make_finding(
            r, wf, path="/settings/timezone",
            evidence=f"timezone: {tz} (expected {ctx.expected_timezone})",
            fix=f"Align the workflow timezone with {ctx.expected_timezone}.",
        )]
    return []


@rule(
    id="REL-008", severity="medium", category="reliability",
    title="Sorting a date-like field as string",
    description="A Sort node (or .sort() in code) orders by a field whose name suggests a date "
    "but is treated as a string: alphabetical order is not chronological order.",
)
def rel_008(wf: Workflow, ctx: ScanContext) -> list[Finding]:
    r = REGISTRY["REL-008"]
    findings: list[Finding] = []
    for node in wf.nodes:
        if node.disabled:
            continue
        if node.base_type in {"sort", "itemLists"}:
            fields = node.parameters.get("sortFieldsUi", {}) or node.parameters.get("fieldsToSortBy", {})
            for pointer, key, value in walk_strings(fields):
                if key == "fieldName" and DATEISH_FIELD.search(value):
                    # n8n Sort node compares strings unless the data is a real Date.
                    findings.append(make_finding(
                        r, wf,
                        node_name=node.name, node_type=node.type,
                        path=f"/parameters/sortFieldsUi{pointer}",
                        evidence=f"sorting by '{value}'",
                        fix="Convert the field to a real date (Date/Luxon) before sorting, or "
                            "sort in the source query (ORDER BY).",
                        confidence="medium",
                    ))
        code = node.parameters.get("jsCode") or ""
        if isinstance(code, str) and ".sort(" in code:
            m = re.search(r"\.sort\(\s*\(?\s*(\w+)\s*,\s*(\w+)\s*\)?\s*=>\s*[^)]*?(\w+)\.(\w+)", code)
            field_name = m.group(4) if m else None
            if field_name and DATEISH_FIELD.search(field_name) and "new Date" not in code and "Date.parse" not in code and "DateTime" not in code:
                findings.append(make_finding(
                    r, wf,
                    node_name=node.name, node_type=node.type,
                    path="/parameters/jsCode",
                    evidence=f".sort() on '{field_name}' without date parsing",
                    fix="Parse the values with new Date()/Luxon inside the comparator.",
                    confidence="medium",
                ))
    return findings


def _execute_workflow_target(node) -> str | None:
    wid = node.parameters.get("workflowId")
    if isinstance(wid, dict):  # resource locator
        return str(wid.get("value", "") or "")
    if wid is None:
        return None
    return str(wid)


@rule(
    id="REL-009", severity="high", category="reliability",
    title="Execute Workflow target missing",
    description="An Execute Workflow node points to a workflow id that does not exist in the "
    "scanned set, or is empty.",
    cross_workflow=True,
)
def rel_009(workflows: list[Workflow], ctx: ScanContext) -> list[Finding]:
    r = REGISTRY["REL-009"]
    findings: list[Finding] = []
    by_id = index_by_id(workflows)
    for wf in workflows:
        for node in wf.nodes:
            if node.base_type not in {"executeWorkflow", "executeWorkflowTrigger"} or node.disabled:
                continue
            if node.base_type == "executeWorkflowTrigger":
                continue
            target = _execute_workflow_target(node)
            if target is None:
                continue
            if target == "":
                findings.append(make_finding(
                    r, wf,
                    node_name=node.name, node_type=node.type,
                    path="/parameters/workflowId", evidence="workflowId: \"\" (empty)",
                    fix="Select the target sub-workflow.",
                ))
            elif target not in by_id:
                findings.append(make_finding(
                    r, wf,
                    node_name=node.name, node_type=node.type,
                    path="/parameters/workflowId",
                    evidence=f"workflowId: {target} (not found in scanned set)",
                    fix="The target workflow was deleted or renamed; repoint the node.",
                ))
    return findings


@rule(
    id="REL-010", severity="low", category="reliability",
    title="Disabled nodes left in the workflow",
    description="Nodes with disabled: true remain in the flow: dead code that confuses "
    "maintenance and hides intent.",
)
def rel_010(wf: Workflow, ctx: ScanContext) -> list[Finding]:
    r = REGISTRY["REL-010"]
    disabled = [n for n in wf.nodes if n.disabled and n.base_type != "stickyNote"]
    return [
        make_finding(
            r, wf,
            node_name=n.name, node_type=n.type, path="/disabled",
            evidence="disabled: true",
            fix="Delete the node (git/backup keeps history) or document why it stays.",
        )
        for n in disabled
    ]


_INSERT_SQL = re.compile(r"(?is)\binsert\s+into\b")
_ON_CONFLICT = re.compile(r"(?is)\bon\s+conflict\b|\bon\s+duplicate\s+key\b|\bmerge\s+into\b")


@rule(
    id="REL-011", severity="medium", category="reliability",
    title="Non-idempotent DB write on a polling/cron trigger",
    description="An INSERT without ON CONFLICT and no prior existence check, in a workflow "
    "triggered by cron/polling: a double run inserts duplicates.",
)
def rel_011(wf: Workflow, ctx: ScanContext) -> list[Finding]:
    r = REGISTRY["REL-011"]
    findings: list[Finding] = []
    has_cron = any(
        n.base_type in {"scheduleTrigger", "cron", "interval"} and not n.disabled for n in wf.nodes
    )
    if not has_cron:
        return findings
    for node in wf.nodes:
        if node.base_type not in DB_NODE_TYPES or node.disabled:
            continue
        query = str(node.parameters.get("query", ""))
        op = str(node.parameters.get("operation", "")).lower()
        is_insert = _INSERT_SQL.search(query) or op == "insert"
        if not is_insert or _ON_CONFLICT.search(query):
            continue
        # Existence check heuristic: an upstream node in the same workflow runs a SELECT
        # or an If node filters before this write.
        has_check = any(
            (other.base_type in DB_NODE_TYPES and _READ_ONLY.search(str(other.parameters.get("query", ""))))
            or other.base_type in {"if", "filter", "removeDuplicates"}
            for other in wf.nodes
            if other.name != node.name and not other.disabled and node.name in {s.name for s in wf.successors(other.name)}
        )
        if has_check:
            continue
        findings.append(make_finding(
            r, wf,
            node_name=node.name, node_type=node.type, path="/parameters/query",
            evidence="INSERT without ON CONFLICT on a cron-triggered workflow",
            fix="Make the write idempotent: ON CONFLICT DO NOTHING/UPDATE, a unique key, or an "
                "existence check before inserting.",
            confidence="low",
        ))
    return findings


_READ_ONLY = re.compile(r"(?is)^\s*select\b")


@rule(
    id="REL-012", severity="medium", category="reliability",
    title="Polling a service that offers webhooks",
    description="A Schedule trigger polls a service (HTTP get) that is known to support "
    "webhooks: event-driven would be cheaper and faster.",
)
def rel_012(wf: Workflow, ctx: ScanContext) -> list[Finding]:
    r = REGISTRY["REL-012"]
    findings: list[Finding] = []
    has_schedule = any(
        n.base_type in {"scheduleTrigger", "cron", "interval"} and not n.disabled for n in wf.nodes
    )
    if not has_schedule:
        return findings
    for node in wf.nodes:
        if node.disabled:
            continue
        service = None
        if node.base_type == "httpRequest":
            url = str(node.parameters.get("url", "")).lower()
            method = str(node.parameters.get("method", "GET")).upper()
            if method != "GET":
                continue
            service = next((s for s in POLLABLE_SERVICES_WITH_WEBHOOKS if s in url), None)
        elif node.base_type.lower() in POLLABLE_SERVICES_WITH_WEBHOOKS:
            op = str(node.parameters.get("operation", "")).lower()
            if op and op not in {"get", "getall", "search", "list"}:
                continue
            service = node.base_type.lower()
        if service:
            findings.append(make_finding(
                r, wf,
                node_name=node.name, node_type=node.type, path="/parameters",
                evidence=f"cron polling '{service}', which supports webhooks",
                fix=f"Replace the schedule+poll with a {service} webhook/trigger node.",
                confidence="low",
            ))
    return findings
