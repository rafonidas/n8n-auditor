"""Load workflows from files, directories, globs or a live n8n instance."""
from __future__ import annotations

import glob as globlib
import json
import os
from pathlib import Path

import httpx

from .model import Workflow


class LoadError(Exception):
    pass


def load_file(path: str | Path) -> Workflow:
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        raise LoadError(f"{path}: cannot parse as JSON ({e})") from e
    if not isinstance(data, dict) or "nodes" not in data:
        raise LoadError(f"{path}: not an n8n workflow export (missing 'nodes')")
    return Workflow.from_json(data, source_path=str(path))


def load_paths(paths: list[str], directory: str | None = None) -> tuple[list[Workflow], list[str]]:
    """Resolve files/dirs/globs into workflows. Returns (workflows, errors)."""
    files: list[Path] = []
    if directory:
        files.extend(sorted(Path(directory).rglob("*.json")))
    for p in paths:
        path = Path(p)
        if path.is_dir():
            files.extend(sorted(path.rglob("*.json")))
        elif path.is_file():
            files.append(path)
        elif any(ch in p for ch in "*?["):
            files.extend(sorted(Path(f) for f in globlib.glob(p, recursive=True)))
        else:
            raise LoadError(f"{p}: not found")

    workflows: list[Workflow] = []
    errors: list[str] = []
    seen: set[str] = set()
    for f in files:
        key = str(f.resolve())
        if key in seen:
            continue
        seen.add(key)
        # Skip companion files from the eval fixtures.
        if f.name.endswith("expected.json") or f.name == "baseline.json":
            continue
        try:
            workflows.append(load_file(f))
        except LoadError as e:
            errors.append(str(e))
    return workflows, errors


def load_remote(api_url: str | None = None, api_key: str | None = None) -> list[Workflow]:
    """Download every workflow from a live instance via the public REST API."""
    api_url = (api_url or os.environ.get("N8N_API_URL", "")).rstrip("/")
    api_key = api_key or os.environ.get("N8N_API_KEY", "")
    if not api_url or not api_key:
        raise LoadError("Remote scan needs N8N_API_URL and N8N_API_KEY (in .env or environment)")

    workflows: list[Workflow] = []
    headers = {"X-N8N-API-KEY": api_key, "Accept": "application/json"}
    cursor: str | None = None
    with httpx.Client(headers=headers, timeout=30) as client:
        while True:
            params: dict[str, str] = {"limit": "100"}
            if cursor:
                params["cursor"] = cursor
            resp = client.get(f"{api_url}/api/v1/workflows", params=params)
            resp.raise_for_status()
            payload = resp.json()
            for item in payload.get("data", []):
                workflows.append(Workflow.from_json(item, source_path=f"remote:{item.get('id')}"))
            cursor = payload.get("nextCursor")
            if not cursor:
                break
    return workflows
