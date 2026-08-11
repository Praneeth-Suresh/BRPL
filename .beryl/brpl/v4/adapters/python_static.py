"""Trusted Python-specific extraction adapter for development validation only."""
from __future__ import annotations

import ast
import subprocess
import tomllib
from pathlib import Path
from typing import Any

from ..tree import candidate_tree_hash


def collect(root: Path, base: str, check_results: list[dict[str, str]] | None = None, relation: str = "source-import", manifest: str = "pyproject-toml") -> dict[str, Any]:
    """Produce normalized evidence without being imported by the v4 compiler/verifier.

    Dynamic imports, generated sources, and runtime module resolution are outside
    the declared static-Python universe; within that universe, syntax errors
    fail extraction rather than being silently treated as complete coverage.
    """
    root = root.resolve(strict=True)
    candidate = candidate_tree_hash(root)
    deltas = _manifest_delta(root, base, manifest, candidate)
    return {"schema": "brpl-evidence/v4", "candidate_tree": {"sha256": candidate}, "changes": _changes(root, base), "graphs": [{"relation": relation, "source_universe": "candidate-static-python-files", "target_universe": "candidate-static-python-files", "completeness": "complete", "adapter_binding": "brpl.v4.adapters.python-evidence-bundle.v1", "candidate_tree_sha256": candidate, "edges": _imports(root)}], "manifest_deltas": deltas, "checks": _checks(check_results or [], candidate), "metrics": []}


def _changes(root: Path, base: str) -> list[dict[str, str]]:
    output = _git(root, ["diff", "--raw", "-z", "-M", "-C", base, "--"])
    changes: list[dict[str, str]] = []
    fields = output.split("\0"); index = 0
    while index < len(fields) and fields[index]:
        header = fields[index]; index += 1
        if not header.startswith(":"): raise RuntimeError("unexpected git raw change record")
        metadata, first = header[1:].split("\t", 1) if "\t" in header else (header[1:], fields[index])
        if "\t" not in header: index += 1
        parts = metadata.split(); old_mode, new_mode, status = parts[0], parts[1], parts[4]
        code = status[0]
        if code in {"R", "C"}:
            old_path = first; path = fields[index]; index += 1
        else: old_path = None; path = first
        kind = {"A": "add", "D": "delete", "R": "rename", "C": "copy", "T": "type"}.get(code, "modify")
        if old_mode == "160000" or new_mode == "160000": kind = "submodule"
        elif old_mode == "120000" or new_mode == "120000": kind = "symlink"
        elif code == "M" and old_mode != new_mode: kind = "mode"
        item: dict[str, str] = {"status": code, "change_kind": kind, "path": path}
        if old_path is not None: item["old_path"] = old_path
        changes.append(item)
    for path in _git(root, ["ls-files", "--others", "--exclude-standard", "-z"]).split("\0"):
        if path:
            changes.append({"status": "?", "change_kind": "untracked", "path": path})
    return sorted(changes, key=lambda item: (item["path"], item.get("old_path", ""), item["status"]))


def _imports(root: Path) -> list[dict[str, str]]:
    files = [path for path in sorted(root.rglob("*.py")) if ".git" not in path.parts]
    modules: dict[str, str] = {}
    for path in files:
        relative = path.relative_to(root).with_suffix("")
        names = relative.parts[:-1] if relative.name == "__init__" else relative.parts
        for index in range(len(names)):
            module = ".".join(names[index:])
            if module in modules and modules[module] != path.relative_to(root).as_posix(): modules[module] = ""
            else: modules[module] = path.relative_to(root).as_posix()
    edges: list[dict[str, str]] = []
    for source in files:
        relative = source.relative_to(root).as_posix()
        try: tree = ast.parse(source.read_text(encoding="utf-8"), filename=relative)
        except (OSError, SyntaxError, UnicodeDecodeError) as exc: raise RuntimeError(f"cannot parse static Python source {relative}: {exc}") from exc
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for name in node.names:
                    if name.name in modules and not modules[name.name]: raise RuntimeError(f"ambiguous candidate module {name.name!r} from {relative}")
                    target = modules.get(name.name)
                    if target: edges.append({"source": relative, "target": target})
            elif isinstance(node, ast.ImportFrom):
                for target_module in _from_targets(node, source.relative_to(root), modules):
                    target = modules.get(target_module)
                    if not target:
                        raise RuntimeError(f"cannot resolve local relative import {target_module!r} from {relative}")
                    edges.append({"source": relative, "target": target})
    return [{"source": source, "target": target} for source, target in sorted({(item["source"], item["target"]) for item in edges})]


def _from_targets(node: ast.ImportFrom, source: Path, modules: dict[str, str]) -> list[str]:
    """Resolve static ImportFrom module dependencies within the candidate index.

    Absolute imports only contribute when their exact module is a candidate module.
    Every relative import is relevant to the declared candidate static-Python
    universe and therefore raises instead of silently disappearing if unresolved.
    """
    if node.level == 0:
        return [node.module] if node.module and modules.get(node.module) else []
    parts = list(source.with_suffix("").parts)
    package = parts[:-1] if parts[-1] != "__init__" else parts[:-1]
    remaining = len(package) - (node.level - 1)
    if remaining < 0:
        raise RuntimeError(f"relative import climbs above candidate package from {source.as_posix()}")
    prefix = package[:remaining]
    if node.module:
        target = ".".join([*prefix, *node.module.split(".")])
        return [target]
    targets: list[str] = []
    for alias in node.names:
        target = ".".join([*prefix, alias.name])
        if not target:
            raise RuntimeError(f"relative import has no candidate module from {source.as_posix()}")
        targets.append(target)
    return targets


def _manifest_delta(root: Path, base: str, manifest: str, candidate: str) -> list[dict[str, Any]]:
    candidate_path = root / "pyproject.toml"
    if not candidate_path.is_file():
        raise RuntimeError("required candidate pyproject.toml is missing")
    current = _dependencies(candidate_path.read_bytes(), "candidate pyproject.toml")
    try: previous = _dependencies(_git(root, ["show", f"{base}:pyproject.toml"]).encode(), "baseline pyproject.toml")
    except RuntimeError as exc:
        raise RuntimeError("required baseline pyproject.toml is missing or unreadable") from exc
    return [{"manifest": manifest, "added": sorted(current - previous), "removed": sorted(previous - current), "completeness": "complete", "candidate_tree_sha256": candidate}]


def _dependencies(payload: bytes, label: str) -> set[str]:
    try: project = tomllib.loads(payload.decode("utf-8")).get("project", {})
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc: raise RuntimeError(f"invalid {label}: {exc}") from exc
    if not isinstance(project, dict) or not isinstance(project.get("dependencies", []), list): raise RuntimeError(f"invalid {label} dependencies")
    return {value.split(";", 1)[0].split("[", 1)[0].split(" ", 1)[0].lower() for value in project.get("dependencies", []) if isinstance(value, str)}


def _checks(results: list[dict[str, str]], candidate: str) -> list[dict[str, str]]:
    seen: set[str] = set(); normalized: list[dict[str, str]] = []
    for result in results:
        if not isinstance(result, dict) or set(result) != {"check", "status"} or not isinstance(result["check"], str) or not result["check"] or result.get("status") not in {"pass", "fail", "error"} or result["check"] in seen:
            raise ValueError("fixed check results must contain unique check/status pass|fail|error records")
        seen.add(result["check"]); normalized.append({"check": result["check"], "status": result["status"], "candidate_tree_sha256": candidate})
    return sorted(normalized, key=lambda item: item["check"])


def _git(root: Path, args: list[str]) -> str:
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, check=False)
    if result.returncode: raise RuntimeError(result.stderr.strip() or "git command failed")
    return result.stdout
