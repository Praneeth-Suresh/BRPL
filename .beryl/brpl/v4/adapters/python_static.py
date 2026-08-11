"""Trusted Python-specific extraction adapter for development validation only."""
from __future__ import annotations

import ast
import hashlib
import subprocess
import tomllib
from pathlib import Path
from typing import Any


def collect(root: Path, base: str, check_results: list[dict[str, str]] | None = None, relation: str = "source-import", manifest: str = "pyproject-toml") -> dict[str, Any]:
    """Produce normalized evidence without being imported by the v4 compiler/verifier.

    Dynamic imports, generated sources, and runtime module resolution are outside
    the declared static-Python universe; within that universe, syntax errors
    fail extraction rather than being silently treated as complete coverage.
    """
    root = root.resolve(strict=True)
    candidate = _tree_hash(root)
    return {"schema": "brpl-evidence/v4", "candidate_tree": {"sha256": candidate}, "changes": _changes(root, base), "graphs": [{"relation": relation, "source_universe": "candidate-static-python-files", "target_universe": "candidate-static-python-files", "completeness": "complete", "adapter_binding": "brpl.v4.adapters.python-evidence-bundle.v1", "candidate_tree_sha256": candidate, "edges": _imports(root)}], "manifest_deltas": [_manifest_delta(root, base, manifest, candidate)], "checks": _checks(check_results or [], candidate), "metrics": []}


def _changes(root: Path, base: str) -> list[dict[str, str]]:
    output = _git(root, ["diff", "--name-status", "-M", base, "--"])
    changes: list[dict[str, str]] = []
    for line in output.splitlines():
        fields = line.split("\t")
        if len(fields) == 2: changes.append({"status": fields[0], "path": fields[1]})
        elif len(fields) == 3: changes.append({"status": fields[0], "old_path": fields[1], "path": fields[2]})
    return changes


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


def _manifest_delta(root: Path, base: str, manifest: str, candidate: str) -> dict[str, Any]:
    current = _dependencies((root / "pyproject.toml").read_bytes()) if (root / "pyproject.toml").is_file() else set()
    try: previous = _dependencies(_git(root, ["show", f"{base}:pyproject.toml"]).encode())
    except RuntimeError: previous = set()
    return {"manifest": manifest, "added": sorted(current - previous), "removed": sorted(previous - current), "completeness": "complete", "candidate_tree_sha256": candidate}


def _dependencies(payload: bytes) -> set[str]:
    try: project = tomllib.loads(payload.decode("utf-8")).get("project", {})
    except (UnicodeDecodeError, tomllib.TOMLDecodeError): return set()
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


def _tree_hash(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file() and ".git" not in item.parts):
        relative = path.relative_to(root).as_posix().encode(); digest.update(len(relative).to_bytes(8, "big")); digest.update(relative); content = path.read_bytes(); digest.update(len(content).to_bytes(8, "big")); digest.update(content)
    return digest.hexdigest()
