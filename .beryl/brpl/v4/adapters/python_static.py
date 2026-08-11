"""Trusted Python-specific extraction adapter for development validation only."""
from __future__ import annotations

import ast
import hashlib
import subprocess
import tomllib
from pathlib import Path
from typing import Any


def collect(root: Path, base: str, relation: str = "source-import", manifest: str = "pyproject-toml") -> dict[str, Any]:
    """Produce normalized evidence without being imported by the v4 compiler/verifier.

    Static Python imports are honestly labelled partial because dynamic imports,
    generated sources, and runtime module resolution are outside this adapter.
    """
    root = root.resolve(strict=True)
    candidate = _tree_hash(root)
    return {"schema": "brpl-evidence/v4", "candidate_tree": {"sha256": candidate}, "changes": _changes(root, base), "graphs": [{"relation": relation, "source_universe": "candidate-python-files", "target_universe": "candidate-python-files", "completeness": "partial", "adapter_binding": "brpl.v4.adapters.python-static.v1", "candidate_tree_sha256": candidate, "edges": _imports(root)}], "manifest_deltas": [_manifest_delta(root, base, manifest, candidate)], "checks": [], "metrics": []}


def _changes(root: Path, base: str) -> list[dict[str, str]]:
    output = _git(root, ["diff", "--name-status", "-M", base, "--"])
    changes: list[dict[str, str]] = []
    for line in output.splitlines():
        fields = line.split("\t")
        if len(fields) == 2: changes.append({"status": fields[0], "path": fields[1]})
        elif len(fields) == 3: changes.append({"status": fields[0], "old_path": fields[1], "path": fields[2]})
    return changes


def _imports(root: Path) -> list[dict[str, str]]:
    edges: list[dict[str, str]] = []
    for source in sorted(root.rglob("*.py")):
        if ".git" in source.parts: continue
        relative = source.relative_to(root).as_posix()
        try: tree = ast.parse(source.read_text(encoding="utf-8"), filename=relative)
        except (OSError, SyntaxError, UnicodeDecodeError): continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for name in node.names: edges.append({"source": relative, "target": name.name})
            elif isinstance(node, ast.ImportFrom) and node.module: edges.append({"source": relative, "target": node.module})
    return sorted(edges, key=lambda item: (item["source"], item["target"]))


def _manifest_delta(root: Path, base: str, manifest: str, candidate: str) -> dict[str, Any]:
    current = _dependencies((root / "pyproject.toml").read_bytes()) if (root / "pyproject.toml").is_file() else set()
    try: previous = _dependencies(_git(root, ["show", f"{base}:pyproject.toml"]).encode())
    except RuntimeError: previous = set()
    return {"manifest": manifest, "added": sorted(current - previous), "removed": sorted(previous - current), "completeness": "complete", "candidate_tree_sha256": candidate}


def _dependencies(payload: bytes) -> set[str]:
    try: project = tomllib.loads(payload.decode("utf-8")).get("project", {})
    except (UnicodeDecodeError, tomllib.TOMLDecodeError): return set()
    return {value.split(";", 1)[0].split("[", 1)[0].split(" ", 1)[0].lower() for value in project.get("dependencies", []) if isinstance(value, str)}


def _git(root: Path, args: list[str]) -> str:
    result = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, check=False)
    if result.returncode: raise RuntimeError(result.stderr.strip() or "git command failed")
    return result.stdout


def _tree_hash(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file() and ".git" not in item.parts):
        relative = path.relative_to(root).as_posix().encode(); digest.update(len(relative).to_bytes(8, "big")); digest.update(relative); content = path.read_bytes(); digest.update(len(content).to_bytes(8, "big")); digest.update(content)
    return digest.hexdigest()
