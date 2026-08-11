"""Explicit trusted-adapter driver, deliberately separate from the v4 core."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from .adapters import adapter_artifact_digest
from .adapters.python_static import collect


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Produce normalized evidence using a named trusted BRPL v4 adapter.")
    parser.add_argument("--adapter", choices=("python-static",), required=True)
    parser.add_argument("--repo-root", required=True)
    parser.add_argument("--base", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    root = Path(args.repo_root).resolve(strict=True); output = Path(args.output).resolve(strict=False)
    if output.is_relative_to(root): parser.error("--output must be outside --repo-root")
    # The printed digest is the catalog value an external launch authority pins.
    evidence = collect(root, args.base)
    output.write_text(json.dumps(evidence, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({"adapter": args.adapter, "artifact_sha256": adapter_artifact_digest(args.adapter), "evidence": str(output)}, sort_keys=True))
    return 0


if __name__ == "__main__": raise SystemExit(main())
