"""Named trusted v4 evidence adapters; never imported by the v4 core."""
from __future__ import annotations

import hashlib
from pathlib import Path


def adapter_artifact_digest(adapter: str) -> str:
    """Return the SHA-256 of a reviewed built-in adapter artifact."""
    artifacts = {"python-evidence-bundle": Path(__file__).with_name("python_static.py"), "python-static": Path(__file__).with_name("python_static.py")}
    if adapter not in artifacts:
        raise ValueError(f"unknown trusted adapter {adapter!r}")
    return hashlib.sha256(artifacts[adapter].read_bytes()).hexdigest()
