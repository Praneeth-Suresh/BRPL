"""Host-neutral candidate-tree identity used by v4 launch and evidence boundaries."""
from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path


def candidate_tree_hash(root: Path) -> str:
    """Hash all candidate entries without following links outside the worktree."""
    root = root.resolve(strict=True)
    digest = hashlib.sha256()
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        directories[:] = sorted(name for name in directories if name != ".git")
        for name in sorted([*directories, *files]):
            path = current_path / name
            if ".git" in path.relative_to(root).parts:
                continue
            info = path.lstat()
            relative = path.relative_to(root).as_posix().encode("utf-8")
            if stat.S_ISREG(info.st_mode): kind, payload = b"F", path.read_bytes()
            elif stat.S_ISLNK(info.st_mode): kind, payload = b"L", os.readlink(path).encode("utf-8", "surrogateescape")
            elif stat.S_ISDIR(info.st_mode): kind, payload = b"D", b""
            else: kind, payload = b"O", b""
            digest.update(len(relative).to_bytes(8, "big")); digest.update(relative); digest.update(kind); digest.update(stat.S_IMODE(info.st_mode).to_bytes(4, "big")); digest.update(len(payload).to_bytes(8, "big")); digest.update(payload)
    return digest.hexdigest()
