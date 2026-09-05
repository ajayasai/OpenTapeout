"""Capture a clean Git worktree and recursive submodule commits without shell expansion."""
from __future__ import annotations

import subprocess
from pathlib import Path

from .util import TapeoutError, ensure, safe_relative


def inspect_git(root: Path, relative: str) -> dict:
    if relative != ".":
        safe_relative(relative)
    repository = (root / relative).resolve()
    ensure(repository.is_relative_to(root.resolve()), "Git repository escapes workspace")
    def git(*arguments: str) -> str:
        try:
            result = subprocess.run(["git", "-C", str(repository), *arguments], capture_output=True,
                                    text=True, timeout=30, check=True)
            return result.stdout.strip()
        except (subprocess.SubprocessError, OSError) as exc:
            raise TapeoutError("Cannot inspect Git repository") from exc
    ensure(Path(git("rev-parse", "--show-toplevel")).resolve() == repository,
           "Git path must be the actual repository root")
    commit = git("rev-parse", "HEAD")
    dirty = bool(git("status", "--porcelain", "--untracked-files=normal"))
    submodules = []
    for line in git("submodule", "status", "--recursive").splitlines():
        ensure(line[0] not in {"-", "+", "U"}, "Submodule is uninitialized, changed, or conflicted")
        parts = line.strip().split()
        ensure(len(parts) >= 2, "Malformed submodule state")
        submodules.append({"commit": parts[0], "path": parts[1]})
    return {"commit": commit, "submodules": submodules, "dirty": dirty,
            "capture": "git-worktree", "repo_path": relative}
