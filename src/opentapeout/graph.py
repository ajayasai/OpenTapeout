"""Linear-time dependency fingerprints, derivation freshness and impact paths."""
from __future__ import annotations

from collections import deque
from pathlib import Path

from .util import TapeoutError, digest, ensure, file_digest, identifier, workspace_file

KINDS = {"rtl", "netlist", "layout", "pdk", "tool", "corner", "rule_deck", "constraints",
         "library", "ip", "submodule", "git", "power_intent", "config", "other"}


class Graph:
    def __init__(self, resources: dict[str, dict]):
        self.resources = resources
        self.fingerprints: dict[str, str] = {}
        self.stale: dict[str, list[str]] = {}
        self.order: list[str] = []
        self._build()

    def _build(self) -> None:
        # Kahn ordering avoids Python recursion limits on large IP dependency graphs.
        children = {key: [] for key in self.resources}
        indegree = {}
        for key, resource in self.resources.items():
            identifier(key)
            deps = resource["depends_on"]
            ensure(len(deps) == len(set(deps)), f"Duplicate dependencies for {key}")
            indegree[key] = len(deps)
            for dependency in deps:
                ensure(dependency in self.resources, f"Missing dependency {dependency} for {key}")
                children[dependency].append(key)
        queue = deque(sorted(key for key, degree in indegree.items() if degree == 0))
        while queue:
            key = queue.popleft()
            self.order.append(key)
            resource = self.resources[key]
            current = {dep: self.fingerprints[dep] for dep in resource["depends_on"]}
            self.fingerprints[key] = digest({"resource": resource, "dependency_fingerprints": current})
            reasons = []
            for dependency in resource["depends_on"]:
                if resource["built_from"].get(dependency) != current[dependency]:
                    reasons.append(f"{key} was built against a different version of {dependency}")
                if self.stale[dependency]:
                    reasons.append(f"{key} depends on obsolete resource {dependency}")
            self.stale[key] = reasons
            for child in children[key]:
                indegree[child] -= 1
                if indegree[child] == 0:
                    queue.append(child)
        ensure(len(self.order) == len(self.resources), "Dependency cycle detected")
        self.children = children

    def closure(self, roots: list[str]) -> dict[str, str]:
        selected, queue = set(), list(roots)
        while queue:
            key = queue.pop()
            ensure(key in self.resources, f"Unknown resource: {key}")
            if key in selected:
                continue
            selected.add(key)
            queue.extend(self.resources[key]["depends_on"])
        return {key: self.fingerprints[key] for key in sorted(selected)}

    def impact(self, key: str) -> list[dict]:
        ensure(key in self.resources, f"Unknown resource: {key}")
        seen, queue, result = {key}, deque([(key, [key])]), []
        while queue:
            current, path = queue.popleft()
            for child in sorted(self.children[current]):
                if child not in seen:
                    seen.add(child)
                    next_path = path + [child]
                    result.append({"resource": child, "path": next_path})
                    queue.append((child, next_path))
        return result

    def drift(self, root: Path, selected: dict | None = None) -> dict[str, str]:
        result = {}
        for key in self.resources if selected is None else selected:
            resource = self.resources[key]
            if resource["metadata"].get("capture") == "directory-tree":
                from .tree_capture import capture_tree
                try:
                    observed = capture_tree(root, resource["metadata"]["directory"])
                    if observed != resource["metadata"]["files"]:
                        result[key] = "Directory contents changed (addition, deletion, or changed file bytes)"
                except (TapeoutError, OSError) as exc:
                    result[key] = str(exc)
            if resource["kind"] == "git" and resource["metadata"].get("capture") == "git-worktree":
                from .git_capture import inspect_git
                try:
                    observed = inspect_git(root, resource["metadata"]["repo_path"])
                    if observed != resource["metadata"] or observed["dirty"]:
                        result[key] = "Git commit, submodule pins, or worktree cleanliness changed"
                except TapeoutError as exc:
                    result[key] = str(exc)
            if resource["path"] is not None:
                try:
                    actual, _ = file_digest(workspace_file(root, resource["path"]))
                    if actual != resource["sha256"]:
                        result[key] = "Workspace bytes differ from recorded content"
                except (TapeoutError, OSError) as exc:
                    result[key] = str(exc)
        return result

    def assert_fresh(self, root: Path, selected: dict) -> None:
        stale = {key: self.stale[key] for key in selected if self.stale[key]}
        ensure(not stale, f"Obsolete derived inputs must be rebuilt: {stale}")
        drift = self.drift(root, selected)
        ensure(not drift, f"Workspace drift; register changed inputs first: {drift}")


def validate_resource(kind: str, metadata: dict, depends_on: list[str]) -> None:
    ensure(kind in KINDS, f"Unknown resource kind: {kind}")
    ensure(isinstance(metadata, dict), "Metadata must be an object")
    ensure(isinstance(depends_on, list) and all(isinstance(x, str) for x in depends_on),
           "Dependencies must be resource IDs")
    if kind == "tool":
        ensure(isinstance(metadata.get("name"), str) and bool(metadata["name"].strip()), "Tool name required")
        ensure(isinstance(metadata.get("version"), str) and bool(metadata["version"].strip()),
               "Tool version required")
        ensure(isinstance(metadata.get("argv"), list) and bool(metadata["argv"])
               and all(isinstance(x, str) and "\x00" not in x for x in metadata["argv"]),
               "Tool argv must be a nonempty argument array; shell commands are not accepted")
    if kind in {"pdk", "ip", "submodule"}:
        ensure(isinstance(metadata.get("version"), str) and bool(metadata["version"].strip()),
               f"{kind} version required")
    if kind == "git":
        commit = metadata.get("commit", "")
        ensure(isinstance(commit, str) and len(commit) in (40, 64)
               and all(x in "0123456789abcdef" for x in commit), "Full Git commit hash required")
    if kind == "corner":
        ensure(bool(metadata), "Corner definition cannot be empty")
