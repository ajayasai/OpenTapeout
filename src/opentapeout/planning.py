"""Read-only dependency rebuild plans and immutable release metric comparisons.

Plans never mark evidence fresh, waive failures, execute tools or relax the gate.
Reuse means input-compatible, currently passing evidence under the supplied policy,
not permission to skip re-approval of a changed candidate.
"""
from __future__ import annotations

from collections import deque

from .engine import Engine, scope_view
from .graph import Graph
from .policy import check_key, evaluate, validate_policy
from .signing import Trust
from .util import TapeoutError, digest, ensure, now, finite_number


def affected_paths(graph: Graph, changes: list[str]) -> dict[str, list[str]]:
    """One shortest explanation per affected node, including each changed root."""
    paths = {}
    queue = deque()
    for key in sorted(set(changes)):
        ensure(key in graph.resources, f"Unknown changed resource: {key}")
        paths[key] = [key]
        queue.append(key)
    while queue:
        parent = queue.popleft()
        for child in graph.children[parent]:
            if child not in paths:
                paths[child] = paths[parent] + [child]
                queue.append(child)
    return paths


def plan(engine: Engine, policy: dict, trust: Trust, *, candidate_name: str | None = None,
         changed: list[str] | None = None) -> dict:
    validate_policy(policy)
    ensure(changed is None or isinstance(changed, list) and all(isinstance(x, str) for x in changed),
           "Changed resources must be a list of IDs")
    state = engine.state()
    graph = Graph(state["resources"])
    observed = graph.drift(engine.root)
    hypothetical = sorted(set(changed or []))
    paths = affected_paths(graph, sorted(set(hypothetical) | set(observed)))
    stale = {key for key, reasons in graph.stale.items() if reasons}
    # Existing registered changes are represented by built_from mismatches even
    # when no hypothetical change or on-disk drift remains.
    for key in graph.order:
        if key in stale and key not in paths:
            parents = [p for p in graph.resources[key]["depends_on"]
                       if graph.resources[key]["built_from"].get(p) != graph.fingerprints[p] or p in stale]
            parent = parents[0] if parents else key
            paths[key] = paths.get(parent, [parent]) + ([key] if parent != key else [])
    if candidate_name is None:
        candidate_name = next(reversed(state["candidates"]), None)
    if candidate_name is not None:
        ensure(candidate_name in state["candidates"], "Unknown candidate")
        frozen = state["candidates"][candidate_name]
    else:
        frozen = {"schema": "opentapeout.candidate/v1", "project_id": state["project"]["id"],
                  "name": "unfrozen", "created_by": "unfrozen", "deliveries": []}
    current = scope_view(state, frozen, policy, trust)
    evaluated = evaluate(current, policy, trust, [], at=now(), include_approvals=False)
    scoped = {}
    for blocker in evaluated["blockers"]:
        scoped.setdefault(blocker["scope"], []).append(blocker)
    runs = {check_key(r): r for r in current["runs"].values()}
    tasks, levels = [], {}
    for resource in graph.order:
        if resource not in paths:
            continue
        deps = [d for d in graph.resources[resource]["depends_on"] if d in paths]
        levels[resource] = 1 + max((levels[d] for d in deps), default=-1)
        action = "rebuild" if graph.resources[resource]["depends_on"] else "refresh_input"
        tasks.append({"resource": resource, "action": action, "wave": levels[resource],
                      "depends_on": deps, "reason_path": paths[resource],
                      "workspace_drift": observed.get(resource), "derivation_reasons": graph.stale[resource],
                      "hypothetical": resource in hypothetical})
    checks = []
    for required in policy["required_checks"]:
        check = check_key(required)
        run = runs.get(check)
        affected = sorted(set(run["snapshot"]) & set(paths)) if run else []
        blockers = scoped.get(check, [])
        if run is None:
            action = "configure_and_run"
        elif not run.get("completed_at") and not affected:
            action = "wait_for_latest_run"
        elif affected or blockers:
            action = "rerun_or_resolve"
        else:
            action = "reuse_evidence"
        checks.append({"check": check, "action": action, "run_id": run["id"] if run else None,
                       "roots": run["roots"] if run else None, "affected_inputs": affected,
                       "reason_paths": [paths[k] for k in affected], "blockers": blockers,
                       "required_resource_kinds": required["required_resource_kinds"]})
    # Object corruption is not visible in dependency fingerprints. Never advertise
    # corrupt reports as reusable, even when the graph and normalized result pass.
    object_errors = {}
    for row in checks:
        if row["action"] != "reuse_evidence":
            continue
        run = runs[row["check"]]
        refs = {current["resources"][k]["sha256"] for k in run["snapshot"]}
        for k in run["snapshot"]:
            resource = current["resources"][k]
            if resource["metadata"].get("capture") == "directory-tree":
                refs.update(f["sha256"] for f in resource["metadata"]["files"])
        refs.update(run[k] for k in ("report_sha256", "stdout_sha256", "stderr_sha256") if run.get(k))
        for checksum in refs:
            if checksum not in object_errors:
                try:
                    engine.store.verify_object(checksum)
                    object_errors[checksum] = None
                except TapeoutError as exc:
                    object_errors[checksum] = str(exc)
            if object_errors[checksum]:
                row["action"] = "repair_evidence"
                row["blockers"].append({"code": "OBJECT_INTEGRITY", "scope": row["check"],
                                         "message": object_errors[checksum]})
    return {"schema": "opentapeout.rebuild-plan/v1", "advisory_only": True,
            "candidate": candidate_name, "hypothetical_changes": hypothetical, "observed_drift": observed,
            "resource_tasks": tasks, "checks": checks,
            "summary": {"resource_tasks": len(tasks), "required_checks": len(checks),
                        "reusable_checks": sum(c["action"] == "reuse_evidence" for c in checks),
                        "checks_needing_attention": sum(c["action"] != "reuse_evidence" for c in checks)},
            "new_candidate_required": candidate_name is None or digest(current) != digest(frozen) or bool(paths),
            "limitations": "Declared dependencies only. Plans do not execute tools or authorize release; rerun the gate after repairs."}


def compare(engine: Engine, before: str, after: str) -> dict:
    state = engine.state()
    ensure(before in state["candidates"] and after in state["candidates"], "Unknown candidate")
    a, b = state["candidates"][before], state["candidates"][after]
    result = engine.diff(before, after)
    aruns, bruns = ({check_key(r): r for r in c["runs"].values()} for c in (a, b))
    deltas = []
    for check in sorted(set(aruns) | set(bruns)):
        old, new = aruns.get(check, {}), bruns.get(check, {})
        am, bm = old.get("result", {}).get("metrics", {}), new.get("result", {}).get("metrics", {})
        for metric in sorted(set(am) | set(bm)):
            av, bv = am.get(metric), bm.get(metric)
            delta = bv - av if av is not None and bv is not None else None
            overflow = delta is not None and not finite_number(delta)
            deltas.append({"check": check, "metric": metric, "before": av, "after": bv,
                           "delta": None if overflow else delta, "delta_overflow": overflow,
                           "change": "added" if av is None else "removed" if bv is None else
                                     "unchanged" if av == bv else "changed"})
    result["metric_deltas"] = deltas
    result["check_transitions"] = [{"check": check,
        "before": aruns.get(check, {}).get("result", {}).get("status", "missing"),
        "after": bruns.get(check, {}).get("result", {}).get("status", "missing"),
        "evidence_changed": aruns.get(check) != bruns.get(check)} for check in sorted(set(aruns) | set(bruns))]
    result["policy_changed"] = a["policy_sha256"] != b["policy_sha256"]
    result["interpretation"] = "Numeric deltas are not automatically improvements; review units, thresholds and policy changes."
    return result
