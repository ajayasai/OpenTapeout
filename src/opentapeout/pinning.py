"""Explicitly produce a reviewable policy lock from declared, observed runs.

This does not infer tool dependencies, bless a deck or authorize a release.
Every pin is only as good as the engineer's reviewed dependency declarations.
"""
from __future__ import annotations

import copy

from .engine import Engine
from .graph import Graph
from .policy import check_key, validate_policy
from .util import HEX, digest, ensure


def pin_policy(engine: Engine, policy: dict) -> dict:
    validate_policy(policy)
    state = engine.state()
    graph = Graph(state["resources"])
    latest = {}
    for run in state["runs"].values():
        scope = check_key(run)
        if scope not in latest or latest[scope]["sequence"] < run["sequence"]:
            latest[scope] = run
    result = copy.deepcopy(policy)
    result["schema"] = "opentapeout.policy/v2"
    for requirement in result["required_checks"]:
        run = latest.get(check_key(requirement))
        ensure(run is not None and run.get("completed_at"), "Pinning requires a completed latest run for every required check")
        ensure(run.get("capture_mode") == "managed", "Pinning requires managed evidence")
        current = graph.closure(run["roots"])
        graph.assert_fresh(engine.root, current)
        ensure(current == run["snapshot"] and not run.get("input_drift"), "Cannot pin stale evidence")
        for resource_id in (run["tool"], run["corner"]):
            resource = graph.resources[resource_id]
            ensure(resource["path"] is None and resource["sha256"] == digest(resource["metadata"]),
                   "Pinning requires metadata-only tool/corner definitions; capture executable bytes separately")
        ensure(run["tool_spec"] == graph.resources[run["tool"]]["metadata"], "Captured tool specification mismatch")
        pin = run["tool_spec"].get("executable_sha256")
        ensure(isinstance(pin, str) and HEX.fullmatch(pin) is not None, "Register an executable SHA-256 pin before execution")
        identity = run.get("execution_identity") or {}
        ensure(identity.get("sha256") == pin and identity.get("unchanged") is True, "Executable identity was not established")
        for name in ("report_sha256", "stdout_sha256", "stderr_sha256"):
            ensure(run.get(name) is not None, "Managed evidence is missing captured bytes")
            engine.store.verify_object(run[name])
        requirement.update(input_pins={key: graph.resources[key]["sha256"] for key in sorted(current)},
                           allowed_tools=[run["tool"]], report_formats=[run["format"]], require_pinned_executable=True)
    return validate_policy(result)
