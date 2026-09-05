"""Strict policy schema and a deterministic, offline-reusable gate evaluator."""
from __future__ import annotations

from datetime import timedelta

from .graph import Graph, KINDS
from .parsers import CHECKS
from .signing import Trust
from .util import HEX, TapeoutError, digest, ensure, finite_number, identifier, timestamp


def validate_policy(policy: dict) -> dict:
    ensure(isinstance(policy, dict) and policy.get("schema") in {"opentapeout.policy/v1", "opentapeout.policy/v2"}, "Invalid policy schema")
    strict = policy["schema"] == "opentapeout.policy/v2"
    allowed = {"schema", "required_checks", "approval_roles", "distinct_approvers", "forbid_self_approval",
               "max_approval_age_hours", "require_managed_runs", "require_delivery", "require_git",
               "require_hashed_pdk"}
    ensure(set(policy) == allowed, "Policy has missing or unknown fields; do not silently ignore policy")
    checks = policy["required_checks"]
    ensure(isinstance(checks, list) and bool(checks), "At least one required check is mandatory")
    seen = set()
    for check in checks:
        fields = {"kind", "corner", "required_resource_kinds", "max_age_hours", "metrics"}
        if strict:
            fields |= {"input_pins", "allowed_tools", "report_formats", "require_pinned_executable"}
        ensure(isinstance(check, dict) and set(check) == fields, "Malformed check policy")
        if strict:
            pins = check["input_pins"]
            ensure(isinstance(pins, dict) and bool(pins), "Exact input pins are required by policy v2")
            for resource_id, checksum in pins.items():
                identifier(resource_id)
                ensure(isinstance(checksum, str) and HEX.fullmatch(checksum) is not None, "Invalid input pin digest")
            tools, formats = check["allowed_tools"], check["report_formats"]
            ensure(isinstance(tools, list) and bool(tools) and all(isinstance(t, str) for t in tools) and len(tools) == len(set(tools)), "Allowed tools required")
            for tool in tools:
                identifier(tool)
                ensure(tool in pins, "Every allowed tool must have an exact metadata pin")
            ensure(check["corner"] in pins, "The corner definition must have an exact pin")
            from .parsers import FORMATS
            ensure(isinstance(formats, list) and bool(formats) and all(isinstance(f, str) and f in FORMATS for f in formats)
                   and len(formats) == len(set(formats)), "Invalid report format allowlist")
            ensure(type(check["require_pinned_executable"]) is bool, "Executable pin requirement must be boolean")
        ensure(check["kind"] in CHECKS, "Unsupported check kind")
        identifier(check["corner"])
        key = check_key(check)
        ensure(key not in seen, "Duplicate kind/corner requirement")
        seen.add(key)
        kinds = check["required_resource_kinds"]
        ensure(isinstance(kinds, list) and bool(kinds) and all(k in KINDS for k in kinds),
               "Invalid required resource kinds")
        ensure(finite_number(check["max_age_hours"]) and 0 < check["max_age_hours"] <= 876000,
               "Check maximum age must be positive and at most 100 years")
        ensure(isinstance(check["metrics"], dict), "Metric thresholds must be an object")
        for name, limits in check["metrics"].items():
            ensure(isinstance(name, str) and isinstance(limits, dict) and bool(limits)
                   and set(limits) <= {"min", "max"} and all(finite_number(v) for v in limits.values()),
                   "Invalid metric threshold")
            ensure(not ("min" in limits and "max" in limits and limits["min"] > limits["max"]),
                   "Metric minimum exceeds maximum")
    roles = policy["approval_roles"]
    ensure(isinstance(roles, list) and bool(roles) and all(isinstance(x, str) and x for x in roles)
           and len(roles) == len(set(roles)) and len(roles) <= 64, "Approval roles must be nonempty and unique")
    for key in ("distinct_approvers", "forbid_self_approval", "require_managed_runs", "require_delivery",
                "require_git", "require_hashed_pdk"):
        ensure(type(policy[key]) is bool, f"{key} must be a boolean")
    ensure(finite_number(policy["max_approval_age_hours"]) and 0 < policy["max_approval_age_hours"] <= 876000,
           "Approval maximum age must be positive and at most 100 years")
    return policy


def check_key(check: dict) -> str:
    return f"{check['kind']}:{check['corner']}"


def default_policy() -> dict:
    return {"schema": "opentapeout.policy/v1", "required_checks": [
        {"kind": kind, "corner": "nominal", "required_resource_kinds": kinds,
         "max_age_hours": 168, "metrics": metrics}
        for kind, kinds, metrics in [
            ("DRC", ["layout", "pdk", "rule_deck"], {}),
            ("LVS", ["layout", "netlist", "pdk", "rule_deck"], {}),
            ("STA", ["netlist", "constraints", "library"], {"wns_ns": {"min": 0}, "tns_ns": {"min": 0}}),
            ("CDC", ["rtl", "constraints"], {}),
            ("POWER", ["netlist", "power_intent", "library"], {"power_mw": {"max": 100}}),
            ("FORMAL", ["rtl", "netlist"], {})]],
        "approval_roles": ["physical", "verification"], "distinct_approvers": True,
        "forbid_self_approval": True, "max_approval_age_hours": 168, "require_managed_runs": True,
        "require_delivery": True, "require_git": True, "require_hashed_pdk": True}


def evidence_digest(run: dict) -> str:
    return digest(run)


def valid_waivers(candidate: dict, trust: Trust, at: str) -> tuple[dict, list[str]]:
    valid, rejected = {}, []
    for envelope in candidate["waivers"]:
        try:
            body, principal = trust.verify(envelope, role="waiver", statement_type="opentapeout.waiver/v1")
            ensure(body["project_id"] == candidate["project_id"], "Waiver belongs to another project")
            ensure(principal != body["owner"], "Waiver owner cannot review their own waiver")
            ensure(timestamp(body["created_at"]) <= timestamp(at) < timestamp(body["expires_at"]),
                   "Waiver expired or not yet valid")
            run = candidate["runs"].get(body["run_id"])
            ensure(run is not None and evidence_digest(run) == body["evidence_sha256"],
                   "Waiver does not match this exact evidence")
            fingerprints = {v["fingerprint"] for v in run["result"]["violations"]}
            ensure(body["violation_fingerprint"] in fingerprints, "Waiver violation not present")
            ensure(bool(body["rationale"].strip()), "Waiver rationale required")
            valid[(body["run_id"], body["violation_fingerprint"])] = envelope
        except (TapeoutError, KeyError, TypeError) as exc:
            rejected.append(str(exc))
    return valid, rejected


def _assign_roles(roles: list[str], options: dict[str, set[str]], distinct: bool) -> dict[str, str] | None:
    # Augmenting-path matching, O(roles * edges), rather than exponential backtracking.
    if not distinct:
        return {role: sorted(options[role])[0] for role in roles} if all(options.get(r) for r in roles) else None
    principal_to_role: dict[str, str] = {}
    def augment(role: str, visited: set[str]) -> bool:
        for principal in sorted(options.get(role, set())):
            if principal in visited:
                continue
            visited.add(principal)
            if principal not in principal_to_role or augment(principal_to_role[principal], visited):
                principal_to_role[principal] = role
                return True
        return False
    for role in sorted(roles, key=lambda r: len(options.get(r, set()))):
        if not augment(role, set()):
            return None
    return {role: principal for principal, role in principal_to_role.items()}


def evaluate(candidate: dict, policy: dict, trust: Trust, approvals: list[dict], *, at: str,
             include_approvals: bool = True) -> dict:
    validate_policy(policy)
    blockers, checks = [], []
    def block(code: str, message: str, scope: str = "release") -> None:
        blockers.append({"code": code, "scope": scope, "message": message})
    if digest(policy) != candidate["policy_sha256"]:
        block("POLICY_CHANGED", "Candidate is bound to a different release policy")
    if trust.sha256 != candidate["trust_sha256"]:
        block("TRUST_CHANGED", "Trust store changed; re-review candidate and signatures")
    graph = Graph(candidate["resources"])
    for key, reasons in graph.stale.items():
        for reason in reasons:
            block("DERIVATION_STALE", reason, key)
    if policy["require_git"] and not any(r["kind"] == "git" and r["metadata"].get("capture") == "git-worktree" and r["metadata"].get("dirty") is False for r in graph.resources.values()):
        block("GIT_PROVENANCE_MISSING", "A captured clean Git worktree with a full commit is required")
    if policy["require_hashed_pdk"] and not any(r["kind"] == "pdk" and (r["path"] is not None or r["metadata"].get("capture") == "directory-tree")
                                                for r in graph.resources.values()):
        block("PDK_CHECKSUM_MISSING", "A file-backed PDK manifest/archive checksum is required")
    if policy["require_delivery"] and not candidate["deliveries"]:
        block("DELIVERY_MISSING", "At least one GDS/OASIS delivery is required")
    waivers, rejected = valid_waivers(candidate, trust, at)
    for requirement in policy["required_checks"]:
        scope = check_key(requirement)
        run = next((r for r in candidate["runs"].values() if check_key(r) == scope), None)
        start = len(blockers)
        if run is None:
            block("CHECK_MISSING", "No run for required check/corner", scope)
            checks.append({"check": scope, "status": "missing", "run_id": None})
            continue
        stale = {key for key, fingerprint in run["snapshot"].items()
                 if graph.fingerprints.get(key) != fingerprint}
        current_closure = graph.closure(run["roots"])
        if current_closure != run["snapshot"]:
            stale.update(set(current_closure) ^ set(run["snapshot"]))
        if stale:
            block("RESULT_STALE", "Input/dependency changed: " + ", ".join(sorted(stale)), scope)
        if policy["schema"] == "opentapeout.policy/v2":
            for resource_id, expected_hash in requirement["input_pins"].items():
                if resource_id in requirement["allowed_tools"] and resource_id != run["tool"]:
                    continue
                resource = graph.resources.get(resource_id)
                if resource_id not in run["snapshot"] or resource is None:
                    block("EXACT_INPUT_MISSING", f"Run does not bind required resource: {resource_id}", scope)
                elif resource["sha256"] != expected_hash:
                    block("INPUT_PIN_MISMATCH", f"Resource does not match policy checksum: {resource_id}", scope)
            if run["tool"] not in requirement["allowed_tools"]:
                block("TOOL_NOT_ALLOWED", "Run used a tool outside the policy allowlist", scope)
            if run.get("completed_at") and run.get("format") not in requirement["report_formats"]:
                block("REPORT_FORMAT_NOT_ALLOWED", "Report adapter is not permitted for this check", scope)
            if requirement["require_pinned_executable"]:
                identity = run.get("execution_identity") or {}
                pin = run["tool_spec"].get("executable_sha256")
                if (not isinstance(pin, str) or HEX.fullmatch(pin) is None
                        or identity.get("sha256") != pin or identity.get("unchanged") is not True
                        or run.get("capture_mode") != "managed"):
                    block("EXECUTABLE_IDENTITY", "Requires a managed run with matching, unchanged executable bytes", scope)
        kinds = {graph.resources[key]["kind"] for key in run["snapshot"] if key in graph.resources}
        for kind in requirement["required_resource_kinds"]:
            if kind not in kinds:
                block("INPUT_KIND_MISSING", f"Run does not bind required input kind: {kind}", scope)
        if policy["require_hashed_pdk"]:
            for key in run["snapshot"]:
                resource = graph.resources.get(key)
                if resource and resource["kind"] == "pdk" and resource["path"] is None and resource["metadata"].get("capture") != "directory-tree":
                    block("PDK_CHECKSUM_MISSING", f"Run uses metadata-only PDK {key}; hash a pinned manifest/archive", scope)
        if not run.get("completed_at"):
            block("RUN_INCOMPLETE", "Latest run has not completed", scope)
        else:
            age = timestamp(at) - timestamp(run["completed_at"])
            if age < timedelta(0) or age > timedelta(hours=requirement["max_age_hours"]):
                block("RESULT_AGE", "Evidence is too old or future-dated", scope)
            if run.get("input_drift"):
                block("INPUT_CHANGED_DURING_RUN", "Inputs changed during execution: " + ", ".join(run["input_drift"]), scope)
            if run["exit_code"] != 0:
                block("TOOL_FAILED", f"Process exit code {run['exit_code']}; cannot be waived", scope)
            if policy["require_managed_runs"] and run["capture_mode"] != "managed":
                block("UNMANAGED_RUN", "Policy requires execution through the managed runner", scope)
            result = run["result"]
            if not result["complete"] or result["status"] == "unknown":
                block("RESULT_UNKNOWN", "Incomplete/unknown result cannot establish success", scope)
            if result["status"] == "fail" and not result["violations"]:
                block("RESULT_FAILED", "Failure without individually waiverable violations", scope)
            for violation in result["violations"]:
                if (run["id"], violation["fingerprint"]) not in waivers:
                    block("UNWAIVED_VIOLATION", f"{violation['rule']}: {violation['message']}", scope)
            for name, bounds in requirement["metrics"].items():
                value = result["metrics"].get(name)
                if not finite_number(value):
                    block("METRIC_MISSING", f"Required metric missing: {name}", scope)
                elif ("min" in bounds and value < bounds["min"]) or ("max" in bounds and value > bounds["max"]):
                    block("METRIC_THRESHOLD", f"{name}={value} violates {bounds}", scope)
        checks.append({"check": scope, "status": "pass" if len(blockers) == start else
                       "stale" if stale else "blocked", "run_id": run["id"],
                       "violations": len(run.get("result", {}).get("violations", []))})
    options, rejected_approvals = {}, []
    candidate_hash = digest(candidate)
    for envelope in approvals:
        try:
            role = envelope["payload"]["role"]
            ensure(role in policy["approval_roles"], "Approval role is not required by policy")
            body, principal = trust.verify(envelope, role=role, statement_type="opentapeout.approval/v1")
            ensure(body["candidate_sha256"] == candidate_hash and body["project_id"] == candidate["project_id"],
                   "Approval is bound to different candidate content")
            ensure(body["decision"] == "approve", "Approval decision is not approve")
            ensure(not policy["forbid_self_approval"] or principal != candidate["created_by"],
                   "Candidate author cannot approve their own release")
            age = timestamp(at) - timestamp(body["created_at"])
            ensure(timedelta(0) <= age <= timedelta(hours=policy["max_approval_age_hours"]),
                   "Approval expired or future-dated")
            options.setdefault(role, set()).add(principal)
        except (TapeoutError, KeyError, TypeError) as exc:
            rejected_approvals.append(str(exc))
    assignment = _assign_roles(policy["approval_roles"], options, policy["distinct_approvers"])
    if include_approvals and assignment is None:
        block("APPROVALS_MISSING", "Required valid approvals (and distinct principals) are not satisfied")
    return {"ready": not blockers, "candidate_sha256": candidate_hash, "evaluated_at": at,
            "blockers": blockers, "checks": checks, "approval_assignment": assignment or {},
            "valid_waivers": len(waivers), "rejected_waivers": rejected,
            "rejected_approvals": rejected_approvals}
