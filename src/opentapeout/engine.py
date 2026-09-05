"""Event-sourced application API; mutations validate and commit under a single SQLite lock."""
from __future__ import annotations

import copy
import os
import signal
import shutil
import subprocess
import uuid
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .graph import Graph, validate_resource
from .parsers import CHECKS, MAX_REPORT, SCHEMA, parse
from .policy import check_key, evaluate, evidence_digest, validate_policy
from .signing import Trust, sign
from .store import Store, Transaction
from .util import (TapeoutError, canonical, digest, ensure, identifier, now, safe_relative,
                   timestamp, workspace_file, finite_number, file_digest)


def state_from(events: list[dict]) -> dict:
    state = {"project": None, "resources": {}, "runs": {}, "waivers": {}, "revoked_waivers": set(),
             "candidates": {}, "approvals": [], "releases": {}, "receipts": [],
             "revoked_approvals": {}, "withdrawals": {}, "deliveries": {}, "delivery_receipts": []}
    for event in events:
        kind, payload = event["type"], event["payload"]
        if kind == "project.created":
            ensure(state["project"] is None, "Duplicate project genesis")
            state["project"] = payload
        elif kind == "resource.registered":
            state["resources"][payload["id"]] = payload["resource"]
        elif kind == "run.started":
            state["runs"][payload["id"]] = {**payload, "sequence": event["seq"]}
        elif kind == "run.completed":
            ensure(payload["id"] in state["runs"], "Completion without run start")
            state["runs"][payload["id"]].update(payload)
        elif kind == "waiver.signed":
            state["waivers"][digest(payload)] = payload
        elif kind == "waiver.revoked":
            state["revoked_waivers"].add(payload["payload"]["waiver_sha256"])
        elif kind == "candidate.created":
            state["candidates"][payload["id"]] = payload["candidate"]
        elif kind == "approval.signed":
            state["approvals"].append(payload)
        elif kind == "approval.revoked":
            state["revoked_approvals"][payload["payload"]["approval_sha256"]] = payload
        elif kind == "release.withdrawn":
            state["withdrawals"][payload["payload"]["candidate_sha256"]] = payload
        elif kind == "delivery.sealed":
            state["deliveries"][payload["id"]] = payload
        elif kind == "delivery.received":
            state["delivery_receipts"].append(payload)
        elif kind == "release.sealed":
            state["releases"][payload["id"]] = payload
        elif kind == "receipt.recorded":
            state["receipts"].append(payload)
        else:
            raise TapeoutError(f"Unknown ledger event type: {kind}")
    return state


def object_refs(candidate: dict) -> set[str]:
    refs = {resource["sha256"] for resource in candidate["resources"].values()}
    for resource in candidate["resources"].values():
        if resource["metadata"].get("capture") == "directory-tree":
            refs.update(entry["sha256"] for entry in resource["metadata"]["files"])
    for run in candidate["runs"].values():
        for key in ("report_sha256", "stdout_sha256", "stderr_sha256"):
            if run.get(key):
                refs.add(run[key])
    for waiver in candidate["waivers"]:
        refs.update(waiver["payload"].get("attachments", []))
    return refs


def scope_view(state: dict, candidate: dict, policy: dict, trust: Trust) -> dict:
    latest_by_check = {}
    for run in state["runs"].values():
        scope = check_key(run)
        if scope not in latest_by_check or run["sequence"] > latest_by_check[scope]["sequence"]:
            latest_by_check[scope] = run
    runs = {}
    for check in policy["required_checks"]:
        latest = latest_by_check.get(check_key(check))
        if latest is not None:
            runs[latest["id"]] = copy.deepcopy(latest)
    waivers = [envelope for key, envelope in state["waivers"].items()
               if key not in state["revoked_waivers"] and envelope["payload"]["run_id"] in runs]
    deliveries = []
    for delivery in candidate["deliveries"]:
        resource = state["resources"].get(delivery["resource_id"])
        ensure(resource is not None, "Delivery resource missing")
        deliveries.append({**delivery, "sha256": resource["sha256"], "size": resource["size"]})
    return {**candidate, "resources": copy.deepcopy(state["resources"]), "runs": runs,
            "waivers": sorted(waivers, key=digest), "deliveries": deliveries,
            "policy_sha256": digest(policy), "trust_sha256": trust.sha256}


class Engine:
    def __init__(self, root: str | Path):
        self.store = Store(root)
        self.root = self.store.root

    @classmethod
    def init(cls, root: str | Path, project: str, actor: str = "operator") -> "Engine":
        ensure(isinstance(project, str) and bool(project.strip()) and len(project) <= 128, "Project name required")
        store = Store(root, create=True)
        with store.transaction(write=True) as tx:
            ensure(not tx.events, "Workspace already initialized; refusing to overwrite")
            tx.append("project.created", {"id": str(uuid.uuid4()), "name": project,
                                          "schema": "opentapeout.project/v1"}, actor)
        return cls(root)

    def state(self) -> dict:
        with self.store.transaction() as tx:
            return state_from(tx.events)

    def register(self, resource_id: str, kind: str, *, path: str | None = None,
                 metadata: dict | None = None, depends_on: list[str] | None = None,
                 actor: str = "operator") -> dict:
        identifier(resource_id)
        metadata, depends_on = metadata or {}, depends_on or []
        validate_resource(kind, metadata, depends_on)
        with self.store.transaction(write=True) as tx:
            state = state_from(tx.events)
            graph = Graph(state["resources"])
            ensure(resource_id not in depends_on, "A resource cannot depend on itself")
            selected = graph.closure(depends_on)
            graph.assert_fresh(self.root, selected)
            # Prevent cycling an existing dependency graph by replacing a parent with its descendant.
            pins = {key: graph.fingerprints[key] for key in depends_on}
            if path is not None:
                relative = safe_relative(path)
                checksum, size = self.store.put_file(workspace_file(self.root, relative))
            else:
                relative = None
                checksum, size = self.store.put_bytes(canonical(metadata))
            resource = {"kind": kind, "sha256": checksum, "size": size, "path": relative,
                        "metadata": metadata, "depends_on": sorted(depends_on), "built_from": pins}
            Graph({**state["resources"], resource_id: resource})
            tx.append("resource.registered", {"id": resource_id, "resource": resource}, actor)
            return resource

    def register_tree(self, resource_id: str, kind: str, directory: str, *, version: str,
                      depends_on: list[str] | None = None, actor: str = "operator") -> dict:
        from .tree_capture import capture_tree
        manifest = capture_tree(self.root, directory, self.store)
        ensure(capture_tree(self.root, directory) == manifest, "Directory changed during capture")
        return self.register(resource_id, kind, metadata={"version": version, "capture": "directory-tree",
            "directory": directory, "files": manifest}, depends_on=depends_on, actor=actor)

    def begin(self, kind: str, inputs: list[str], tool: str, corner: str,
              actor: str = "operator") -> str:
        ensure(kind in CHECKS, "Unknown check kind")
        ensure(isinstance(inputs, list) and bool(inputs), "Run inputs cannot be empty")
        with self.store.transaction(write=True) as tx:
            state = state_from(tx.events)
            graph = Graph(state["resources"])
            ensure(tool in graph.resources and graph.resources[tool]["kind"] == "tool", "A tool resource is required")
            ensure(corner in graph.resources and graph.resources[corner]["kind"] == "corner", "A corner resource is required")
            roots = sorted(set(inputs + [tool, corner]))
            selected = graph.closure(roots)
            graph.assert_fresh(self.root, selected)
            for key in selected:
                self.store.verify_object(graph.resources[key]["sha256"])
            run_id = str(uuid.uuid4())
            tx.append("run.started", {"id": run_id, "kind": kind, "corner": corner, "tool": tool,
                 "roots": roots, "snapshot": selected, "started_at": now(), "completed_at": None,
                 "tool_spec": graph.resources[tool]["metadata"]}, actor)
            return run_id

    def finish(self, run_id: str, report: str | None, *, exit_code: int, format_name: str = "json",
               actor: str = "operator", _managed: bool = False,
               _logs: tuple[Path, Path] | None = None,
               _execution_identity: dict | None = None) -> dict:
        ensure(type(exit_code) is int and -65536 <= exit_code <= 65536, "Invalid exit code")
        with self.store.transaction(write=True) as tx:
            state = state_from(tx.events)
            ensure(run_id in state["runs"], "Unknown run")
            run = state["runs"][run_id]
            ensure(run["completed_at"] is None, "Run is already completed; start a new run")
            report_hash, parser_error = None, None
            result = {"schema": SCHEMA, "run_id": run_id, "status": "unknown", "complete": False,
                      "metrics": {}, "violations": []}
            if report is not None:
                path = workspace_file(self.root, report)
                report_hash, _ = self.store.put_file(path)
                # Parse the captured CAS bytes, not a subsequently replaced report path.
                with self.store.verify_object(report_hash).open("rb") as handle:
                    raw = handle.read(MAX_REPORT + 1)
                try:
                    from .parsers import FORMAT_KINDS
                    ensure(format_name not in FORMAT_KINDS or run["kind"] == FORMAT_KINDS[format_name],
                           f"{format_name} evidence can only satisfy a {FORMAT_KINDS.get(format_name)} check")
                    result = parse(raw, format_name, run_id)
                    if format_name in {"klayout-drc", "klayout-lvs", "opensta"} and _logs and _logs[1].stat().st_size:
                        # Native diagnostics often go to stderr even when a process returns zero.
                        result = {"schema": SCHEMA, "run_id": run_id, "status": "unknown", "complete": False,
                                  "metrics": {}, "violations": []}
                        parser_error = "Native physical collector wrote stderr; review diagnostics before accepting evidence"
                except TapeoutError as exc:
                    parser_error = str(exc)
            else:
                parser_error = "No report produced"
            graph = Graph(state["resources"])
            current = graph.closure(run["roots"])
            changed = sorted(key for key in set(current) | set(run["snapshot"])
                             if current.get(key) != run["snapshot"].get(key))
            drift = graph.drift(self.root, current)
            completion = {"id": run_id, "completed_at": now(), "exit_code": exit_code,
                "capture_mode": "managed" if _managed else "imported", "report_sha256": report_hash,
                "format": format_name, "parser_error": parser_error, "result": result,
                "input_drift": sorted(set(changed) | set(drift)),
                "stdout_sha256": None, "stderr_sha256": None}
            if _execution_identity is not None:
                completion["execution_identity"] = _execution_identity
            if _logs:
                for name, log in zip(("stdout_sha256", "stderr_sha256"), _logs):
                    completion[name], _ = self.store.put_file(log)
            tx.append("run.completed", completion, actor)
            return {**run, **completion}

    def run(self, kind: str, inputs: list[str], tool: str, corner: str, report: str, *,
            format_name: str = "json", timeout: float = 3600, actor: str = "operator",
            report_source: str = "file") -> dict:
        """Execute the explicitly registered argv, without a shell. This is not a sandbox."""
        safe_relative(report)
        ensure(report_source in {"file", "stdout"}, "Report source must be file or stdout")
        ensure(not (self.root / report).exists(), "Output report already exists; refusing stale-report reuse")
        ensure(finite_number(timeout) and 0 < timeout <= 31536000, "Timeout must be finite, positive and at most one year")
        run_id = self.begin(kind, inputs, tool, corner, actor)
        tool_spec = self.state()["runs"][run_id]["tool_spec"]
        logs = self.store.directory / "logs"
        logs.mkdir(exist_ok=True)
        out, err = logs / f"{run_id}.out", logs / f"{run_id}.err"
        env = {**os.environ, "OPENTAPEOUT_RUN_ID": run_id, "OPENTAPEOUT_REPORT": report}
        identity = None
        argv = list(tool_spec["argv"])
        with out.open("xb") as stdout, err.open("xb") as stderr:
            try:
                if "executable_sha256" in tool_spec:
                    # Resolve exactly once. This pins the launcher, not dynamic libraries or child tools.
                    command = argv[0]
                    resolved = (str((self.root / command).resolve()) if "/" in command
                                else shutil.which(command, path=env.get("PATH")))
                    ensure(resolved is not None, "Pinned executable could not be resolved")
                    executable = Path(resolved).resolve(strict=True)
                    checksum, size = file_digest(executable)
                    identity = {"path": str(executable), "sha256": checksum, "size": size, "unchanged": False}
                    ensure(checksum == tool_spec["executable_sha256"], "Executable SHA-256 does not match registered pin")
                    argv[0] = str(executable)
                process = subprocess.Popen(argv, cwd=self.root, env=env, stdout=stdout,
                                           stderr=stderr, start_new_session=(os.name == "posix"))
                try:
                    code = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    if os.name == "posix":
                        os.killpg(process.pid, signal.SIGKILL)
                    else:
                        process.kill()
                    process.wait()
                    code = 124
            except (OSError, TapeoutError) as exc:
                stderr.write(f"Execution failed: {exc}\n".encode())
                code = 127
            if identity is not None:
                try:
                    identity["unchanged"] = file_digest(Path(identity["path"])) == (identity["sha256"], identity["size"])
                except TapeoutError:
                    identity["unchanged"] = False
                if not identity["unchanged"]:
                    stderr.write(b"Executable changed or disappeared during execution.\n")
                    code = 126
        if report_source == "stdout":
            # Captured stdout is already a workspace-contained regular file. Never read an arbitrary tool path.
            report = out.relative_to(self.root).as_posix()
        return self.finish(run_id, report if (self.root / report).is_file() else None,
                           exit_code=code, format_name=format_name, actor=actor, _managed=True,
                           _logs=(out, err), _execution_identity=identity)

    def attach(self, relative: str) -> str:
        checksum, _ = self.store.put_file(workspace_file(self.root, relative))
        return checksum

    def waive(self, run_id: str, fingerprint: str, rationale: str, owner: str, expires_at: str,
              key: Ed25519PrivateKey, trust: Trust, *, attachments: list[str] | None = None) -> str:
        ensure(isinstance(rationale, str) and len(rationale.strip()) >= 12, "Explain the waiver rationale (12+ characters)")
        identifier(owner)
        ensure(timestamp(expires_at) > timestamp(now()), "Waiver expiration must be in the future")
        with self.store.transaction(write=True) as tx:
            state = state_from(tx.events)
            run = state["runs"].get(run_id)
            ensure(run is not None and run["completed_at"] is not None, "Waiver requires completed evidence")
            ensure(fingerprint in {v["fingerprint"] for v in run["result"]["violations"]},
                   "Violation fingerprint not found")
            for checksum in attachments or []:
                self.store.verify_object(checksum)
            envelope = sign({"type": "opentapeout.waiver/v1", "project_id": state["project"]["id"],
                "run_id": run_id, "evidence_sha256": evidence_digest(run), "violation_fingerprint": fingerprint,
                "rationale": rationale, "owner": owner, "expires_at": expires_at,
                "attachments": sorted(set(attachments or [])), "created_at": now()}, key)
            _, principal = trust.verify(envelope, role="waiver", statement_type="opentapeout.waiver/v1")
            ensure(principal != owner, "Waiver owner cannot review their own waiver")
            tx.append("waiver.signed", envelope, principal)
            return digest(envelope)

    def revoke_waiver(self, waiver_hash: str, reason: str, key: Ed25519PrivateKey, trust: Trust) -> None:
        ensure(isinstance(reason, str) and bool(reason.strip()), "Revocation reason required")
        with self.store.transaction(write=True) as tx:
            state = state_from(tx.events)
            ensure(waiver_hash in state["waivers"], "Unknown waiver")
            envelope = sign({"type": "opentapeout.waiver-revocation/v1", "project_id": state["project"]["id"],
                             "waiver_sha256": waiver_hash, "reason": reason, "created_at": now()}, key)
            _, principal = trust.verify(envelope, role="waiver", statement_type="opentapeout.waiver-revocation/v1")
            tx.append("waiver.revoked", envelope, principal)

    def candidate(self, name: str, notes: str, deliveries: dict[str, str], policy: dict, trust: Trust,
                  actor: str = "operator") -> str:
        identifier(name)
        validate_policy(policy)
        ensure(isinstance(notes, str) and bool(notes.strip()) and len(notes) <= 100000, "Release notes required")
        with self.store.transaction(write=True) as tx:
            state = state_from(tx.events)
            ensure(name not in state["candidates"], "Candidate name already exists; use a new revision")
            entries = []
            for filename, resource_id in sorted(deliveries.items()):
                safe_relative(filename)
                ensure(Path(filename).suffix.lower() in {".gds", ".gdsii", ".oas", ".oasis"},
                       "Delivery must be named GDS or OASIS")
                resource = state["resources"].get(resource_id)
                ensure(resource is not None and resource["kind"] == "layout" and resource["path"] is not None,
                       "Delivery must refer to a file-backed layout resource")
                entries.append({"name": filename, "resource_id": resource_id,
                                "sha256": resource["sha256"], "size": resource["size"]})
            candidate = {"schema": "opentapeout.candidate/v1", "project_id": state["project"]["id"],
                "project_name": state["project"]["name"], "name": name, "created_at": now(),
                "created_by": actor, "notes": notes, "deliveries": entries}
            candidate = scope_view(state, candidate, policy, trust)
            tx.append("candidate.created", {"id": name, "candidate": candidate}, actor)
            return digest(candidate)

    def _gate(self, tx: Transaction, name: str, policy: dict, trust: Trust,
              *, include_approvals: bool = True) -> dict:
        state = state_from(tx.events)
        ensure(name in state["candidates"], "Unknown candidate")
        candidate = state["candidates"][name]
        at = now()
        from .lifecycle import active_approvals
        report = evaluate(candidate, policy, trust, active_approvals(state), at=at,
                          include_approvals=include_approvals)
        if digest(candidate) in state["withdrawals"]:
            report["blockers"].append({"code": "RELEASE_WITHDRAWN", "scope": name,
                "message": "This release was withdrawn. Issue a new candidate; history is preserved."})
        current = scope_view(state, candidate, policy, trust)
        if digest(current) != digest(candidate):
            report["blockers"].append({"code": "CANDIDATE_CHANGED", "scope": name,
                "message": "Resources, evidence, waivers, trust, or policy changed. Create and approve a new candidate."})
            live = evaluate(current, policy, trust, [], at=at, include_approvals=False)
            report["checks"] = live["checks"]
            for blocker in live["blockers"]:
                if blocker not in report["blockers"]:
                    report["blockers"].append(blocker)
        for resource_id, reason in Graph(state["resources"]).drift(self.root).items():
            report["blockers"].append({"code": "WORKSPACE_DRIFT", "scope": resource_id, "message": reason})
        for checksum in object_refs(candidate):
            try:
                self.store.verify_object(checksum)
            except TapeoutError as exc:
                report["blockers"].append({"code": "OBJECT_INTEGRITY", "scope": checksum, "message": str(exc)})
        report["ready"] = not report["blockers"]
        report["checkpoint"] = tx.checkpoint
        return report

    def gate(self, name: str, policy: dict, trust: Trust, *, include_approvals: bool = True) -> dict:
        with self.store.transaction() as tx:
            return self._gate(tx, name, policy, trust, include_approvals=include_approvals)

    def approve(self, name: str, role: str, key: Ed25519PrivateKey, policy: dict, trust: Trust) -> dict:
        with self.store.transaction(write=True) as tx:
            report = self._gate(tx, name, policy, trust, include_approvals=False)
            ensure(report["ready"], f"Evidence gate blocks approval: {report['blockers']}")
            state = state_from(tx.events)
            ensure(role in policy["approval_roles"], "Role is not required by policy")
            candidate = state["candidates"][name]
            envelope = sign({"type": "opentapeout.approval/v1", "project_id": state["project"]["id"],
                 "candidate_sha256": digest(candidate), "role": role, "decision": "approve", "created_at": now()}, key)
            _, principal = trust.verify(envelope, role=role, statement_type="opentapeout.approval/v1")
            ensure(not policy["forbid_self_approval"] or principal != candidate["created_by"],
                   "Candidate author cannot approve their own release")
            tx.append("approval.signed", envelope, principal)
            return envelope

    def receipt(self, release_id: str, uploaded_sha256: str, reference: str,
                actor: str = "operator") -> dict:
        ensure(isinstance(reference, str) and bool(reference.strip()), "Foundry receipt/reference required")
        with self.store.transaction(write=True) as tx:
            state = state_from(tx.events)
            release = state["releases"].get(release_id)
            ensure(release is not None, "Unknown sealed release")
            ensure(uploaded_sha256 == release["archive_sha256"], "Foundry-upload checksum does not match sealed archive")
            payload = {"release_id": release_id, "archive_sha256": uploaded_sha256, "reference": reference,
                       "recorded_at": now(), "verification": "operator-supplied receipt; no foundry API attestation"}
            tx.append("receipt.recorded", payload, actor)
            return payload

    def impact(self, resource_id: str) -> dict:
        state = self.state()
        graph = Graph(state["resources"])
        impacted = graph.impact(resource_id)
        affected = {resource_id} | {row["resource"] for row in impacted}
        runs = [{"id": run["id"], "kind": run["kind"], "corner": run["corner"],
                 "affected_inputs": sorted(affected & set(run["snapshot"]))}
                for run in state["runs"].values() if affected & set(run["snapshot"])]
        return {"resource": resource_id, "downstream": impacted, "affected_runs": runs}

    def diff(self, before: str, after: str) -> dict:
        state = self.state()
        ensure(before in state["candidates"] and after in state["candidates"], "Unknown candidate")
        a, b = state["candidates"][before], state["candidates"][after]
        return {"before": before, "after": after,
            "resources": [{"id": key, "before": a["resources"].get(key), "after": b["resources"].get(key)}
                for key in sorted(set(a["resources"]) | set(b["resources"]))
                if a["resources"].get(key) != b["resources"].get(key)],
            "changed_sections": [key for key in sorted(set(a) | set(b)) if a.get(key) != b.get(key)]}
