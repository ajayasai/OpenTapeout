"""Project-scoped team commands, serialized with ledger mutations and retry receipts.

The gateway does not accept paths, tool invocations, trust changes or private keys.
The filesystem owner and deployment administrator remain trusted principals.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from typing import Any
import uuid

from .engine import Engine, state_from
from .policy import validate_policy
from .signing import Trust, sign
from .team_auth import AccessTokens, Identity, TeamError, require
from .util import HEX, canonical, digest, ensure, identifier, now, read_json, timestamp

COMMAND_TYPE = "opentapeout.team-command/v1"
ACTIONS = frozenset({"candidate.create", "approval.submit", "approval.revoke", "release.withdraw"})
PERMISSIONS = ACTIONS | {"read", "audit"}
MAX_COMMAND = 128 * 1024
MAX_VALIDITY = 300


def fields(value: Any, expected: set[str]) -> None:
    ensure(isinstance(value, dict) and set(value) == expected, "Missing or unexpected fields")


def check_checkpoint(value: Any) -> None:
    fields(value, {"seq", "hash"})
    ensure(type(value["seq"]) is int and value["seq"] >= 1
           and isinstance(value["hash"], str) and HEX.fullmatch(value["hash"]), "Invalid checkpoint")


def check_window(body: dict, *, at: str | None = None) -> None:
    issued, expires, current = timestamp(body["created_at"]), timestamp(body["expires_at"]), timestamp(at or now())
    require(issued <= current < expires and timedelta(0) < expires - issued <= timedelta(seconds=MAX_VALIDITY),
            "COMMAND_EXPIRED", "Command expired, future-dated or exceeds five-minute validity", 409)


def make_command(context: dict, action: str, parameters: dict, key, *, request_id: str | None = None,
                 valid_seconds: int = MAX_VALIDITY) -> dict:
    """Offline client helper. The caller must independently review the context/parameters."""
    ensure(action in ACTIONS and isinstance(parameters, dict), "Unsupported command")
    ensure(type(valid_seconds) is int and 1 <= valid_seconds <= MAX_VALIDITY, "Invalid command validity")
    check_checkpoint(context["checkpoint"])
    issued = now()
    body = {"type": COMMAND_TYPE, "request_id": request_id or str(uuid.uuid4()),
            "project_id": context["project_id"], "action": action, "parameters": parameters,
            "expected_checkpoint": context["checkpoint"], "governance_sha256": context["governance_sha256"],
            "created_at": issued, "expires_at": (timestamp(issued) + timedelta(seconds=valid_seconds)).isoformat()}
    ensure(len(canonical(body)) <= MAX_COMMAND, "Command exceeds size budget")
    return sign(body, key)


@dataclass(frozen=True)
class Project:
    slug: str
    project_id: str
    workspace: Path
    policy_file: Path
    trust_file: Path
    access_file: Path

    def governance(self) -> tuple[dict, Trust, dict, str]:
        for path in (self.policy_file, self.trust_file, self.access_file):
            ensure(not path.is_symlink(), "Governance files must not be symlinks")
        policy, trust, access = read_json(self.policy_file), Trust.from_file(self.trust_file), read_json(self.access_file)
        validate_policy(policy)
        fields(access, {"schema", "project_id", "members"})
        ensure(access["schema"] == "opentapeout.team-access/v1" and access["project_id"] == self.project_id,
               "Access file belongs to a different project")
        ensure(isinstance(access["members"], dict), "Invalid project membership")
        principals = set()
        for subject, entry in access["members"].items():
            ensure(isinstance(subject, str) and 0 < len(subject) <= 512, "Invalid subject")
            fields(entry, {"principal", "permissions"})
            identifier(entry["principal"])
            ensure(entry["principal"] not in principals, "Different subjects must not share a principal")
            principals.add(entry["principal"])
            permissions = entry["permissions"]
            ensure(isinstance(permissions, list) and all(isinstance(p, str) and p in PERMISSIONS for p in permissions)
                   and len(permissions) == len(set(permissions)), "Invalid permission allowlist")
        governance_hash = digest({"project_id": self.project_id, "policy": policy, "trust": trust.data, "access": access})
        return policy, trust, access, governance_hash

    def member(self, identity: Identity, access: dict, permission: str) -> str:
        entry = access["members"].get(identity.subject)
        # Unknown projects and projects hidden from this identity deliberately share a response.
        require(entry is not None and "read" in entry["permissions"], "NOT_FOUND", "Project not found", 404)
        require(permission in entry["permissions"], "PERMISSION_DENIED", "Project permission is required", 403)
        required_scope = "opentapeout:read" if permission in {"read", "audit"} else "opentapeout:write"
        require(required_scope in identity.scopes, "SCOPE_REQUIRED", "Access-token scope is required", 403)
        return entry["principal"]


class Gateway:
    def __init__(self, config_file: Path):
        self.config_file = config_file.absolute()
        ensure(not self.config_file.is_symlink(), "Gateway configuration must not be a symlink")
        config = read_json(self.config_file)
        fields(config, {"schema", "identity", "projects"})
        ensure(config["schema"] == "opentapeout.team/v1", "Unsupported team configuration")
        self.tokens = AccessTokens(config["identity"])
        ensure(isinstance(config["projects"], dict) and config["projects"], "Configure at least one project")
        self.projects: dict[str, Project] = {}
        roots, ids, protected = [], set(), [self.config_file, self.tokens.path]
        for slug, entry in config["projects"].items():
            identifier(slug)
            fields(entry, {"project_id", "workspace", "policy", "trust", "access"})
            ensure(isinstance(entry["project_id"], str) and entry["project_id"] not in ids, "Duplicate project ID")
            ids.add(entry["project_id"])
            paths = [Path(entry[k]) for k in ("workspace", "policy", "trust", "access")]
            ensure(all(p.is_absolute() and not p.is_symlink() for p in paths), "Absolute nonsymlink paths required")
            paths = [p.resolve(strict=True) for p in paths]
            root = paths[0]
            ensure(all(not root.is_relative_to(other) and not other.is_relative_to(root) for other in roots),
                   "Project workspaces must not overlap")
            roots.append(root)
            protected.extend(paths[1:])
            project = Project(slug, entry["project_id"], *paths)
            project.governance()
            ensure(Engine(root).state()["project"]["id"] == project.project_id, "Workspace project ID mismatch")
            self.projects[slug] = project
        ensure(all(not path.resolve().is_relative_to(root) for path in protected for root in roots),
               "Configuration, JWKS, policy, trust and access files must live outside ALL workspaces")

    def project(self, slug: str) -> Project:
        project = self.projects.get(slug)
        require(project is not None, "NOT_FOUND", "Project not found", 404)
        return project

    def context(self, slug: str, token: str) -> dict:
        identity = self.tokens.verify(token)
        project = self.project(slug)
        _, _, access, governance_hash = project.governance()
        principal = project.member(identity, access, "read")
        engine = Engine(project.workspace)
        with engine.store.transaction() as tx:
            state = state_from(tx.events)
            ensure(state["project"]["id"] == project.project_id, "Workspace project ID mismatch")
            return {"project_id": project.project_id, "slug": slug, "principal": principal,
                    "permissions": access["members"][identity.subject]["permissions"],
                    "governance_sha256": governance_hash, "checkpoint": tx.checkpoint}

    def execute(self, slug: str, token: str, envelope: dict) -> dict:
        # Verify again under the write lock, so a token expiring while queued cannot mutate.
        self.tokens.verify(token)
        project = self.project(slug)
        ensure(len(canonical(envelope)) <= MAX_COMMAND, "Command exceeds size budget")
        engine = Engine(project.workspace)
        with engine.store.transaction(write=True) as tx:
            identity = self.tokens.verify(token)
            policy, trust, access, governance_hash = project.governance()
            body, signer = trust.verify(envelope, role="team", statement_type=COMMAND_TYPE)
            fields(body, {"type", "request_id", "project_id", "action", "parameters", "expected_checkpoint",
                          "governance_sha256", "created_at", "expires_at"})
            ensure(isinstance(body["action"], str) and body["action"] in ACTIONS, "Unsupported team action")
            principal = project.member(identity, access, body["action"])
            require(signer == principal, "IDENTITY_MISMATCH", "Access identity and command signer must match", 403)
            require(body["project_id"] == project.project_id, "PROJECT_MISMATCH", "Command belongs to another project", 403)
            try:
                ensure(str(uuid.UUID(body["request_id"])) == body["request_id"], "Canonical request UUID required")
            except (ValueError, AttributeError, TypeError) as exc:
                raise TeamError("INVALID_COMMAND", "Canonical request UUID required") from exc
            check_window(body)
            state = state_from(tx.events)
            ensure(state["project"]["id"] == project.project_id, "Workspace project ID mismatch")
            previous = state["team_commands"].get(body["request_id"])
            if previous is not None:
                require(previous["request_sha256"] == digest(envelope), "REQUEST_ID_REUSED",
                        "Request ID was already used for different signed content", 409)
                return {**previous["response"], "checkpoint": previous["checkpoint"], "replayed": True}
            check_checkpoint(body["expected_checkpoint"])
            require(body["expected_checkpoint"] == tx.checkpoint, "STALE_CHECKPOINT",
                    "Ledger changed; fetch current context and review before signing again", 409)
            require(body["governance_sha256"] == governance_hash, "GOVERNANCE_CHANGED",
                    "Policy, keys or permissions changed; review the new context", 409)
            result = self._apply(engine, tx, state, body, envelope["key_id"], principal, policy, trust)
            # Recheck observable authorization changes/expiry during a potentially slow evidence gate.
            current_identity = self.tokens.verify(token)
            _, _, current_access, current_hash = project.governance()
            require(current_hash == governance_hash, "GOVERNANCE_CHANGED",
                    "Governance changed during validation; transaction rolled back", 409)
            project.member(current_identity, current_access, body["action"])
            response = {"request_id": body["request_id"], "action": body["action"], "result": result,
                        "mutation_checkpoint": tx.checkpoint}
            tx.append("team.command", {"request_id": body["request_id"], "request_sha256": digest(envelope),
                      "envelope": envelope, "response": response,
                      "identity": {"issuer": identity.issuer, "subject": identity.subject,
                                   "client_id": identity.client_id}}, principal)
            return {**response, "checkpoint": tx.checkpoint, "replayed": False}

    @staticmethod
    def _apply(engine, tx, state, body, command_key_id, principal, policy, trust) -> dict:
        action, params = body["action"], body["parameters"]
        if action == "candidate.create":
            fields(params, {"name", "notes", "deliveries"})
            ensure(isinstance(params["deliveries"], dict) and len(params["deliveries"]) <= 1000
                   and all(isinstance(k, str) and isinstance(v, str) for k, v in params["deliveries"].items()),
                   "Delivery aliases must map to existing resource IDs")
            checksum = engine._candidate(tx, params["name"], params["notes"], params["deliveries"], policy, trust, principal)
            return {"name": params["name"], "candidate_sha256": checksum}
        fields(params, {"statement"})
        envelope = params["statement"]
        ensure(isinstance(envelope, dict) and envelope.get("key_id") == command_key_id,
               "Decision must be signed with the same key as the command")
        payload = envelope.get("payload")
        ensure(isinstance(payload, dict), "Decision payload required")
        ensure(payload.get("project_id") == state["project"]["id"], "Decision project mismatch")
        created = timestamp(payload.get("created_at"))
        ensure(timestamp(body["created_at"]) - timedelta(seconds=MAX_VALIDITY) <= created <= timestamp(body["created_at"]),
               "Decision timestamp must be recent and no later than its command")
        if action == "approval.submit":
            fields(payload, {"type", "project_id", "candidate_sha256", "role", "decision", "created_at"})
            role = payload["role"]
            ensure(isinstance(role, str) and role in policy["approval_roles"] and payload["decision"] == "approve",
                   "Approval role/decision is not required by policy")
            _, reviewer = trust.verify(envelope, role=role, statement_type="opentapeout.approval/v1")
            name = next((n for n, c in state["candidates"].items() if digest(c) == payload["candidate_sha256"]), None)
            ensure(name is not None, "Unknown candidate digest")
            report = engine._gate(tx, name, policy, trust, include_approvals=False)
            require(report["ready"], "EVIDENCE_BLOCKED", "Fresh evidence gate blocks approval", 409)
            ensure(not policy["forbid_self_approval"] or reviewer != state["candidates"][name]["created_by"],
                   "Candidate author cannot approve their own release")
            ensure(not any(digest(a) == digest(envelope) for a in state["approvals"]), "Approval already exists")
            tx.append("approval.signed", envelope, reviewer)
            return {"approval_sha256": digest(envelope), "candidate_sha256": payload["candidate_sha256"]}
        ensure(isinstance(payload.get("reason"), str) and 12 <= len(payload["reason"].strip()) <= 4000,
               "Decision reason must be 12..4000 characters")
        if action == "approval.revoke":
            fields(payload, {"type", "project_id", "approval_sha256", "candidate_sha256", "reason", "created_at"})
            approval = next((a for a in state["approvals"] if digest(a) == payload["approval_sha256"]), None)
            ensure(approval is not None, "Unknown approval")
            ensure(payload["approval_sha256"] not in state["revoked_approvals"], "Approval already revoked")
            original = trust.keys.get(approval["key_id"])
            ensure(original is not None, "Retain original reviewer key in trust store")
            ensure(payload["candidate_sha256"] == approval["payload"]["candidate_sha256"], "Revocation candidate mismatch")
            role = "release-admin" if "release-admin" in trust.keys[command_key_id]["roles"] else approval["payload"]["role"]
            _, reviewer = trust.verify(envelope, role=role, statement_type="opentapeout.approval-revocation/v1")
            require(role == "release-admin" or reviewer == original["principal"], "PERMISSION_DENIED",
                    "Only original reviewer or release-admin may revoke approval", 403)
            tx.append("approval.revoked", envelope, reviewer)
            return {"revoked_approval": payload["approval_sha256"]}
        fields(payload, {"type", "project_id", "release_id", "candidate_sha256", "archive_sha256", "reason", "created_at"})
        ensure(isinstance(payload["release_id"], str), "Release ID required")
        release = state["releases"].get(payload["release_id"])
        ensure(release is not None, "Unknown sealed release")
        ensure(payload["candidate_sha256"] == release["candidate_sha256"]
               and payload["archive_sha256"] == release["archive_sha256"], "Release bytes/digest mismatch")
        ensure(payload["candidate_sha256"] not in state["withdrawals"], "Release already withdrawn")
        _, reviewer = trust.verify(envelope, role="release", statement_type="opentapeout.release-withdrawal/v1")
        tx.append("release.withdrawn", envelope, reviewer)
        return {"withdrawn_release": payload["release_id"]}
