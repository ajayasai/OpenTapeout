"""Signed approval revocation, release withdrawal and short-lived offline status.

A status statement is an authenticated snapshot, not a transparency service. Retain
its sequence externally to reject older snapshots. No offline verifier can learn
about events created after that snapshot without receiving a newer one.
"""
from __future__ import annotations

from datetime import timedelta

from .engine import Engine, state_from
from .signing import Trust, sign
from .util import HEX, digest, ensure, finite_number, now, timestamp

STATUS_TYPE = "opentapeout.release-status/v1"
MAX_STATUS_HOURS = 24


def active_approvals(state: dict) -> list[dict]:
    return [a for a in state["approvals"] if digest(a) not in state["revoked_approvals"]]


def revoke_approval(engine: Engine, approval_sha256: str, reason: str, key, trust: Trust) -> dict:
    ensure(isinstance(reason, str) and len(reason.strip()) >= 12, "Revocation reason requires 12+ characters")
    with engine.store.transaction(write=True) as tx:
        state = state_from(tx.events)
        approval = next((a for a in state["approvals"] if digest(a) == approval_sha256), None)
        ensure(approval is not None, "Unknown approval")
        ensure(approval_sha256 not in state["revoked_approvals"], "Approval already revoked")
        original = trust.keys.get(approval["key_id"])
        ensure(original is not None, "Original reviewer key must remain in trust store (may be revoked)")
        body = {"type": "opentapeout.approval-revocation/v1", "project_id": state["project"]["id"],
                "approval_sha256": approval_sha256, "candidate_sha256": approval["payload"]["candidate_sha256"],
                "reason": reason, "created_at": now()}
        envelope = sign(body, key)
        signer = trust.keys.get(envelope["key_id"], {})
        # Ordinary release signers cannot silently revoke another reviewer's decision.
        role = "release-admin" if "release-admin" in signer.get("roles", []) else approval["payload"]["role"]
        _, principal = trust.verify(envelope, role=role, statement_type=body["type"])
        ensure(role == "release-admin" or principal == original["principal"],
               "Only the original reviewer or release-admin can revoke this approval")
        tx.append("approval.revoked", envelope, principal)
        return envelope


def withdraw_release(engine: Engine, release_id: str, reason: str, key, trust: Trust) -> dict:
    ensure(isinstance(reason, str) and len(reason.strip()) >= 12, "Withdrawal reason requires 12+ characters")
    with engine.store.transaction(write=True) as tx:
        state = state_from(tx.events)
        release = state["releases"].get(release_id)
        ensure(release is not None, "Unknown sealed release")
        candidate_hash = release["candidate_sha256"]
        ensure(candidate_hash not in state["withdrawals"], "Release already withdrawn; withdrawal is irreversible")
        body = {"type": "opentapeout.release-withdrawal/v1", "project_id": state["project"]["id"],
                "release_id": release_id, "candidate_sha256": candidate_hash,
                "archive_sha256": release["archive_sha256"], "reason": reason, "created_at": now()}
        envelope = sign(body, key)
        _, principal = trust.verify(envelope, role="release", statement_type=body["type"])
        tx.append("release.withdrawn", envelope, principal)
        return envelope


def export_status(engine: Engine, key, trust: Trust, *, valid_hours: float = 1) -> dict:
    ensure(finite_number(valid_hours) and 0 < valid_hours <= MAX_STATUS_HOURS,
           "Status validity must be positive and no more than 24 hours")
    with engine.store.transaction() as tx:
        state = state_from(tx.events)
        issued = now()
        body = {"type": STATUS_TYPE, "project_id": state["project"]["id"], "created_at": issued,
                "expires_at": (timestamp(issued) + timedelta(hours=valid_hours)).isoformat(),
                "checkpoint": tx.checkpoint,
                "revoked_approvals": sorted(state["revoked_approvals"]),
                "revoked_waivers": sorted(state["revoked_waivers"]),
                "withdrawn_candidates": sorted(state["withdrawals"])}
        envelope = sign(body, key)
        trust.verify(envelope, role="release", statement_type=STATUS_TYPE)
        return envelope


def verify_status(envelope: dict, trust: Trust, project_id: str, *, minimum_sequence: int = 0,
                  at: str | None = None) -> dict:
    body, principal = trust.verify(envelope, role="release", statement_type=STATUS_TYPE)
    ensure(set(body) == {"type", "project_id", "created_at", "expires_at", "checkpoint",
                         "revoked_approvals", "revoked_waivers", "withdrawn_candidates"},
           "Invalid status statement fields")
    ensure(body["project_id"] == project_id, "Status belongs to a different project")
    issued, expires, current = timestamp(body["created_at"]), timestamp(body["expires_at"]), timestamp(at or now())
    ensure(issued <= current < expires, "Status expired or future-dated")
    ensure(timedelta(0) < expires - issued <= timedelta(hours=MAX_STATUS_HOURS), "Excessive status validity")
    ensure(type(minimum_sequence) is int and minimum_sequence >= 0, "Invalid minimum status sequence")
    checkpoint = body["checkpoint"]
    ensure(isinstance(checkpoint, dict) and set(checkpoint) == {"seq", "hash"}
           and type(checkpoint["seq"]) is int and checkpoint["seq"] >= max(1, minimum_sequence)
           and isinstance(checkpoint["hash"], str) and HEX.fullmatch(checkpoint["hash"]),
           "Invalid or replayed status checkpoint")
    for field in ("revoked_approvals", "revoked_waivers", "withdrawn_candidates"):
        values = body[field]
        ensure(isinstance(values, list) and all(isinstance(x, str) and HEX.fullmatch(x) for x in values)
               and values == sorted(set(values)), "Invalid revocation digest list")
    return {"verified": True, "signer": principal, "statement": body,
            "checked_at": current.isoformat(), "scope": "status snapshot; retain checkpoint sequence externally"}


def check_candidate_status(candidate: dict, approvals: list[dict], envelope: dict, trust: Trust,
                           *, minimum_sequence: int = 0) -> tuple[list[dict], dict]:
    status = verify_status(envelope, trust, candidate["project_id"], minimum_sequence=minimum_sequence)
    body = status["statement"]
    ensure(digest(candidate) not in body["withdrawn_candidates"], "Release has been withdrawn")
    ensure(not {digest(w) for w in candidate["waivers"]} & set(body["revoked_waivers"]),
           "Release contains a revoked waiver")
    approvals = [a for a in approvals if digest(a) not in body["revoked_approvals"]]
    return approvals, status
