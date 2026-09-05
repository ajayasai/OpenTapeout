import copy
from datetime import timedelta

import pytest

from opentapeout.bundle import seal, verify_bundle
from opentapeout.lifecycle import export_status, revoke_approval, verify_status, withdraw_release
from opentapeout.signing import sign
from opentapeout.util import TapeoutError, digest, now, timestamp


def package(ctx):
    ctx.ready()
    path = ctx.root / "private-evidence.zip"
    seal(ctx.engine, "RC1", path, ctx.keys["release"], ctx.policy, ctx.trust)
    return path


def test_reviewer_can_revoke_and_reapprove_without_changing_candidate(ctx):
    ctx.ready()
    first = ctx.engine.state()["approvals"][0]
    revoke_approval(ctx.engine, digest(first), "Need to repeat physical review", ctx.keys["alice"], ctx.trust)
    assert not ctx.gate()["ready"]
    assert any(b["code"] == "APPROVALS_MISSING" for b in ctx.gate()["blockers"])
    assert len(ctx.engine.state()["approvals"]) == 2
    ctx.engine.approve("RC1", "physical", ctx.keys["alice"], ctx.policy, ctx.trust)
    assert ctx.gate()["ready"]


@pytest.mark.parametrize("signer", ["flexible", "release", "bob", "author"])
def test_cannot_revoke_another_principals_approval(ctx, signer):
    ctx.ready()
    old = ctx.engine.store.verify_checkpoint()
    with pytest.raises(TapeoutError):
        revoke_approval(ctx.engine, digest(ctx.engine.state()["approvals"][0]),
                        "Unauthorized revocation attempt", ctx.keys[signer], ctx.trust)
    assert ctx.engine.store.verify_checkpoint() == old


def test_explicit_release_admin_can_revoke(ctx):
    for entry in ctx.trust.keys.values():
        if entry["principal"] == "release":
            entry["roles"].append("release-admin")
    ctx.ready()
    revoke_approval(ctx.engine, digest(ctx.engine.state()["approvals"][0]),
                    "Compromised reviewer workstation", ctx.keys["release"], ctx.trust)
    assert not ctx.gate()["ready"]


def test_revocation_is_exact_and_nonrepeatable(ctx):
    ctx.ready()
    h = digest(ctx.engine.state()["approvals"][0])
    with pytest.raises(TapeoutError, match="Unknown"):
        revoke_approval(ctx.engine, "0" * 64, "A sufficiently long reason", ctx.keys["alice"], ctx.trust)
    with pytest.raises(TapeoutError, match="reason"):
        revoke_approval(ctx.engine, h, "", ctx.keys["alice"], ctx.trust)
    revoke_approval(ctx.engine, h, "A sufficiently long reason", ctx.keys["alice"], ctx.trust)
    with pytest.raises(TapeoutError, match="already"):
        revoke_approval(ctx.engine, h, "A sufficiently long reason", ctx.keys["alice"], ctx.trust)


def test_historical_verification_and_fresh_status_are_distinct(ctx):
    archive = package(ctx)
    original = archive.read_bytes()
    revoke_approval(ctx.engine, digest(ctx.engine.state()["approvals"][0]),
                    "The original reviewer withdrew consent", ctx.keys["alice"], ctx.trust)
    assert verify_bundle(archive, ctx.policy, ctx.trust)["verified"]
    status = export_status(ctx.engine, ctx.keys["release"], ctx.trust)
    with pytest.raises(TapeoutError, match="APPROVALS_MISSING"):
        verify_bundle(archive, ctx.policy, ctx.trust, status=status)
    assert archive.read_bytes() == original


def test_withdrawal_blocks_live_gate_and_status_verification(ctx):
    archive = package(ctx)
    withdrawal = withdraw_release(ctx.engine, "RC1", "Post-release issue requires withdrawal", ctx.keys["release"], ctx.trust)
    assert withdrawal["payload"]["archive_sha256"]
    assert any(b["code"] == "RELEASE_WITHDRAWN" for b in ctx.gate()["blockers"])
    assert verify_bundle(archive, ctx.policy, ctx.trust)["release_status"] is None
    with pytest.raises(TapeoutError, match="withdrawn"):
        verify_bundle(archive, ctx.policy, ctx.trust, status=export_status(ctx.engine, ctx.keys["release"], ctx.trust))
    with pytest.raises(TapeoutError, match="already withdrawn"):
        withdraw_release(ctx.engine, "RC1", "Repeated withdrawal reason", ctx.keys["release"], ctx.trust)
    with pytest.raises(TapeoutError, match="blocks approval"):
        ctx.engine.approve("RC1", "physical", ctx.keys["alice"], ctx.policy, ctx.trust)


def test_withdrawal_requires_sealed_release_and_release_key(ctx):
    ctx.ready()
    with pytest.raises(TapeoutError, match="Unknown"):
        withdraw_release(ctx.engine, "RC1", "Not yet a sealed release", ctx.keys["release"], ctx.trust)
    seal(ctx.engine, "RC1", ctx.root / "a.zip", ctx.keys["release"], ctx.policy, ctx.trust)
    with pytest.raises(TapeoutError, match="authorized"):
        withdraw_release(ctx.engine, "RC1", "Unauthorized reviewer request", ctx.keys["alice"], ctx.trust)


@pytest.mark.parametrize("hours", [0, -1, 25, True, float("inf"), float("nan"), "1"])
def test_invalid_status_lifetime(ctx, hours):
    with pytest.raises(TapeoutError, match="validity"):
        export_status(ctx.engine, ctx.keys["release"], ctx.trust, valid_hours=hours)


def test_status_authority_and_scope(ctx):
    project = ctx.engine.state()["project"]["id"]
    with pytest.raises(TapeoutError, match="authorized"):
        export_status(ctx.engine, ctx.keys["alice"], ctx.trust)
    status = export_status(ctx.engine, ctx.keys["release"], ctx.trust)
    assert verify_status(status, ctx.trust, project)["verified"]
    with pytest.raises(TapeoutError, match="different project"):
        verify_status(status, ctx.trust, "other-project")
    tampered = copy.deepcopy(status)
    tampered["payload"]["revoked_approvals"] = ["f" * 64]
    with pytest.raises(TapeoutError):
        verify_status(tampered, ctx.trust, project)


def test_status_expiry_and_replay_protection(ctx):
    archive = package(ctx)
    status = export_status(ctx.engine, ctx.keys["release"], ctx.trust)
    project = ctx.engine.state()["project"]["id"]
    sequence = status["payload"]["checkpoint"]["seq"]
    result = verify_bundle(archive, ctx.policy, ctx.trust, status=status, minimum_status_sequence=sequence)
    assert result["release_status"]["verified"]
    with pytest.raises(TapeoutError, match="replayed"):
        verify_status(status, ctx.trust, project, minimum_sequence=sequence + 1)
    with pytest.raises(TapeoutError, match="expired"):
        verify_status(status, ctx.trust, project, at=status["payload"]["expires_at"])
    with pytest.raises(TapeoutError, match="future"):
        verify_status(status, ctx.trust, project,
                      at=(timestamp(status["payload"]["created_at"]) - timedelta(seconds=1)).isoformat())
    with pytest.raises(TapeoutError, match="required"):
        verify_bundle(archive, ctx.policy, ctx.trust, minimum_status_sequence=sequence)


@pytest.mark.parametrize("mutation", [
    {"revoked_approvals": ["invalid"]}, {"revoked_waivers": ["a"*64, "a"*64]},
    {"withdrawn_candidates": "not-a-list"}, {"checkpoint": {"seq": 0, "hash": "0"*64}},
    {"checkpoint": {"seq": True, "hash": "0"*64}}, {"extra": "never silently ignore"},
    {"expires_at": (timestamp(now()) + timedelta(days=30)).isoformat()},
])
def test_even_valid_signatures_require_strict_status_schema(ctx, mutation):
    status = export_status(ctx.engine, ctx.keys["release"], ctx.trust)
    body = {**status["payload"], **mutation}
    with pytest.raises(TapeoutError):
        verify_status(sign(body, ctx.keys["release"]), ctx.trust, ctx.engine.state()["project"]["id"])
