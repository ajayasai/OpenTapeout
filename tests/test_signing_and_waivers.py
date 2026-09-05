import copy
from datetime import timedelta

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentapeout.policy import _assign_roles, evaluate
from opentapeout.signing import Trust, generate_key, load_key, sign
from opentapeout.util import TapeoutError, digest, now, timestamp


def codes(report):
    return {item["code"] for item in report["blockers"]}


def expiry():
    return (timestamp(now()) + timedelta(days=3)).isoformat()


def test_correct_signed_scoped_waiver_unblocks_one_violation(ctx, violation):
    result=ctx.run(status="fail",violations=[violation])
    fingerprint=result["result"]["violations"][0]["fingerprint"]
    ctx.engine.waive(result["id"],fingerprint,"Reviewed intentional fixture exception","author",expiry(),ctx.keys["alice"],ctx.trust)
    ctx.candidate();ctx.approve();assert ctx.gate()["ready"]
    assert ctx.gate()["valid_waivers"]==1


def test_waiver_never_covers_another_violation(ctx,violation):
    other={**violation,"location":"top/u1/net1"}
    result=ctx.run(status="fail",violations=[violation,other])
    ctx.engine.waive(result["id"],result["result"]["violations"][0]["fingerprint"],
                    "One deliberate exception only","author",expiry(),ctx.keys["alice"],ctx.trust)
    ctx.candidate();assert "UNWAIVED_VIOLATION" in codes(ctx.gate())


def test_waiver_does_not_cover_nonzero_exit(ctx,violation):
    result=ctx.run(status="fail",violations=[violation],exit_code=1)
    ctx.engine.waive(result["id"],result["result"]["violations"][0]["fingerprint"],
                    "Approved only this design marker","author",expiry(),ctx.keys["alice"],ctx.trust)
    ctx.candidate();assert "TOOL_FAILED" in codes(ctx.gate())


def test_waiver_owner_cannot_self_review(ctx,violation):
    result=ctx.run(status="fail",violations=[violation])
    with pytest.raises(TapeoutError,match="owner cannot review"):
        ctx.engine.waive(result["id"],result["result"]["violations"][0]["fingerprint"],
                        "Reason is long enough here","alice",expiry(),ctx.keys["alice"],ctx.trust)


@pytest.mark.parametrize("bad_expiry",["2020-01-01T00:00:00Z","2099-01-01", "not-a-time"])
def test_waiver_requires_future_timezone_expiry(ctx,violation,bad_expiry):
    result=ctx.run(status="fail",violations=[violation])
    with pytest.raises(TapeoutError):
        ctx.engine.waive(result["id"],result["result"]["violations"][0]["fingerprint"],
                        "Reason is long enough here","author",bad_expiry,ctx.keys["alice"],ctx.trust)


def test_waiver_expiration_is_rechecked_at_gate(ctx,violation):
    result=ctx.run(status="fail",violations=[violation])
    end=expiry()
    ctx.engine.waive(result["id"],result["result"]["violations"][0]["fingerprint"],
                    "Reason is long enough here","author",end,ctx.keys["alice"],ctx.trust)
    ctx.candidate()
    candidate=ctx.engine.state()["candidates"]["RC1"]
    assert "UNWAIVED_VIOLATION" in codes(evaluate(candidate,ctx.policy,ctx.trust,[],at=end))


def test_waiver_does_not_transfer_to_new_run(ctx,violation):
    result=ctx.run(status="fail",violations=[violation])
    ctx.engine.waive(result["id"],result["result"]["violations"][0]["fingerprint"],
                    "Reason is long enough here","author",expiry(),ctx.keys["alice"],ctx.trust)
    ctx.run(status="fail",violations=[violation]);ctx.candidate()
    assert "UNWAIVED_VIOLATION" in codes(ctx.gate())


def test_waiver_revocation_invalidates_candidate(ctx,violation):
    result=ctx.run(status="fail",violations=[violation])
    wid=ctx.engine.waive(result["id"],result["result"]["violations"][0]["fingerprint"],
                    "Reason is long enough here","author",expiry(),ctx.keys["alice"],ctx.trust)
    ctx.candidate();ctx.approve()
    ctx.engine.revoke_waiver(wid,"Exception is no longer acceptable",ctx.keys["alice"],ctx.trust)
    assert {"CANDIDATE_CHANGED","UNWAIVED_VIOLATION"} <= codes(ctx.gate())


def test_evidence_attachment_preserved(ctx,violation):
    (ctx.root/"review.txt").write_text("Synthetic design rationale")
    checksum=ctx.engine.attach("review.txt")
    result=ctx.run(status="fail",violations=[violation])
    ctx.engine.waive(result["id"],result["result"]["violations"][0]["fingerprint"],
                    "Reason is long enough here","author",expiry(),ctx.keys["alice"],ctx.trust,attachments=[checksum])
    ctx.candidate();ctx.approve();assert ctx.gate()["ready"]


def test_candidate_author_cannot_self_approve(ctx):
    ctx.run();ctx.candidate()
    with pytest.raises(TapeoutError,match="author cannot approve"):
        ctx.engine.approve("RC1","physical",ctx.keys["author"],ctx.policy,ctx.trust)


def test_unauthorized_role_rejected(ctx):
    ctx.run();ctx.candidate()
    with pytest.raises(TapeoutError,match="not authorized"):
        ctx.engine.approve("RC1","verification",ctx.keys["alice"],ctx.policy,ctx.trust)


def test_one_principal_cannot_satisfy_two_required_reviewers(ctx):
    ctx.run();ctx.candidate()
    for role in ["physical","verification"]:
        ctx.engine.approve("RC1",role,ctx.keys["flexible"],ctx.policy,ctx.trust)
    assert "APPROVALS_MISSING" in codes(ctx.gate())


def test_role_matching_is_not_greedy():
    assert _assign_roles(["physical","verification"],{"physical":{"a","b"},"verification":{"a"}},True)=={
        "verification":"a","physical":"b"}


def test_two_keys_same_principal_are_still_one_reviewer(ctx):
    data=copy.deepcopy(ctx.trust.data)
    for entry in data["keys"].values():
        if entry["principal"] in {"alice","bob"}:entry["principal"]="same-human"
    trust=Trust(data)
    ctx.run();ctx.engine.candidate("RC1","Release notes",{"chip.gds":"layout"},ctx.policy,trust,"author")
    ctx.engine.approve("RC1","physical",ctx.keys["alice"],ctx.policy,trust)
    ctx.engine.approve("RC1","verification",ctx.keys["bob"],ctx.policy,trust)
    assert "APPROVALS_MISSING" in codes(ctx.engine.gate("RC1",ctx.policy,trust))


def test_untrusted_key_cannot_sign(ctx):
    ctx.run();ctx.candidate()
    with pytest.raises(TapeoutError):
        ctx.engine.approve("RC1","physical",Ed25519PrivateKey.generate(),ctx.policy,ctx.trust)


def test_approval_signature_binds_candidate_hash(ctx):
    ctx.ready();state=ctx.engine.state()
    altered=copy.deepcopy(state["approvals"])
    altered[0]["payload"]["candidate_sha256"]="0"*64
    report=evaluate(state["candidates"]["RC1"],ctx.policy,ctx.trust,altered,at=now())
    assert "APPROVALS_MISSING" in codes(report)


def test_signature_domain_separation(ctx):
    payload={"type":"opentapeout.approval/v1","created_at":now(),"role":"physical"}
    signed=sign(payload,ctx.keys["alice"])
    with pytest.raises(TapeoutError,match="domain"):
        ctx.trust.verify(signed,role="waiver",statement_type="opentapeout.waiver/v1")


def test_changed_notes_require_new_approval(ctx):
    ctx.ready();ctx.candidate("RC2",notes="New notes must be approved independently")
    assert "APPROVALS_MISSING" in codes(ctx.gate("RC2"))


def test_key_file_exclusive_and_password_supported(tmp_path):
    path=tmp_path/"key.pem"
    public=generate_key(path,password=b"test-only-encryption-passphrase")
    assert len(public["key_id"])==32
    assert load_key(path,b"test-only-encryption-passphrase")
    with pytest.raises(TapeoutError):load_key(path,b"wrong")
    with pytest.raises(TapeoutError):generate_key(path)


@pytest.mark.parametrize("change",["public","id","roles","principal","schema"])
def test_invalid_trust_store_rejected(ctx,change):
    data=copy.deepcopy(ctx.trust.data);kid=next(iter(data["keys"]))
    if change=="public":data["keys"][kid]["public_key"]="garbage"
    elif change=="id":data["keys"]["wrong-id"]=data["keys"].pop(kid)
    elif change=="roles":data["keys"][kid]["roles"]=[]
    elif change=="principal":data["keys"][kid]["principal"]=""
    else:data["schema"]="untrusted-schema"
    with pytest.raises(TapeoutError):Trust(data)
