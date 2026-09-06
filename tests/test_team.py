"""Team controls are tested with real RSA access tokens and real Ed25519 commands."""
from __future__ import annotations

import base64
import copy
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi.testclient import TestClient

from opentapeout.bundle import seal, verify_bundle
from opentapeout.engine import Engine
from opentapeout.signing import Trust, sign
from opentapeout.store import Transaction
from opentapeout.team import ACTIONS, Gateway, make_command
from opentapeout.team_auth import TeamError
from opentapeout.team_web import create_team_app
from opentapeout.util import TapeoutError, canonical, digest, now, read_json, write_json


@pytest.fixture(scope="module")
def rsa_key():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@pytest.fixture
def team(ctx, tmp_path, rsa_key):
    config_dir = tmp_path / "config"
    config_dir.mkdir()
    for entry in ctx.trust.keys.values():
        entry["roles"].append("team")
    ctx.trust = Trust(ctx.trust.data)
    project_id = ctx.engine.state()["project"]["id"]
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(rsa_key.public_key(), as_dict=True)
    jwk.update(kid="issuer-key", use="sig", alg="RS256")
    write_json(config_dir / "jwks.json", {"keys": [jwk]})
    write_json(config_dir / "policy.json", ctx.policy)
    write_json(config_dir / "trust.json", ctx.trust.data)
    access = {"schema": "opentapeout.team-access/v1", "project_id": project_id, "members": {
        "sub-"+p: {"principal": p, "permissions": ["read", "audit", *sorted(ACTIONS)]}
        for p in ctx.keys}}
    access["members"]["sub-reader"] = {"principal": "reader", "permissions": ["read"]}
    write_json(config_dir / "access.json", access)
    config = {"schema": "opentapeout.team/v1", "identity": {
        "issuer": "https://identity.example.test/realm", "audience": "opentapeout-api",
        "jwks_file": str(config_dir/"jwks.json"), "client_ids": ["review-cli"], "max_lifetime_seconds": 600},
        "projects": {"chip": {"project_id": project_id, "workspace": str(ctx.root),
            "policy": str(config_dir/"policy.json"), "trust": str(config_dir/"trust.json"),
            "access": str(config_dir/"access.json")}}}
    write_json(config_dir/"team.json", config)
    gateway = Gateway(config_dir/"team.json")
    def token(principal="author", **overrides):
        at = int(time.time())
        claims = {"iss": config["identity"]["issuer"], "aud": "opentapeout-api", "sub": "sub-"+principal,
            "iat": at, "exp": at+120, "jti": str(uuid.uuid4()), "client_id": "review-cli",
            "scope": "opentapeout:read opentapeout:write"}
        claims.update(overrides)
        return jwt.encode(claims, rsa_key, algorithm="RS256", headers={"kid": "issuer-key", "typ": "at+jwt"})
    def command(action="candidate.create", params=None, principal="author", **kwargs):
        return make_command(gateway.context("chip", token(principal)), action,
                params if params is not None else {"name": "RC1", "notes": "Reviewed synthetic candidate", "deliveries": {"chip.gds": "layout"}},
                ctx.keys[principal], **kwargs)
    def decision(principal="alice", kind="approval", **overrides):
        if kind == "approval":
            payload = {"type": "opentapeout.approval/v1", "project_id": project_id,
                "candidate_sha256": digest(ctx.engine.state()["candidates"]["RC1"]),
                "role": "physical" if principal != "bob" else "verification", "decision": "approve", "created_at": now()}
        else:
            payload = {"type": "opentapeout."+kind+"/v1", "project_id": project_id, "created_at": now(), **overrides}
        payload.update(overrides)
        return sign(payload, ctx.keys[principal])
    client = TestClient(create_team_app(config_dir/"team.json"), base_url="https://testserver")
    return SimpleNamespace(ctx=ctx, cfg=config, folder=config_dir, access=access, token=token,
        command=command, gateway=gateway, client=client, decision=decision, rsa=rsa_key,
        project_id=project_id, path=config_dir/"team.json")


def submit(team, envelope, principal="author"):
    return team.client.post("/v1/projects/chip/commands", json=envelope,
                            headers={"Authorization": "Bearer "+team.token(principal)})


def auth(team, principal="author"):
    return {"Authorization": "Bearer "+team.token(principal)}


def save(path, value):
    write_json(path, value, overwrite=True)


def test_team_round_trip_two_reviewers_and_offline_archive(team, tmp_path):
    t = team
    t.ctx.run()
    creation = submit(t, t.command())
    assert creation.status_code == 200, creation.text
    assert t.ctx.engine.state()["candidates"]["RC1"]["created_by"] == "author"
    for principal in ("alice", "bob"):
        response = submit(t, t.command("approval.submit", {"statement": t.decision(principal)}, principal), principal)
        assert response.status_code == 200, response.text
    gate = t.client.get("/v1/projects/chip/gate/RC1", headers=auth(t)).json()
    assert gate["ready"] and gate["approval_assignment"] == {"physical": "alice", "verification": "bob"}
    result = seal(t.ctx.engine, "RC1", tmp_path/"archive.zip", t.ctx.keys["release"], t.ctx.policy, t.ctx.trust)
    assert result["archive_sha256"]
    assert verify_bundle(tmp_path/"archive.zip", t.ctx.policy, t.ctx.trust)["verified"]
    assert len(t.ctx.engine.state()["team_commands"]) == 3


@pytest.mark.parametrize("path", ["/v1/projects", "/v1/projects/chip/context", "/v1/projects/chip/candidates",
    "/v1/projects/chip/candidates/RC1", "/v1/projects/chip/gate/RC1", "/v1/projects/chip/audit"])
def test_every_read_requires_auth(team, path):
    response = team.client.get(path)
    assert response.status_code == 401
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["www-authenticate"] == "Bearer"


@pytest.mark.parametrize("claims", [
    {"iss": "https://evil.example"}, {"aud": "another-api"}, {"client_id": "unapproved"},
    {"exp": 1}, {"exp": int(time.time())+10000}, {"iat": int(time.time())+600},
    {"nbf": int(time.time())+600}, {"scope": ["opentapeout:write"]}, {"iat": "1"},
    {"exp": True}, {"sub": 123}, {"jti": 123}, {"sub": ""}, {"client_id": []}, {"nbf": "1"},
])
def test_access_token_claim_validation(team, claims):
    response = team.client.get("/v1/projects", headers={"Authorization": "Bearer "+team.token(**claims)})
    assert response.status_code == 401


@pytest.mark.parametrize("removed", ["iss", "aud", "sub", "exp", "iat", "jti", "client_id"])
def test_required_claims(team, removed):
    claims = jwt.decode(team.token(), options={"verify_signature": False})
    del claims[removed]
    token = jwt.encode(claims, team.rsa, algorithm="RS256", headers={"kid":"issuer-key", "typ":"at+jwt"})
    with pytest.raises(TeamError):
        team.gateway.tokens.verify(token)


@pytest.mark.parametrize("headers", [
    {"kid":"unknown", "typ":"at+jwt"}, {"kid":"issuer-key", "typ":"JWT"},
    {"kid":"issuer-key", "typ":"at+jwt", "jku":"https://evil.invalid/keys"},
    {"kid":"issuer-key", "typ":"at+jwt", "jwk":{}},
    {"kid":"issuer-key", "typ":"at+jwt", "crit":["extension"]},
    {"kid":123, "typ":"at+jwt"},
])
def test_token_type_key_and_external_headers_rejected(team, headers):
    claims = jwt.decode(team.token(), options={"verify_signature": False})
    # PyJWT rejects non-string kid at encoding time; construct that malformed header manually.
    if not isinstance(headers["kid"], str):
        valid = team.token().split(".")
        valid[0] = base64.urlsafe_b64encode(canonical({"alg":"RS256", **headers})).rstrip(b"=").decode()
        token = ".".join(valid)
    else:
        token = jwt.encode(claims, team.rsa, algorithm="RS256", headers=headers)
    with pytest.raises(TeamError):
        team.gateway.tokens.verify(token)


@pytest.mark.parametrize("token", ["", "x", "a.b.c.d", "a.b.c", "a=.b.c", "x"*16385,
    "eyJhbGciOiJub25lIn0.e30."])
def test_malformed_tokens_fail_closed(team, token):
    with pytest.raises(TeamError):
        team.gateway.tokens.verify(token)


def test_jwt_duplicate_keys_rejected(team):
    parts = team.token().split(".")
    parts[0] = base64.urlsafe_b64encode(b'{"alg":"RS256","alg":"none","typ":"at+jwt"}').rstrip(b"=").decode()
    with pytest.raises(TeamError):
        team.gateway.tokens.verify(".".join(parts))


def test_hmac_algorithm_confusion_rejected(team):
    token = jwt.encode({"sub":"author"}, b"x"*32, algorithm="HS256", headers={"kid":"issuer-key", "typ":"at+jwt"})
    with pytest.raises(TeamError):
        team.gateway.tokens.verify(token)


def test_signature_tampering_rejected(team):
    token = team.token().split(".")
    token[2] = ("A" if token[2][0] != "A" else "B")+token[2][1:]
    with pytest.raises(TeamError):
        team.gateway.tokens.verify(".".join(token))


def test_unknown_subject_hidden_project(team):
    headers = {"Authorization":"Bearer "+team.token("stranger")}
    assert team.client.get("/v1/projects", headers=headers).json() == {"projects":[]}
    existing = team.client.get("/v1/projects/chip/context", headers=headers)
    missing = team.client.get("/v1/projects/hidden/context", headers=headers)
    assert existing.status_code == missing.status_code == 404
    assert existing.json() == missing.json()


def test_reader_cannot_write_or_audit(team):
    envelope = team.command()
    before = team.ctx.engine.store.verify_checkpoint()
    response = submit(team, envelope, "reader")
    assert response.status_code == 403
    assert team.client.get("/v1/projects/chip/audit", headers=auth(team,"reader")).status_code == 403
    assert team.ctx.engine.store.verify_checkpoint() == before


def test_token_scopes_are_not_project_permissions(team):
    headers = {"Authorization":"Bearer "+team.token("author", scope="opentapeout:read")}
    response = team.client.post("/v1/projects/chip/commands", json=team.command(), headers=headers)
    assert response.status_code == 403
    response = team.client.get("/v1/projects/chip/context", headers={"Authorization":"Bearer "+team.token(scope="")})
    assert response.status_code == 403


def test_identity_cannot_impersonate_other_signer(team):
    before = team.ctx.engine.store.verify_checkpoint()
    assert submit(team, team.command(), "alice").json()["error"] == "IDENTITY_MISMATCH"
    assert team.ctx.engine.store.verify_checkpoint() == before


def test_project_bound_command(team):
    envelope = team.command()
    envelope["payload"]["project_id"] = str(uuid.uuid4())
    envelope = sign(envelope["payload"], team.ctx.keys["author"])
    assert submit(team, envelope).json()["error"] == "PROJECT_MISMATCH"


def test_forged_command_rejected(team):
    envelope = team.command()
    envelope["payload"]["parameters"]["name"] = "FORGED"
    assert submit(team, envelope).status_code == 422
    assert "FORGED" not in team.ctx.engine.state()["candidates"]


def test_duplicate_retry_is_durable_across_gateway_restart(team):
    envelope = team.command()
    first = submit(team, envelope).json()
    new_gateway = Gateway(team.path)
    again = new_gateway.execute("chip", team.token(), envelope)
    assert again["replayed"] and not first["replayed"]
    assert {k:v for k,v in first.items() if k != "replayed"} == {k:v for k,v in again.items() if k != "replayed"}
    assert len(team.ctx.engine.state()["candidates"]) == 1
    assert team.ctx.engine.store.verify_checkpoint() == first["checkpoint"]


def test_request_id_cannot_be_reused_for_different_bytes(team):
    envelope = team.command()
    assert submit(team,envelope).status_code == 200
    envelope["payload"]["parameters"]["notes"] = "different request"
    assert submit(team,sign(envelope["payload"],team.ctx.keys["author"])).json()["error"] == "REQUEST_ID_REUSED"


def test_compare_and_swap_rejects_stale_hash_even_same_sequence(team):
    envelope = team.command()
    envelope["payload"]["expected_checkpoint"]["hash"] = "f"*64
    assert submit(team,sign(envelope["payload"],team.ctx.keys["author"])).json()["error"] == "STALE_CHECKPOINT"


def test_concurrent_different_writers_exactly_one_commits(team):
    requests = [team.command(params={"name":f"RC{i}", "notes":"concurrent candidate", "deliveries":{}}) for i in range(8)]
    token = team.token()
    def execute(request):
        try:
            return team.gateway.execute("chip",token,request)
        except TeamError as exc:
            return exc.code
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(execute,requests))
    assert sum(isinstance(r,dict) for r in results) == 1
    assert results.count("STALE_CHECKPOINT") == 7
    assert len(team.ctx.engine.state()["candidates"]) == 1


def test_concurrent_duplicate_only_one_mutation(team):
    envelope, token = team.command(), team.token()
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _:team.gateway.execute("chip",token,envelope),range(8)))
    assert sum(not r["replayed"] for r in results) == 1
    assert len({r["checkpoint"]["hash"] for r in results}) == 1


def test_command_and_receipt_rollback_together(team, monkeypatch):
    original = Transaction.append
    def fail(self, event_type, payload, actor):
        if event_type == "team.command":
            raise RuntimeError("injected crash before receipt commit")
        return original(self,event_type,payload,actor)
    before = team.ctx.engine.store.verify_checkpoint()
    monkeypatch.setattr(Transaction,"append",fail)
    with pytest.raises(RuntimeError):
        team.gateway.execute("chip",team.token(),team.command())
    assert team.ctx.engine.store.verify_checkpoint() == before
    assert not team.ctx.engine.state()["candidates"]


@pytest.mark.parametrize("change", ["policy", "trust", "access"])
def test_governance_change_requires_new_review(team, change):
    envelope = team.command()
    path = team.folder/(change+".json")
    data = read_json(path)
    if change == "policy":
        data["forbid_self_approval"] = not data["forbid_self_approval"]
    elif change == "trust":
        next(iter(data["keys"].values()))["roles"].append("new-role")
    else:
        data["members"]["sub-reader"]["permissions"].append("audit")
    save(path,data)
    assert submit(team,envelope).json()["error"] == "GOVERNANCE_CHANGED"


def test_membership_and_key_revocation_effective_on_retry(team):
    envelope = team.command()
    assert submit(team,envelope).status_code == 200
    access = read_json(team.folder/"access.json")
    access["members"].pop("sub-author")
    save(team.folder/"access.json",access)
    assert submit(team,envelope).status_code == 404


def test_ed25519_revocation_effective_without_restart(team):
    envelope = team.command()
    trust = read_json(team.folder/"trust.json")
    trust["keys"][envelope["key_id"]]["revoked"] = True
    save(team.folder/"trust.json",trust)
    assert submit(team,envelope).status_code == 422


def test_jwks_rotation_effective_without_restart(team):
    old_token = team.token()
    data = read_json(team.folder/"jwks.json")
    data["keys"][0]["kid"] = "rotated"
    save(team.folder/"jwks.json",data)
    with pytest.raises(TeamError):
        team.gateway.tokens.verify(old_token)


@pytest.mark.parametrize("changes", [{"created_at":"2000-01-01T00:00:00Z", "expires_at":"2000-01-01T00:05:00Z"},
    {"created_at":"2099-01-01T00:00:00Z", "expires_at":"2099-01-01T00:05:00Z"},
    {"expires_at":"2099-01-01T00:05:00Z"}])
def test_expiring_commands(team,changes):
    body = team.command()["payload"]
    body.update(changes)
    assert submit(team,sign(body,team.ctx.keys["author"])).json()["error"] == "COMMAND_EXPIRED"


@pytest.mark.parametrize("changes", [{"request_id":"not-uuid"},{"request_id":3},{"action":"run"},
    {"extra":"unexpected"},{"expected_checkpoint":{"seq":True,"hash":"f"*64}},
    {"parameters":{"name":"RC", "notes":"draft", "deliveries":[], "actor":"alice"}}])
def test_strict_commands(team, changes):
    body = team.command()["payload"]
    body.update(changes)
    assert submit(team,sign(body,team.ctx.keys["author"])).status_code == 422


def test_remote_approval_cannot_bypass_evidence(team):
    team.ctx.candidate()
    request = team.command("approval.submit",{"statement":team.decision()},"alice")
    assert submit(team,request,"alice").json()["error"] == "EVIDENCE_BLOCKED"
    assert not team.ctx.engine.state()["approvals"]


def test_remote_approval_rechecks_unregistered_drift(team):
    team.ctx.run(); team.ctx.candidate()
    request = team.command("approval.submit",{"statement":team.decision()},"alice")
    (team.ctx.root/"netlist.v").write_text("drift")
    assert submit(team,request,"alice").json()["error"] == "EVIDENCE_BLOCKED"


def test_remote_author_cannot_self_approve(team):
    team.ctx.run(); team.ctx.candidate()
    request = team.command("approval.submit",{"statement":team.decision("author")},"author")
    assert submit(team,request).status_code == 422


@pytest.mark.parametrize("changes", [{"project_id":"wrong"},{"candidate_sha256":"f"*64},
    {"decision":"reject"},{"role":"unrequired"},{"created_at":"2000-01-01T00:00:00Z"},
    {"created_at":"2099-01-01T00:00:00Z"},{"type":"opentapeout.waiver/v1"}, {"extra":True}])
def test_detached_decision_validation(team,changes):
    team.ctx.run(); team.ctx.candidate()
    request = team.command("approval.submit",{"statement":team.decision(**changes)},"alice")
    assert submit(team,request,"alice").status_code == 422


def test_inner_signature_must_use_same_key(team):
    team.ctx.run(); team.ctx.candidate()
    request = team.command("approval.submit",{"statement":team.decision("bob")},"alice")
    assert submit(team,request,"alice").status_code == 422


def revocation(team, principal="alice", **changes):
    approval = team.ctx.engine.state()["approvals"][0]
    statement = team.decision(principal, "approval-revocation", approval_sha256=digest(approval),
        candidate_sha256=approval["payload"]["candidate_sha256"], reason="Reviewer withdrew approval after review")
    if changes:
        statement = sign({**statement["payload"],**changes},team.ctx.keys[principal])
    return team.command("approval.revoke",{"statement":statement},principal)


def test_approval_revocation_preserves_history_and_blocks(team):
    team.ctx.ready()
    assert submit(team,revocation(team),"alice").status_code == 200
    assert not team.ctx.gate()["ready"]
    assert len(team.ctx.engine.state()["approvals"]) == 2
    assert len(team.ctx.engine.state()["revoked_approvals"]) == 1


def test_other_reviewer_cannot_revoke(team):
    team.ctx.ready()
    assert submit(team,revocation(team,"flexible"),"flexible").status_code == 403


def test_release_admin_can_revoke(team):
    trust = team.ctx.trust.data
    for entry in trust["keys"].values():
        if entry["principal"] == "release":
            entry["roles"].append("release-admin")
    save(team.folder/"trust.json",trust)
    team.ctx.ready()
    assert submit(team,revocation(team,"release"),"release").status_code == 200


@pytest.mark.parametrize("changes", [{"approval_sha256":"f"*64},{"candidate_sha256":"f"*64},{"reason":"tiny"}])
def test_invalid_revocation(team,changes):
    team.ctx.ready()
    assert submit(team,revocation(team,**changes),"alice").status_code == 422


def withdrawal(team, **changes):
    release = team.ctx.engine.state()["releases"]["RC1"]
    body = {"type":"opentapeout.release-withdrawal/v1", "project_id":team.project_id,
        "release_id":"RC1", "candidate_sha256":release["candidate_sha256"], "archive_sha256":release["archive_sha256"],
        "created_at":now(), "reason":"Release withdrawn after physical review", **changes}
    return team.command("release.withdraw", {"statement":sign(body,team.ctx.keys["release"])},"release")


def test_release_withdrawal_is_signed_and_irreversible(team,tmp_path):
    team.ctx.ready()
    seal(team.ctx.engine,"RC1",tmp_path/"release.zip",team.ctx.keys["release"],team.ctx.policy,team.ctx.trust)
    assert submit(team,withdrawal(team),"release").status_code == 200
    assert "RELEASE_WITHDRAWN" in {b["code"] for b in team.ctx.gate()["blockers"]}
    assert submit(team,withdrawal(team),"release").status_code == 422


@pytest.mark.parametrize("changes", [{"release_id":"unknown"},{"archive_sha256":"f"*64},
    {"candidate_sha256":"f"*64},{"reason":"short"},{"release_id":[]}, {"type":"wrong"}])
def test_invalid_withdrawal(team,tmp_path,changes):
    team.ctx.ready()
    seal(team.ctx.engine,"RC1",tmp_path/"release.zip",team.ctx.keys["release"],team.ctx.policy,team.ctx.trust)
    assert submit(team,withdrawal(team,**changes),"release").status_code == 422


def test_token_never_persisted_in_ledger_or_error_log(team,caplog):
    token = team.token()
    envelope = team.command()
    team.gateway.execute("chip",token,envelope)
    with team.ctx.engine.store.transaction() as tx:
        assert token not in str(tx.events)
        record = tx.events[-1]
        assert record["payload"]["identity"]["subject"] == "sub-author"
        assert record["payload"]["envelope"] == envelope
    assert token not in caplog.text


def test_audit_pagination_is_hash_bound_and_snapshot_pinned(team):
    client = team.client
    first = client.get("/v1/projects/chip/audit?limit=2",headers=auth(team)).json()
    end, cursor = first["until"], first["after"]
    team.ctx.engine.register("extra","other",metadata={"version":"1"})
    events = first["events"]
    while cursor["seq"] < end["seq"]:
        page = client.get("/v1/projects/chip/audit",params={"limit":2,"after":cursor["seq"],
            "after_hash":cursor["hash"],"until":end["seq"],"until_hash":end["hash"]},headers=auth(team)).json()
        assert page["events"][0]["previous"] == cursor["hash"]
        events.extend(page["events"]); cursor = page["after"]
    assert len(events) == end["seq"] and page["complete"]
    bad = client.get("/v1/projects/chip/audit?after=2&after_hash=bad",headers=auth(team))
    assert bad.status_code == 409


@pytest.mark.parametrize("query", ["limit=0","limit=101","after=-1","after=999", "until=0",
    "until=999", "until=1&until_hash=bad"])
def test_audit_cursor_errors(team,query):
    assert team.client.get("/v1/projects/chip/audit?"+query,headers=auth(team)).status_code in {409,422}


def test_candidate_list_and_details(team):
    submit(team,team.command())
    listing = team.client.get("/v1/projects/chip/candidates",headers=auth(team)).json()
    assert len(listing["candidates"]) == 1 and listing["next_offset"] is None
    details = team.client.get("/v1/projects/chip/candidates/RC1",headers=auth(team)).json()
    assert details["candidate_sha256"] == listing["candidates"][0]["candidate_sha256"]
    assert team.client.get("/v1/projects/chip/candidates/missing",headers=auth(team)).status_code == 404


def test_http_origin_url_token_and_body_controls(team):
    assert TestClient(create_team_app(team.path)).get("/health").status_code == 400
    assert team.client.get("/health",headers={"Origin":"https://evil.invalid"}).status_code == 403
    assert team.client.get("/v1/projects?access_token=not-accepted").status_code == 400
    headers = auth(team)
    assert team.client.post("/v1/projects/chip/commands",content="x",headers=headers).status_code == 415
    headers["Content-Type"] = "application/json"
    assert team.client.post("/v1/projects/chip/commands",content=b"x"*131073,headers=headers).status_code == 413
    assert team.client.post("/v1/projects/chip/commands",content=b'{"a":1,"a":2}',headers=headers).status_code == 422
    headers["Content-Encoding"] = "gzip"
    assert team.client.post("/v1/projects/chip/commands",content=b"{}",headers=headers).status_code == 415
    assert team.client.post("/v1/projects/chip/commands",json=team.command()).status_code == 401


def test_missing_governance_fails_closed(team):
    (team.folder/"access.json").unlink()
    assert team.client.get("/v1/projects/chip/context",headers=auth(team)).status_code == 503


@pytest.mark.parametrize("file",["policy","trust","access"])
def test_governance_inside_workspace_forbidden(team,file):
    target = team.ctx.root/(file+".json")
    save(target,read_json(team.folder/(file+".json")))
    config = copy.deepcopy(team.cfg)
    config["projects"]["chip"][file] = str(target)
    save(team.path,config)
    with pytest.raises(TapeoutError,match="outside ALL"):
        Gateway(team.path)


def test_project_workspaces_cannot_alias(team):
    cfg = copy.deepcopy(team.cfg)
    cfg["projects"]["alias"] = copy.deepcopy(cfg["projects"]["chip"])
    save(team.path,cfg)
    with pytest.raises(TapeoutError):
        Gateway(team.path)


def test_distinct_projects_are_invisible_without_membership(team,tmp_path):
    other = Engine.init(tmp_path/"other","Confidential other project")
    other_id = other.state()["project"]["id"]
    access = {"schema":"opentapeout.team-access/v1","project_id":other_id,"members":{}}
    write_json(team.folder/"other-access.json",access)
    cfg = copy.deepcopy(team.cfg)
    cfg["projects"]["other"] = {**cfg["projects"]["chip"], "project_id":other_id,
        "workspace":str(other.root),"access":str(team.folder/"other-access.json")}
    save(team.path,cfg)
    client = TestClient(create_team_app(team.path),base_url="https://testserver")
    assert client.get("/v1/projects",headers=auth(team)).json()["projects"] == [{"slug":"chip","project_id":team.project_id}]
    assert client.get("/v1/projects/other/context",headers=auth(team)).status_code == 404


def _process_execute(args):
    path, token, envelope = args
    try:
        return Gateway(path).execute("chip", token, envelope)
    except TeamError as exc:
        return exc.code


def test_competing_processes_do_not_lose_updates(team):
    import multiprocessing
    from concurrent.futures import ProcessPoolExecutor
    commands = [team.command(params={"name":f"P{i}", "notes":"process race test", "deliveries":{}}) for i in range(4)]
    token = team.token()
    with ProcessPoolExecutor(max_workers=4, mp_context=multiprocessing.get_context("spawn")) as pool:
        results = list(pool.map(_process_execute,[(team.path,token,e) for e in commands]))
    assert sum(isinstance(r,dict) for r in results) == 1
    assert results.count("STALE_CHECKPOINT") == 3


@pytest.mark.parametrize("variant", ["duplicate_kid", "private_key", "wrong_kty", "wrong_alg", "wrong_use",
    "bad_key_ops", "empty", "bad_rsa", "symlink"])
def test_bad_jwks_configuration_fails_closed(team,variant):
    path = team.folder/"jwks.json"
    data = read_json(path)
    if variant == "duplicate_kid": data["keys"].append(copy.deepcopy(data["keys"][0]))
    elif variant == "private_key": data["keys"][0]["d"] = "private key material is forbidden"
    elif variant == "wrong_kty": data["keys"][0]["kty"] = "oct"
    elif variant == "wrong_alg": data["keys"][0]["alg"] = "HS256"
    elif variant == "wrong_use": data["keys"][0]["use"] = "enc"
    elif variant == "bad_key_ops": data["keys"][0]["key_ops"] = ["sign"]
    elif variant == "empty": data["keys"] = []
    elif variant == "bad_rsa": data["keys"][0]["n"] = "bad"
    else:
        target = team.folder/"other-jwks.json"
        path.rename(target); path.symlink_to(target)
        with pytest.raises(TapeoutError): Gateway(team.path)
        return
    save(path,data)
    with pytest.raises(TapeoutError): Gateway(team.path)


@pytest.mark.parametrize("field,value", [("issuer","http://issuer.test"),("audience",""),
    ("max_lifetime_seconds",True),("max_lifetime_seconds",3601),("client_ids",[]),
    ("jwks_file","relative.json")])
def test_bad_identity_config(team,field,value):
    cfg = copy.deepcopy(team.cfg);cfg["identity"][field]=value;save(team.path,cfg)
    with pytest.raises(TapeoutError): Gateway(team.path)


@pytest.mark.parametrize("variant", ["unknown_permission", "duplicate_permission", "same_principal",
    "wrong_project", "symlink", "unknown_member_field"])
def test_invalid_access_configuration(team,variant):
    path = team.folder/"access.json";data=read_json(path)
    if variant == "unknown_permission": data["members"]["sub-reader"]["permissions"].append("admin")
    elif variant == "duplicate_permission": data["members"]["sub-reader"]["permissions"].append("read")
    elif variant == "same_principal": data["members"]["sub-reader"]["principal"]="author"
    elif variant == "wrong_project": data["project_id"]="another"
    elif variant == "unknown_member_field": data["members"]["sub-reader"]["is_admin"]=True
    else:
        target=team.folder/"access-actual.json";path.rename(target);path.symlink_to(target)
        with pytest.raises(TapeoutError): Gateway(team.path)
        return
    save(path,data)
    with pytest.raises(TapeoutError): Gateway(team.path)


def test_http_loopback_development_never_trusts_forwarded_headers(team):
    client = TestClient(create_team_app(team.path,allow_insecure_loopback=True),client=("127.0.0.1",1234))
    assert client.get("/health").status_code == 200
    remote = TestClient(create_team_app(team.path,allow_insecure_loopback=True),client=("192.0.2.3",1234))
    assert remote.get("/health",headers={"X-Forwarded-For":"127.0.0.1","X-Forwarded-Proto":"https"}).status_code == 400
    nonip = TestClient(create_team_app(team.path,allow_insecure_loopback=True))
    assert nonip.get("/health").status_code == 400


def test_approval_already_present_cannot_be_added_as_new_request(team):
    team.ctx.run();team.ctx.candidate()
    statement=team.decision()
    assert submit(team,team.command("approval.submit",{"statement":statement},"alice"),"alice").status_code==200
    assert submit(team,team.command("approval.submit",{"statement":statement},"alice"),"alice").status_code==422


def test_revocation_already_present_is_not_new_action(team):
    team.ctx.ready()
    assert submit(team,revocation(team),"alice").status_code==200
    assert submit(team,revocation(team),"alice").status_code==422


def test_pagination_multiple_candidates(team):
    for i in range(3):
        assert submit(team,team.command(params={"name":f"R{i}","notes":"reviewed test", "deliveries":{}})).status_code==200
    page=team.client.get("/v1/projects/chip/candidates?limit=2",headers=auth(team)).json()
    assert page["next_offset"]==2
    last=team.client.get("/v1/projects/chip/candidates?offset=2&limit=2",headers=auth(team)).json()
    assert len(last["candidates"])==1 and last["next_offset"] is None


def test_empty_final_audit_page(team):
    with team.ctx.engine.store.transaction() as tx: end=tx.checkpoint
    response=team.client.get("/v1/projects/chip/audit",params={"after":end["seq"],"after_hash":end["hash"]},headers=auth(team)).json()
    assert response["complete"] and response["events"]==[]


def test_governance_revoked_during_validation_rolls_back(team,monkeypatch):
    before=team.ctx.engine.store.verify_checkpoint()
    original=Gateway._apply
    def apply(*args):
        result=original(*args)
        access=read_json(team.folder/"access.json")
        access["members"].pop("sub-author")
        save(team.folder/"access.json",access)
        return result
    monkeypatch.setattr(Gateway,"_apply",staticmethod(apply))
    response=submit(team,team.command())
    assert response.status_code==409 and response.json()["error"]=="GOVERNANCE_CHANGED"
    assert team.ctx.engine.store.verify_checkpoint()==before


def test_token_expiring_during_validation_rolls_back(team,monkeypatch):
    before=team.ctx.engine.store.verify_checkpoint()
    envelope=team.command();token=team.token()
    original=team.gateway.tokens.verify;calls=[0]
    def verify(value):
        calls[0]+=1
        if calls[0]==3: raise TeamError("AUTHENTICATION","Token expired",401)
        return original(value)
    monkeypatch.setattr(team.gateway.tokens,"verify",verify)
    with pytest.raises(TeamError):team.gateway.execute("chip",token,envelope)
    assert team.ctx.engine.store.verify_checkpoint()==before


def test_lost_response_recovered_from_receipt_after_command_window(team):
    envelope=team.command();reply=submit(team,envelope).json()
    # Receipt retrieval is a historical read, not replay or renewed authorization.
    response=team.client.get("/v1/projects/chip/commands/"+reply["request_id"],headers=auth(team))
    assert response.status_code==200 and response.json()["historical"]
    assert response.json()["checkpoint"]==reply["checkpoint"]
    assert team.client.get("/v1/projects/chip/commands/"+str(uuid.uuid4()),headers=auth(team)).status_code==404
    assert team.client.get("/v1/projects/chip/commands/"+reply["request_id"]).status_code==401


def test_database_failure_is_safe_retry_response(team,monkeypatch):
    import sqlite3
    from opentapeout.store import Store
    def locked(self):raise sqlite3.OperationalError("do not disclose private filesystem path")
    monkeypatch.setattr(Store,"connect",locked)
    response=team.client.get("/v1/projects/chip/context",headers=auth(team))
    assert response.status_code==503 and response.headers["retry-after"]=="1"
    assert "private filesystem" not in response.text


def test_process_crash_before_commit_leaves_no_partial_candidate(team):
    import subprocess,sys
    envelope=team.command();token=team.token()
    write_json(team.folder/"crash-command.json",envelope)
    # Real child-process death after candidate insertion, before command receipt/commit.
    code='''import os,sys
from pathlib import Path
from opentapeout.team import Gateway
from opentapeout.util import read_json
old=Gateway._apply
def die(*args):
    old(*args)
    os._exit(23)
Gateway._apply=staticmethod(die)
Gateway(Path(sys.argv[1])).execute("chip",os.environ["OT_TEST_TOKEN"],read_json(sys.argv[2]))
'''
    import os
    before=team.ctx.engine.store.verify_checkpoint()
    result=subprocess.run([sys.executable,"-c",code,str(team.path),str(team.folder/"crash-command.json")],
        env={**os.environ,"OT_TEST_TOKEN":token},capture_output=True,timeout=15)
    assert result.returncode==23,result.stderr.decode()
    assert team.ctx.engine.store.verify_checkpoint()==before
    assert not team.ctx.engine.state()["candidates"]
    assert team.gateway.execute("chip",token,envelope)["result"]["name"]=="RC1"
