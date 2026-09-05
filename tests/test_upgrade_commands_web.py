import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from fastapi.testclient import TestClient

from opentapeout.cli import main
from opentapeout.util import digest, write_json
from opentapeout.web import create_app


def save_key(ctx, principal):
    path = ctx.root/(principal+".pem")
    path.write_bytes(ctx.keys[principal].private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                   serialization.NoEncryption()))
    return str(path)


def test_cli_plan_compare_and_revocation(ctx, capsys):
    ctx.ready()
    prefix = ["--root", str(ctx.root)]
    assert main(prefix+["plan", "RC1", "--changed", "rtl"]) == 0
    assert json.loads(capsys.readouterr().out)["summary"]["resource_tasks"] == 3
    assert main(prefix+["compare", "RC1", "RC1"]) == 0
    assert json.loads(capsys.readouterr().out)["resources"] == []
    h = digest(ctx.engine.state()["approvals"][0])
    assert main(prefix+["revoke-approval", h, "--reason", "Repeat the physical review", "--key", save_key(ctx,"alice")]) == 0
    capsys.readouterr()
    assert main(prefix+["gate", "RC1"]) == 2


def test_cli_full_delivery_and_status_workflow(ctx, capsys):
    for e in ctx.trust.keys.values():
        if e["principal"] == "flexible": e["roles"].append("delivery-receiver")
    write_json(ctx.root/"trust.json", ctx.trust.data, overwrite=True)
    ctx.ready()
    release_key, receiver_key = save_key(ctx,"release"), save_key(ctx,"flexible")
    prefix = ["--root", str(ctx.root)]
    private, public = str(ctx.root/"private.zip"), str(ctx.root/"delivery.zip")
    disclosure, status, receipt = (str(ctx.root/n) for n in ("disclosure.json","status.json","receipt.json"))
    assert main(prefix+["seal","RC1",private,"--key",release_key]) == 0
    assert main(prefix+["disclosure","RC1","--recipient","flexible","--output",disclosure]) == 0
    assert main(prefix+["deliver","RC1","D1",public,"--disclosure",disclosure,"--key",release_key]) == 0
    # These commands work with a deliberately nonexistent workspace directory.
    offline = ["--root", str(ctx.root/"does-not-exist"), "--trust", str(ctx.root/"trust.json")]
    assert main(offline+["verify-delivery",public,"--disclosure",disclosure]) == 0
    assert main(offline+["sign-receipt",public,"--disclosure",disclosure,"--key",receiver_key,
                         "--reference","TEST-ACK","--output",receipt]) == 0
    assert main(prefix+["record-receipt",receipt]) == 0
    assert main(prefix+["release-status","--key",release_key,"--output",status]) == 0
    assert main(prefix+["verify",private,"--status",status]) == 0
    assert main(prefix+["withdraw","RC1","--reason","Post-release withdrawal request","--key",release_key]) == 0
    assert main(prefix+["gate","RC1"]) == 2
    assert Path(public).exists()


def test_new_api_routes_and_authentication(ctx):
    ctx.ready()
    client = TestClient(create_app(ctx.root, token="test-token"))
    for route in ("/api/plan", "/api/compare/RC1/RC1", "/api/summary"):
        assert client.get(route).status_code == 401
    headers = {"Authorization":"Bearer test-token"}
    result = client.get("/api/plan?name=RC1&changed=rtl", headers=headers)
    assert result.status_code == 200 and result.json()["summary"]["resource_tasks"] == 3
    assert client.get("/api/plan?changed=unknown", headers=headers).status_code == 422
    assert client.get("/api/compare/RC1/RC1", headers=headers).json()["resources"] == []
    result = client.get("/api/summary", headers=headers).json()
    assert len(result["approval_states"]) == 2 and result["delivery_capsules"] == []
    assert client.get("/static/control.js").status_code == 200
    assert client.post("/api/plan", headers=headers).status_code == 405


def test_indexed_selector_matches_old_algorithm_for_ties_and_order(ctx):
    from opentapeout.engine import scope_view
    import importlib.util
    spec = importlib.util.spec_from_file_location("benchmark_selection", Path(__file__).resolve().parents[1]/"scripts/benchmark_selection.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    former_selection = module.former_selection
    from types import SimpleNamespace
    import random
    for seed in range(20):
        rng = random.Random(seed)
        rows = [{"id": str(i), "sequence": rng.randrange(10), "kind": "LVS", "corner": f"c{i%7}"} for i in range(100)]
        rng.shuffle(rows)
        state = {"runs": {r["id"]:r for r in rows}, "resources": {}, "waivers": {}, "revoked_waivers": set()}
        policy = {"required_checks":[{"kind":"LVS","corner":f"c{i}"} for i in range(9)]}
        candidate, trust = {"deliveries": []}, SimpleNamespace(sha256="0"*64)
        assert scope_view(state,candidate,policy,trust) == former_selection(state,candidate,policy,trust)
