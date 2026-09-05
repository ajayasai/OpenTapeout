import json

import pytest
from fastapi.testclient import TestClient

from opentapeout.cli import main,markdown_gate
from opentapeout.demo import build_demo
from opentapeout.engine import Engine
from opentapeout.signing import Trust
from opentapeout.web import create_app
from opentapeout.util import read_json


def test_cli_gate_exit_codes_and_json(ctx,capsys):
    ctx.run();ctx.candidate()
    assert main(["--root",str(ctx.root),"gate","RC1"])==2
    assert json.loads(capsys.readouterr().out)["ready"] is False
    ctx.approve()
    assert main(["--root",str(ctx.root),"gate","RC1"])==0
    assert json.loads(capsys.readouterr().out)["ready"] is True


def test_cli_unknown_resource_returns_structured_error(ctx,capsys):
    assert main(["--root",str(ctx.root),"impact","missing"])==1
    assert "Unknown resource" in json.loads(capsys.readouterr().err)["error"]


def test_cli_status_requires_no_optional_framework_startup(ctx,capsys):
    ctx.ready()
    assert main(["--root",str(ctx.root),"status"])==0
    assert json.loads(capsys.readouterr().out)["mode"]=="read-only"


def test_markdown_gate_escapes_html(ctx):
    ctx.ready();report=ctx.gate();report["blockers"].append({"code":"NOTE","message":"<script>alert(1)</script>"})
    text=markdown_gate(report)
    assert "<script>" not in text and "&lt;script&gt;" in text


@pytest.mark.parametrize("endpoint",["/api/summary","/api/audit","/api/gate/RC1","/api/impact/rtl"])
def test_read_api_authentication(ctx,endpoint):
    ctx.ready()
    client=TestClient(create_app(ctx.root,token="x"*40))
    assert client.get(endpoint).status_code==401
    assert client.get(endpoint,headers={"Authorization":"Bearer wrong"}).status_code==401
    response=client.get(endpoint,headers={"Authorization":"Bearer "+"x"*40})
    assert response.status_code==200
    assert response.headers["Cache-Control"]=="no-store"


def test_dashboard_security_headers_and_read_only_api(ctx):
    ctx.ready();client=TestClient(create_app(ctx.root))
    response=client.get("/")
    assert response.status_code==200
    assert "script-src 'self'" in response.headers["Content-Security-Policy"]
    assert response.headers["X-Frame-Options"]=="DENY"
    assert client.post("/api/summary",json={}).status_code==405
    assert client.get("/static/ledger.sqlite3").status_code==404
    assert client.get("/static/app.js").status_code==200
    assert client.get("/api/summary",headers={"host":"evil.example"}).status_code==400


def test_full_synthetic_demo_has_six_checks_and_real_signatures(tmp_path):
    result=build_demo(tmp_path/"demo")
    assert result["synthetic"] and result["baseline_ready"] and result["current_gate"]["ready"]
    assert len(result["current_gate"]["checks"])==6
    assert result["current_gate"]["approval_assignment"]=={
        "physical":"physical-reviewer","verification":"verification-reviewer"}


def test_synthetic_demo_after_eco_is_blocked(tmp_path):
    result=build_demo(tmp_path/"stale",stale=True)
    assert result["baseline_ready"] and not result["current_gate"]["ready"]
    assert {"RESULT_STALE","DERIVATION_STALE","CANDIDATE_CHANGED"} <= {
        b["code"] for b in result["current_gate"]["blockers"]}


def test_git_capture_detects_uncommitted_edits(tmp_path):
    build_demo(tmp_path/"demo")
    root=tmp_path/"demo";engine=Engine(root)
    (root/"design"/"top.v").write_text("uncommitted change")
    result=engine.gate("RC-001",read_json(root/"policy.json"),Trust.from_file(root/"trust.json"))
    assert any(b["code"]=="WORKSPACE_DRIFT" and b["scope"]=="source-commit" for b in result["blockers"])
