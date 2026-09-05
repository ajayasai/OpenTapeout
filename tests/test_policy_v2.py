import copy
import sys
from pathlib import Path

import pytest

from opentapeout.policy import evaluate, validate_policy
from opentapeout.util import TapeoutError, file_digest, now


def upgrade(w):
    p = copy.deepcopy(w.policy)
    p["schema"] = "opentapeout.policy/v2"
    state = w.engine.state()
    c = p["required_checks"][0]
    c.update(input_pins={k: state["resources"][k]["sha256"] for k in ["layout", "netlist", "pdk", "tool", "nominal"]},
             allowed_tools=["tool"], report_formats=["json"], require_pinned_executable=False)
    return p


def test_v2_valid_existing_report(ctx):
    w=ctx; w.run(); w.policy.update(upgrade(w)); w.candidate(); w.approve()
    assert w.gate()["ready"]


@pytest.mark.parametrize("change,code", [
    (lambda c: c["input_pins"].update({"other-lib":"a"*64}), "EXACT_INPUT_MISSING"),
    (lambda c: c["input_pins"].update({"layout":"b"*64}), "INPUT_PIN_MISMATCH"),
    (lambda c: (c.update(allowed_tools=["another-tool"]), c["input_pins"].update({"another-tool":"a"*64})), "TOOL_NOT_ALLOWED"),
    (lambda c: c.update(report_formats=["junit"]), "REPORT_FORMAT_NOT_ALLOWED"),
    (lambda c: c.update(require_pinned_executable=True), "EXECUTABLE_IDENTITY"),
])
def test_v2_rejects_wrong_evidence(ctx,change,code):
    w=ctx; w.run(); w.policy.update(upgrade(w)); change(w.policy["required_checks"][0]); w.candidate()
    assert code in {b["code"] for b in w.gate()["blockers"]}


@pytest.mark.parametrize("changes", [{"input_pins":{}}, {"input_pins":{"rtl":"bad"}},
    {"allowed_tools":[]}, {"allowed_tools":["tool","tool"]}, {"report_formats":["nonsense"]},
    {"report_formats":[]}, {"require_pinned_executable":1}, {"extra":1}])
def test_v2_bad_policy(ctx,changes):
    p=upgrade(ctx); p["required_checks"][0].update(changes)
    with pytest.raises(TapeoutError): validate_policy(p)


def test_v1_does_not_silently_ignore_v2_fields(ctx):
    p=upgrade(ctx); p["schema"]="opentapeout.policy/v1"
    with pytest.raises(TapeoutError): validate_policy(p)


def test_managed_executable_pin(ctx):
    w=ctx
    meta=w.engine.state()["resources"]["tool"]["metadata"].copy()
    meta["executable_sha256"]=file_digest(Path(sys.executable).resolve())[0]
    w.engine.register("tool","tool",metadata=meta)
    r=w.engine.run("LVS",["netlist","layout","pdk"],"tool","nominal","pinned.json")
    assert r["exit_code"]==0 and r["execution_identity"]["unchanged"]
    w.policy.update(upgrade(w));w.policy["required_checks"][0]["require_pinned_executable"]=True
    w.candidate();w.approve();assert w.gate()["ready"]
    candidate=w.engine.state()["candidates"]["RC1"]
    # The same controls execute during independent offline gate evaluation.
    assert evaluate(candidate,w.policy,w.trust,w.engine.state()["approvals"],at=now())["ready"]


def test_mismatched_executable_never_runs(ctx):
    w=ctx; meta=w.engine.state()["resources"]["tool"]["metadata"].copy()
    meta["executable_sha256"]="a"*64
    w.engine.register("tool","tool",metadata=meta)
    r=w.engine.run("LVS",["netlist"],"tool","nominal","never-created.json")
    assert r["exit_code"]==127 and not (w.root/"never-created.json").exists()
    assert r["result"]["status"]=="unknown"


def test_stdout_report_is_captured_not_a_stale_path(ctx):
    w=ctx
    script="import json,os;print(json.dumps({'schema':'opentapeout.result/v1','run_id':os.environ['OPENTAPEOUT_RUN_ID'],'status':'pass','complete':True,'metrics':{},'violations':[]}))"
    w.engine.register("stdout","tool",metadata={"name":"fixture","version":"1","argv":[sys.executable,"-c",script]})
    r=w.engine.run("LVS",["netlist"],"stdout","nominal","unused.json",report_source="stdout")
    assert r["result"]["status"]=="pass"
    assert r["report_sha256"]==r["stdout_sha256"]
    assert not (w.root/"unused.json").exists()


def test_physical_format_cannot_satisfy_wrong_check(ctx):
    w=ctx
    r=w.engine.begin("LVS",["netlist"],"tool","nominal")
    (w.root/"wrong.txt").write_text("arbitrary")
    result=w.engine.finish(r,"wrong.txt",exit_code=0,format_name="opensta")
    assert result["result"]["status"]=="unknown" and "STA" in result["parser_error"]


def test_bad_pin_and_report_source(ctx):
    w=ctx
    m=w.engine.state()["resources"]["tool"]["metadata"].copy();m["executable_sha256"]="invalid"
    with pytest.raises(TapeoutError):w.engine.register("bad","tool",metadata=m)
    with pytest.raises(TapeoutError):w.engine.run("LVS",["netlist"],"tool","nominal","x",report_source="arbitrary")


def pinned_run(w):
    meta=w.engine.state()["resources"]["tool"]["metadata"].copy()
    meta["executable_sha256"]=file_digest(Path(sys.executable).resolve())[0]
    w.engine.register("tool","tool",metadata=meta)
    return w.engine.run("LVS",["layout","netlist","pdk"],"tool","nominal","pinning.json")


def test_pin_policy_requires_review_and_does_not_mutate(ctx):
    from opentapeout.pinning import pin_policy
    pinned_run(ctx)
    before=ctx.engine.store.verify_checkpoint()
    policy=pin_policy(ctx.engine,ctx.policy)
    assert policy["schema"]=="opentapeout.policy/v2"
    assert ctx.policy["schema"]=="opentapeout.policy/v1"
    assert {"tool","nominal","layout","netlist","pdk"} <= policy["required_checks"][0]["input_pins"].keys()
    assert ctx.engine.store.verify_checkpoint()==before


def test_pin_policy_cli(ctx, capsys):
    from opentapeout.cli import main
    pinned_run(ctx)
    output=ctx.root/"policy-locked.json"
    assert main(["--root",str(ctx.root),"pin-policy","--output",str(output)])==0
    assert output.exists()
    assert '"review_required": true' in capsys.readouterr().out


@pytest.mark.parametrize("mode",["missing","unmanaged","not-pinned","stale","corrupt","incomplete"])
def test_pin_policy_rejects_invalid_evidence(ctx,mode):
    from opentapeout.pinning import pin_policy
    if mode=="unmanaged": ctx.run()
    elif mode=="not-pinned": ctx.engine.run("LVS",["layout","netlist","pdk"],"tool","nominal","n.json")
    elif mode not in {"missing"}:
        run=pinned_run(ctx)
        if mode=="stale":
            (ctx.root/"netlist.v").write_text("changed")
        elif mode=="corrupt":
            p=ctx.engine.store.object_path(run["report_sha256"]);p.chmod(0o600);p.write_bytes(b"bad")
        else: ctx.engine.begin("LVS",["layout","netlist","pdk"],"tool","nominal")
    with pytest.raises(TapeoutError): pin_policy(ctx.engine,ctx.policy)


def test_physical_stderr_cannot_hide_an_error(ctx):
    # A framed pass on stdout cannot conceal a native error on stderr.
    code="import os,sys; r=os.environ['OPENTAPEOUT_RUN_ID']; print('OT_BEGIN klayout-lvs '+r); print('OT_DATA {\"matched\":true,\"layout_devices\":1,\"reference_devices\":1,\"layout_nets\":2,\"reference_nets\":2,\"circuits_compared\":1}'); print('OT_END klayout-lvs '+r); print('ignored failure',file=sys.stderr)"
    ctx.engine.register("native","tool",metadata={"name":"test","version":"1","argv":[sys.executable,"-c",code]})
    r=ctx.engine.run("LVS",["layout","netlist"],"native","nominal","native.txt",report_source="stdout",format_name="klayout-lvs")
    assert r["exit_code"]==0 and r["result"]["status"]=="unknown" and "stderr" in r["parser_error"]


def test_named_rule_coverage_cannot_be_waived_away(ctx):
    from opentapeout.pinning import pin_policy
    pinned_run(ctx)
    ctx.policy.update(pin_policy(ctx.engine,ctx.policy))
    ctx.policy["required_checks"][0]["metrics"]={"rule:REQUIRED:checked":{"min":1}}
    ctx.candidate()
    assert "METRIC_MISSING" in {b["code"] for b in ctx.gate()["blockers"]}


@pytest.mark.parametrize("field,value",[("allowed_tools",[{}]),("report_formats",[[]]),
    ("input_pins",{"layout":"a"*64})])
def test_malformed_policy_types_raise_validation_errors(ctx,field,value):
    p=upgrade(ctx);p["required_checks"][0][field]=value
    with pytest.raises(TapeoutError):validate_policy(p)
