from __future__ import annotations

import copy
import json
import sys
from concurrent.futures import ThreadPoolExecutor

import pytest

from opentapeout.engine import Engine
from opentapeout.policy import evaluate
from opentapeout.signing import Trust
from opentapeout.util import TapeoutError, digest, now


def codes(report):
    return {b["code"] for b in report["blockers"]}


def test_full_review_lifecycle(ctx):
    ctx.run(); ctx.candidate()
    assert "APPROVALS_MISSING" in codes(ctx.gate())
    ctx.approve()
    assert ctx.gate()["ready"]
    assert ctx.gate()["approval_assignment"] == {"physical": "alice", "verification": "bob"}


def test_empty_project_fails_closed(ctx):
    ctx.candidate()
    assert {"CHECK_MISSING", "APPROVALS_MISSING"} <= codes(ctx.gate())


def test_no_overwrite_existing_workspace(ctx):
    with pytest.raises(TapeoutError, match="already initialized"):
        Engine.init(ctx.root, "replacement")
    assert ctx.engine.state()["project"]["name"] == "TEST FIXTURE — NOT SIGNOFF"


def test_on_disk_edit_detected_without_registration(ctx):
    ctx.ready()
    (ctx.root / "netlist.v").write_text("unregistered ECO")
    assert "WORKSPACE_DRIFT" in codes(ctx.gate())


def test_registered_netlist_invalidates_lvs_and_layout(ctx):
    ctx.ready()
    (ctx.root / "netlist.v").write_text("new netlist")
    ctx.engine.register("netlist", "netlist", path="netlist.v", depends_on=["rtl", "pdk"])
    assert {"CANDIDATE_CHANGED", "RESULT_STALE", "DERIVATION_STALE"} <= codes(ctx.gate())
    with pytest.raises(TapeoutError, match="Obsolete derived"):
        ctx.run()


def test_transitive_rtl_change_blocks_derived_netlist(ctx):
    ctx.ready()
    (ctx.root / "rtl.v").write_text("new rtl")
    ctx.engine.register("rtl", "rtl", path="rtl.v")
    report = ctx.gate()
    assert "DERIVATION_STALE" in codes(report)
    assert any("netlist" in b["message"] and "rtl" in b["message"] for b in report["blockers"])


@pytest.mark.parametrize("kind", ["tool", "corner", "pdk", "constraints"])
def test_content_or_definition_change_invalidates_exact_candidate(ctx, kind):
    ctx.ready()
    if kind == "tool":
        spec = copy.deepcopy(ctx.engine.state()["resources"]["tool"]["metadata"])
        spec["version"] = "2"
        ctx.engine.register("tool", "tool", metadata=spec)
    elif kind == "corner":
        ctx.engine.register("nominal", "corner", metadata={"voltage_v": 0.8, "temperature_c": 125})
    elif kind == "pdk":
        (ctx.root / "pdk.lock").write_text("pdk2")
        ctx.engine.register("pdk", "pdk", path="pdk.lock", metadata={"version": "2"})
    else:
        ctx.engine.register("new-constraint", "constraints", metadata={"clock_ns": 5})
    assert "CANDIDATE_CHANGED" in codes(ctx.gate())
    if kind != "constraints":
        assert "RESULT_STALE" in codes(ctx.gate())


def test_identical_reregistration_preserves_evidence_content(ctx):
    ctx.ready()
    ctx.engine.register("rtl", "rtl", path="rtl.v")
    assert ctx.gate()["ready"]


def test_latest_failure_never_falls_back_to_earlier_pass(ctx):
    ctx.ready(); ctx.run(status="fail"); ctx.candidate("RC2")
    assert "RESULT_FAILED" in codes(ctx.gate("RC2"))


def test_latest_started_incomplete_run_blocks_previous_pass(ctx):
    ctx.ready()
    ctx.engine.begin("LVS", ["netlist", "layout", "pdk"], "tool", "nominal")
    ctx.candidate("RC2")
    assert "RUN_INCOMPLETE" in codes(ctx.gate("RC2"))


def test_older_run_finishing_last_does_not_override_newer_run(ctx):
    old = ctx.engine.begin("LVS", ["netlist", "layout"], "tool", "nominal")
    new = ctx.run(status="fail")
    data = {"schema":"opentapeout.result/v1","run_id":old,"status":"pass","complete":True,"metrics":{},"violations":[]}
    (ctx.root / "old.json").write_text(json.dumps(data))
    ctx.engine.finish(old, "old.json", exit_code=0)
    ctx.candidate()
    assert ctx.gate()["checks"][0]["run_id"] == new["id"]
    assert "RESULT_FAILED" in codes(ctx.gate())


@pytest.mark.parametrize("exit_code", [-9, 1, 2, 124, 127])
def test_nonzero_exit_cannot_be_hidden_by_pass_report(ctx, exit_code):
    ctx.run(exit_code=exit_code);ctx.candidate()
    assert "TOOL_FAILED" in codes(ctx.gate())


def test_run_id_mismatch_retained_but_cannot_pass(ctx):
    rid = ctx.engine.begin("LVS", ["netlist", "layout"], "tool", "nominal")
    (ctx.root / "wrong.json").write_text(json.dumps({"schema":"opentapeout.result/v1","run_id":"another-run",
        "status":"pass","complete":True,"metrics":{},"violations":[]}))
    result=ctx.engine.finish(rid,"wrong.json",exit_code=0)
    assert result["parser_error"] and result["result"]["status"]=="unknown"
    assert result["report_sha256"]
    ctx.candidate();assert "RESULT_UNKNOWN" in codes(ctx.gate())


def test_completion_is_immutable(ctx):
    result=ctx.run()
    with pytest.raises(TapeoutError,match="already completed"):
        ctx.engine.finish(result["id"],"report-0.json",exit_code=0)


def test_drift_seen_at_finish_persists_after_restore(ctx):
    original=(ctx.root/"rtl.v").read_bytes()
    rid=ctx.engine.begin("LVS",["netlist","layout"],"tool","nominal")
    (ctx.root/"rtl.v").write_text("changed during run")
    (ctx.root/"result.json").write_text(json.dumps({"schema":"opentapeout.result/v1","run_id":rid,
        "status":"pass","complete":True,"metrics":{},"violations":[]}))
    ctx.engine.finish(rid,"result.json",exit_code=0)
    (ctx.root/"rtl.v").write_bytes(original)
    ctx.candidate()
    assert "INPUT_CHANGED_DURING_RUN" in codes(ctx.gate())


def test_input_kind_missing(ctx):
    ctx.run();ctx.policy["required_checks"][0]["required_resource_kinds"].append("constraints")
    ctx.candidate();assert "INPUT_KIND_MISSING" in codes(ctx.gate())


@pytest.mark.parametrize("metrics", [{},{"wns_ns":-0.1},{"wns_ns":1.0}])
def test_metric_thresholds(ctx,metrics):
    ctx.run(metrics=metrics)
    ctx.policy["required_checks"][0]["metrics"]={"wns_ns":{"min":0}}
    ctx.candidate()
    check=ctx.engine.gate("RC1",ctx.policy,ctx.trust,include_approvals=False)
    assert check["ready"] == (metrics.get("wns_ns",-1)>=0)


def test_managed_execution_and_default_import_policy(ctx):
    ctx.policy["require_managed_runs"]=True
    ctx.run();ctx.candidate()
    assert "UNMANAGED_RUN" in codes(ctx.gate())
    run=ctx.engine.run("LVS",["netlist","layout","pdk"],"tool","nominal","managed.json")
    assert run["capture_mode"]=="managed" and run["exit_code"]==0
    ctx.candidate("RC2");ctx.approve("RC2");assert ctx.gate("RC2")["ready"]


def test_runner_rejects_preexisting_report(ctx):
    (ctx.root/"existing.json").write_text("stale")
    with pytest.raises(TapeoutError,match="already exists"):
        ctx.engine.run("LVS",["netlist","layout"],"tool","nominal","existing.json")


def test_managed_timeout_is_nonwaivable(ctx):
    ctx.engine.register("timeout-tool","tool",metadata={"name":"sleep-fixture","version":"1",
        "argv":[sys.executable,"-c","import time;time.sleep(10)"]})
    result=ctx.engine.run("LVS",["netlist","layout"],"timeout-tool","nominal","timeout.json",timeout=0.1)
    assert result["exit_code"]==124 and result["result"]["status"]=="unknown"


def test_missing_executable_is_recorded_failure(ctx):
    ctx.engine.register("absent-tool","tool",metadata={"name":"absent","version":"1","argv":["/nonexistent/opentapeout-test"]})
    result=ctx.engine.run("LVS",["netlist","layout"],"absent-tool","nominal","missing.json")
    assert result["exit_code"]==127 and result["stderr_sha256"]


def test_candidate_names_are_immutable(ctx):
    ctx.run();ctx.candidate()
    with pytest.raises(TapeoutError,match="already exists"):
        ctx.candidate()


def test_different_corner_cannot_satisfy_requirement(ctx):
    ctx.run();ctx.policy["required_checks"][0]["corner"]="ss"
    ctx.candidate();assert "CHECK_MISSING" in codes(ctx.gate())


def test_age_boundary_and_future_result(ctx):
    ctx.ready();state=ctx.engine.state();candidate=state["candidates"]["RC1"]
    expired=evaluate(candidate,ctx.policy,ctx.trust,state["approvals"],at="2099-01-01T00:00:00Z")
    future=evaluate(candidate,ctx.policy,ctx.trust,[],at="2000-01-01T00:00:00Z")
    assert "RESULT_AGE" in codes(expired) and "RESULT_AGE" in codes(future)


def test_impact_paths_and_candidate_diff(ctx):
    ctx.run();ctx.candidate();ctx.candidate("RC2",notes="Updated release notes only")
    impact=ctx.engine.impact("rtl")
    assert any(x["path"]==["rtl","netlist","layout"] for x in impact["downstream"])
    difference=ctx.engine.diff("RC1","RC2")
    assert not difference["resources"] and "notes" in difference["changed_sections"]


def test_policy_change_requires_new_signatures(ctx):
    ctx.ready();ctx.policy["required_checks"][0]["max_age_hours"]=10
    assert {"POLICY_CHANGED","CANDIDATE_CHANGED"} <= codes(ctx.gate())


def test_revoked_key_changes_trust_and_invalidates_approval(ctx):
    ctx.ready();data=copy.deepcopy(ctx.trust.data)
    for entry in data["keys"].values():
        if entry["principal"]=="alice":entry["revoked"]=True
    report=ctx.engine.gate("RC1",ctx.policy,Trust(data))
    assert {"TRUST_CHANGED","APPROVALS_MISSING"} <= codes(report)


def test_concurrent_writers_have_one_consistent_chain(ctx):
    def register(index):
        Engine(ctx.root).register(f"value-{index}","config",metadata={"value":index})
    with ThreadPoolExecutor(max_workers=6) as executor:
        list(executor.map(register,range(18)))
    state=ctx.engine.state()
    assert all(f"value-{i}" in state["resources"] for i in range(18))
    checkpoint=ctx.engine.store.verify_checkpoint()
    assert checkpoint["seq"]==25


def test_register_dependency_cycle_rejected(ctx):
    with pytest.raises(TapeoutError,match="cycle"):
        ctx.engine.register("rtl","rtl",path="rtl.v",depends_on=["layout"])


def test_default_hashed_pdk_rule_is_not_metadata_only(ctx):
    ctx.engine.register("metadata-pdk","pdk",metadata={"version":"1"})
    rid=ctx.engine.begin("LVS",["netlist","layout","metadata-pdk"],"tool","nominal")
    ctx.engine.finish(rid,None,exit_code=0)
    ctx.candidate();assert "PDK_CHECKSUM_MISSING" in codes(ctx.gate())
