import copy

import pytest

from opentapeout.native import yosys_sat
from opentapeout.parsers import parse
from opentapeout.planning import compare, plan
from opentapeout.policy import validate_policy
from opentapeout.util import TapeoutError, finite_number

LOG = b"""3. Executing SAT pass (solving SAT problems in the circuit).
Import proof-constraint: \\ok = 1'1
Solving problem with 22 variables and 48 clauses..
SAT proof finished - no model found: SUCCESS!
End of script. Logfile hash: abc123, CPU: user 0.01s system 0.00s
Yosys 0.33 (synthetic unit transcript; real qualification runs separately)
"""


def test_fresh_plan_reuses_evidence_but_does_not_authorize_release(ctx):
    ctx.ready()
    result = plan(ctx.engine, ctx.policy, ctx.trust)
    assert result["advisory_only"]
    assert result["summary"]["reusable_checks"] == 1
    assert result["resource_tasks"] == []
    assert not result["new_candidate_required"]
    assert result["checks"][0]["action"] == "reuse_evidence"


def test_hypothetical_eco_plan_is_read_only_and_topological(ctx):
    ctx.ready()
    before = ctx.engine.store.verify_checkpoint()
    result = plan(ctx.engine, ctx.policy, ctx.trust, changed=["rtl"])
    tasks = result["resource_tasks"]
    assert [t["resource"] for t in tasks] == ["rtl", "netlist", "layout"]
    assert [t["wave"] for t in tasks] == [0, 1, 2]
    assert tasks[-1]["reason_path"] == ["rtl", "netlist", "layout"]
    assert result["checks"][0]["action"] == "rerun_or_resolve"
    assert ctx.engine.store.verify_checkpoint() == before and ctx.gate()["ready"]


def test_unrelated_change_preserves_check_evidence_not_approval(ctx):
    ctx.ready()
    ctx.engine.register("unrelated", "config", metadata={"a": 1})
    result = plan(ctx.engine, ctx.policy, ctx.trust, changed=["unrelated"])
    assert result["summary"]["reusable_checks"] == 1
    assert result["new_candidate_required"]
    assert not ctx.gate()["ready"]


def test_observed_and_registered_eco_plans(ctx):
    ctx.ready()
    (ctx.root/"rtl.v").write_text("modified rtl")
    result = plan(ctx.engine, ctx.policy, ctx.trust)
    assert "rtl" in result["observed_drift"]
    assert result["resource_tasks"][-1]["resource"] == "layout"
    ctx.engine.register("rtl", "rtl", path="rtl.v")
    result = plan(ctx.engine, ctx.policy, ctx.trust)
    assert not result["observed_drift"]
    assert {t["resource"] for t in result["resource_tasks"]} == {"netlist", "layout"}
    assert result["checks"][0]["action"] == "rerun_or_resolve"


def test_missing_run_and_unfrozen_project(ctx):
    result = plan(ctx.engine, ctx.policy, ctx.trust)
    assert result["new_candidate_required"]
    assert result["checks"][0]["action"] == "configure_and_run"
    assert result["checks"][0]["roots"] is None


def test_latest_incomplete_does_not_reuse_previous_success(ctx):
    ctx.ready()
    new = ctx.engine.begin("LVS", ["layout"], "tool", "nominal")
    result = plan(ctx.engine, ctx.policy, ctx.trust)
    assert result["checks"][0]["action"] == "wait_for_latest_run"
    assert result["checks"][0]["run_id"] == new


def test_plan_detects_corrupt_report(ctx):
    ctx.ready()
    r = next(iter(ctx.engine.state()["runs"].values()))
    obj = ctx.engine.store.object_path(r["report_sha256"])
    obj.chmod(0o600)
    obj.write_text("broken")
    result = plan(ctx.engine, ctx.policy, ctx.trust)
    assert result["checks"][0]["action"] == "repair_evidence"
    assert result["summary"]["reusable_checks"] == 0


@pytest.mark.parametrize("changed", [["not-registered"], "rtl", [1]])
def test_bad_hypothetical_inputs(ctx, changed):
    with pytest.raises(TapeoutError):
        plan(ctx.engine, ctx.policy, ctx.trust, changed=changed)


def test_metric_comparison_does_not_guess_which_direction_is_better(ctx):
    ctx.run(metrics={"wns_ns": 0.1, "power_mw": 40, "removed": 1})
    ctx.candidate("RC1")
    ctx.run(metrics={"wns_ns": 0.2, "power_mw": 45, "added": 3})
    ctx.candidate("RC2")
    result = compare(ctx.engine, "RC1", "RC2")
    deltas = {d["metric"]: d for d in result["metric_deltas"]}
    assert deltas["power_mw"]["delta"] == 5
    assert deltas["removed"]["change"] == "removed"
    assert deltas["added"]["change"] == "added"
    assert deltas["wns_ns"]["delta"] == pytest.approx(0.1)
    assert result["check_transitions"][0]["evidence_changed"]
    assert not result["policy_changed"]


def test_native_sat_report(ctx):
    result = parse(LOG, "yosys-sat", "run-1")
    assert result["status"] == "pass" and result["metrics"]["proofs_passed"] == 1
    assert result["metrics"]["sat_variables"] == 22
    result = yosys_sat(LOG.replace(b"no model found: SUCCESS!", b"model found: FAIL!"), "run-1")
    assert result["status"] == "fail" and len(result["violations"]) == 1


@pytest.mark.parametrize("data", [b"SUCCESS!", b"", b"End of script. Logfile hash: abc", b"\xff\xfe", LOG+b"\x00"])
def test_unknown_native_transcripts_are_rejected(data):
    with pytest.raises(TapeoutError):
        parse(data, "yosys-sat", "run-1")


@pytest.mark.parametrize("data", [
    LOG.replace(b"End of script.", b"truncated"), LOG+b"ERROR: an additional proof failed\n",
    LOG.replace(b"SAT proof finished", b"SAT proof finished - invalid"),
    LOG.replace(b"Solving problem with 22 variables and 48 clauses..", b"unknown"),
    LOG+b"End of script. Logfile hash: ffff\n", LOG.replace(b"End of script.", b"Solving problem with 1 variables and 2 clauses..\nEnd of script."),
])
def test_incomplete_or_mixed_transcripts_never_pass(data):
    try:
        result = parse(data, "yosys-sat", "run-1")
        assert result["status"] != "pass"
    except TapeoutError:
        pass


def test_native_report_cannot_satisfy_lvs(ctx):
    rid = ctx.engine.begin("LVS", ["layout"], "tool", "nominal")
    (ctx.root/"yosys.log").write_bytes(LOG)
    run = ctx.engine.finish(rid, "yosys.log", exit_code=0, format_name="yosys-sat")
    assert run["result"]["status"] == "unknown"
    assert "FORMAL" in run["parser_error"]


@pytest.mark.parametrize("timeout", [float("inf"), float("nan"), True, -1, 0, 10**500, 31536001])
def test_invalid_timeouts_do_not_start_process_or_mutate_ledger(ctx, timeout):
    checkpoint = ctx.engine.store.verify_checkpoint()
    with pytest.raises(TapeoutError):
        ctx.engine.run("FORMAL", ["rtl"], "tool", "nominal", "out.json", timeout=timeout)
    assert ctx.engine.store.verify_checkpoint() == checkpoint


def test_numeric_overflow_fails_closed(ctx):
    assert not finite_number(10**500)
    policy = copy.deepcopy(ctx.policy)
    policy["max_approval_age_hours"] = 1e300
    with pytest.raises(TapeoutError):
        validate_policy(policy)


def test_vacuous_proof_without_explicit_constraint_is_rejected():
    with pytest.raises(TapeoutError, match="explicit SAT"):
        yosys_sat(LOG.replace(b"Import proof-constraint:", b"Nothing to prove:"), "run-1")


def test_metric_delta_overflow_is_explicit(ctx):
    ctx.run(metrics={"extreme": -1e308})
    ctx.candidate("RC1")
    ctx.run(metrics={"extreme": 1e308})
    ctx.candidate("RC2")
    delta = compare(ctx.engine, "RC1", "RC2")["metric_deltas"][0]
    assert delta["delta"] is None and delta["delta_overflow"]
