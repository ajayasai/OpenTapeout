"""Definition integrity regressions supplementing the policy-v2 tests."""
import copy
import sys
from pathlib import Path

import pytest
from test_policy_v2 import upgrade, pinned_run

from opentapeout.policy import evaluate, validate_policy
from opentapeout.util import TapeoutError, file_digest, now


@pytest.mark.parametrize("field,value", [("corner", []), ("kind", {}), ("required_resource_kinds", [[]])])
def test_invalid_check_containers(ctx, field, value):
    p=upgrade(ctx);p["required_checks"][0][field]=value
    with pytest.raises(TapeoutError):validate_policy(p)


def test_invalid_schema_container(ctx):
    p=upgrade(ctx);p["schema"]=[]
    with pytest.raises(TapeoutError):validate_policy(p)


def test_file_backed_tool_does_not_pin_options(ctx):
    from opentapeout.pinning import pin_policy
    meta=ctx.engine.state()["resources"]["tool"]["metadata"].copy()
    meta["executable_sha256"]=file_digest(Path(sys.executable).resolve())[0]
    ctx.engine.register("tool","tool",metadata=meta,path="netlist.v")
    ctx.engine.run("LVS",["layout","netlist","pdk"],"tool","nominal","file-tool.json")
    with pytest.raises(TapeoutError):pin_policy(ctx.engine,ctx.policy)
    ctx.policy.update(upgrade(ctx));ctx.candidate()
    assert "DEFINITION_PIN_INVALID" in {b["code"] for b in ctx.gate()["blockers"]}


def test_offline_tool_spec_substitution(ctx):
    from opentapeout.pinning import pin_policy
    pinned_run(ctx);ctx.policy.update(pin_policy(ctx.engine,ctx.policy));ctx.candidate()
    c=copy.deepcopy(ctx.engine.state()["candidates"]["RC1"])
    next(iter(c["runs"].values()))["tool_spec"]["argv"]=["different-command"]
    gate=evaluate(c,ctx.policy,ctx.trust,[],at=now(),include_approvals=False)
    assert "TOOL_SPEC_MISMATCH" in {b["code"] for b in gate["blockers"]}
