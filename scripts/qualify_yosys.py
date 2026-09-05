"""Real-tool regression: prove a combinational miter, edit RTL, detect stale proof,
and reject a real counterexample. Fails (never skips) if Yosys is unavailable.
This is not foundry, PDK, DRC/LVS or production signoff qualification.
"""
from __future__ import annotations

import argparse
import base64
import json
import shutil
import subprocess
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentapeout.engine import Engine
from opentapeout.planning import plan
from opentapeout.policy import default_policy
from opentapeout.signing import Trust, key_id
from opentapeout.util import ensure

RTL = """module miter(input [3:0] a, b, output ok);
wire [4:0] spec = {1'b0,a} + {1'b0,b};
wire [4:0] impl = {1'b0,b} + {1'b0,a};
assign ok = (spec == impl);
endmodule
"""
SCRIPT = "read_verilog miter.v\nhierarchy -check -top miter\nproc\nflatten\nopt_clean\nsat -verify -prove ok 1 -show-inputs -show-outputs\n"


def qualify(root: Path) -> dict:
    executable = shutil.which("yosys")
    ensure(executable is not None, "Yosys must be installed: this qualification cannot be replaced by synthetic reports")
    version = subprocess.run([executable, "-V"], check=True, capture_output=True, text=True, timeout=20).stdout.strip()
    engine = Engine.init(root, "REAL YOSYS COMBINATIONAL PROOF — NOT FOUNDRY SIGNOFF", "author")
    (root/"miter.v").write_text(RTL)
    (root/"proof.ys").write_text(SCRIPT)
    engine.register("rtl", "rtl", path="miter.v")
    engine.register("proof-contract", "constraints", path="proof.ys")
    engine.register("nominal", "corner", metadata={"mode": "combinational", "top": "miter", "property": "ok=1"})
    def tool(log):
        engine.register("yosys", "tool", metadata={"name": "yosys", "version": version,
                         "argv": [executable, "-Q", "-l", log, "-s", "proof.ys"]})
    tool("proof-pass.log")
    keys, entries = {}, {}
    for principal, role in (("reviewer-a", "physical"), ("reviewer-b", "verification")):
        key = Ed25519PrivateKey.generate()
        public = base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
        keys[role] = key
        entries[key_id(public)] = {"public_key": public, "principal": principal, "roles": [role]}
    trust = Trust({"schema": "opentapeout.trust/v1", "keys": entries})
    policy = default_policy()
    policy.update(require_delivery=False, require_git=False, require_hashed_pdk=False)
    policy["required_checks"] = [{"kind": "FORMAL", "corner": "nominal", "required_resource_kinds": ["rtl", "constraints"],
                                 "max_age_hours": 1, "metrics": {"proofs_passed": {"min": 1}, "proofs_failed": {"max": 0}}}]
    passing = engine.run("FORMAL", ["rtl", "proof-contract"], "yosys", "nominal", "proof-pass.log", format_name="yosys-sat")
    ensure(passing["exit_code"] == 0 and passing["result"]["status"] == "pass", f"Genuine Yosys proof not accepted: {passing}")
    engine.candidate("RC-PASS", "Real combinational SAT example, not manufacturing signoff", {}, policy, trust, "author")
    for role, key in keys.items():
        engine.approve("RC-PASS", role, key, policy, trust)
    ensure(engine.gate("RC-PASS", policy, trust)["ready"], "Real proof candidate should satisfy this focused policy")
    (root/"miter.v").write_text(RTL.replace("{1'b0,b} + {1'b0,a};", "{1'b0,b} + {1'b0,a} + 1'b1;"))
    drift_gate = engine.gate("RC-PASS", policy, trust)
    ensure(not drift_gate["ready"] and any(b["code"] == "WORKSPACE_DRIFT" for b in drift_gate["blockers"]), "RTL drift was not detected")
    engine.register("rtl", "rtl", path="miter.v")
    stale_gate = engine.gate("RC-PASS", policy, trust)
    ensure(any(b["code"] == "RESULT_STALE" for b in stale_gate["blockers"]), "Old proof was incorrectly fresh after RTL edit")
    rerun = plan(engine, policy, trust)
    ensure(rerun["summary"]["reusable_checks"] == 0, "Planner must not reuse stale proof")
    tool("proof-fail.log")
    failing = engine.run("FORMAL", ["rtl", "proof-contract"], "yosys", "nominal", "proof-fail.log", format_name="yosys-sat")
    ensure(failing["exit_code"] != 0 and failing["result"]["status"] != "pass", "Real counterexample must fail")
    engine.candidate("RC-FAIL", "Deliberate adder defect, must not release", {}, policy, trust, "author")
    failed_gate = engine.gate("RC-FAIL", policy, trust)
    ensure(not failed_gate["ready"] and any(b["code"] == "TOOL_FAILED" for b in failed_gate["blockers"]), "Real failed proof bypassed gate")
    return {"qualified": True, "tool_version": version, "scope": "combinational Yosys SAT only; no foundry signoff",
            "passing_proof": passing["result"], "passing_exit_code": passing["exit_code"],
            "unregistered_drift_blocked": True, "registered_eco_stale": True,
            "counterexample_exit_code": failing["exit_code"], "counterexample_blocked": True,
            "checks_reused_after_eco": rerun["summary"]["reusable_checks"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    with tempfile.TemporaryDirectory(prefix="opentapeout-yosys-") as tmp:
        result = qualify(Path(tmp)/"workspace")
        data = json.dumps(result, indent=2) + "\n"
        if args.output:
            args.output.parent.mkdir(parents=True, exist_ok=True)
            args.output.write_text(data)
        print(data)


if __name__ == "__main__":
    main()
