"""Execute real KLayout DRC/LVS and OpenSTA positive/negative controls.

Cell-scale educational technology only. No foundry PDK, extracted parasitics or
production signoff claim. Missing tools are a failure, never a skipped pass.
"""
from __future__ import annotations

import argparse
import base64
import copy
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentapeout.bundle import seal, verify_bundle
from opentapeout.engine import Engine
from opentapeout.pinning import pin_policy
from opentapeout.policy import default_policy
from opentapeout.signing import Trust, key_id
from opentapeout.util import ensure, file_digest

EXAMPLES = Path(__file__).resolve().parents[1] / "examples" / "physical"


def qualify(root: Path) -> dict:
    tools = {name: shutil.which(command) for name, command in [("klayout", "klayout"), ("opensta", "sta")]}
    ensure(all(tools.values()), "Real KLayout and OpenSTA must be installed; no mock or skipped qualification")
    root.mkdir(parents=True, exist_ok=False)
    runtime = root / "runtime"
    runtime.mkdir(mode=0o700)
    os.environ.update(QT_QPA_PLATFORM="offscreen", XDG_RUNTIME_DIR=str(runtime))
    versions = {}
    for name, executable in tools.items():
        value = subprocess.run([executable, "-v" if name == "klayout" else "-version"],
                               check=True, text=True, capture_output=True, timeout=30)
        versions[name] = (value.stdout + value.stderr).strip()
    engine = Engine.init(root, "REAL PHYSICAL MICROFLOWS — EDUCATIONAL, NOT FOUNDRY SIGNOFF", "author")
    for path in EXAMPLES.iterdir():
        if path.is_file():
            shutil.copy2(path, root / path.name)
    subprocess.run([tools["klayout"], "-b", "-r", "make_layout.rb"], cwd=root, check=True, timeout=60)
    resources = {
        "layout": ("layout", "resistor.gds"), "schematic": ("netlist", "resistor.cir"),
        "drc-deck": ("rule_deck", "drc.drc"), "lvs-deck": ("rule_deck", "lvs.lvs"),
        "timing-netlist": ("netlist", "timing.v"), "sdc": ("constraints", "timing.sdc"),
        "lib-tt": ("library", "timing.lib"), "sta-script": ("config", "sta.tcl")}
    for name, (kind, path) in resources.items():
        engine.register(name, kind, path=path)
    engine.register("physical", "corner", metadata={"technology": "educational resistor", "not_foundry_qualified": True})
    engine.register("tt", "corner", metadata={"voltage_v": 1, "temperature_c": 25, "library": "educational-tt"})
    engine.register("ss", "corner", metadata={"voltage_v": 0.9, "temperature_c": 85, "library": "educational-slow"})
    # Separate native invocations and resource IDs, not just relabeling one report as two corners.
    (root/"timing-slow.lib").write_text((root/"timing.lib").read_text().replace('"0.20"', '"0.35"').replace("nom_voltage : 1.0", "nom_voltage : 0.9").replace("nom_temperature : 25", "nom_temperature : 85"))
    (root/"sta-slow.tcl").write_text((root/"sta.tcl").read_text().replace("read_liberty timing.lib", "read_liberty timing-slow.lib"))
    engine.register("lib-ss", "library", path="timing-slow.lib")
    engine.register("sta-script-ss", "config", path="sta-slow.tcl")
    configurations = {
        "drc": ("DRC", "physical", "klayout-drc", ["layout", "drc-deck"], "klayout", ["-b", "-r", "drc.drc"]),
        "lvs": ("LVS", "physical", "klayout-lvs", ["layout", "schematic", "lvs-deck"], "klayout", ["-b", "-r", "lvs.lvs"]),
        "sta-tt": ("STA", "tt", "opensta", ["timing-netlist", "sdc", "lib-tt", "sta-script"], "opensta", ["-exit", "sta.tcl"]),
        "sta-ss": ("STA", "ss", "opensta", ["timing-netlist", "sdc", "lib-ss", "sta-script-ss"], "opensta", ["-exit", "sta-slow.tcl"])}
    for name, (_, _, _, _, tool, args) in configurations.items():
        engine.register(name, "tool", metadata={"name": tool, "version": versions[tool],
            "argv": [tools[tool], *args], "executable_sha256": file_digest(Path(tools[tool]).resolve())[0]})
    counter = 0
    def run(name):
        nonlocal counter
        counter += 1
        kind, corner, fmt, inputs, _, _ = configurations[name]
        result = engine.run(kind, inputs, name, corner, f"native-{counter}.txt", format_name=fmt,
                            report_source="stdout", timeout=120)
        print(json.dumps({"name": name, "exit_code": result["exit_code"], "result": result["result"],
                          "parser_error": result["parser_error"]}, indent=2))
        # Preserve native transcripts in CI logs to diagnose an unsupported tool version.
        if result["parser_error"] or result["exit_code"]:
            for key in ("stdout_sha256", "stderr_sha256"):
                print(engine.store.verify_object(result[key]).read_text(errors="replace"))
        return result
    passing = {name: run(name) for name in configurations}
    ensure(all(r["exit_code"] == 0 and r["result"]["status"] == "pass" for r in passing.values()),
           "A native positive control failed; inspect transcripts, do not weaken the gate")
    keys, entries = {}, {}
    for principal, role in [("physical-reviewer", "physical"), ("timing-reviewer", "verification"), ("release-officer", "release")]:
        key = Ed25519PrivateKey.generate()
        public = base64.b64encode(key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
        keys[role] = key
        entries[key_id(public)] = {"public_key": public, "principal": principal, "roles": [role]}
    trust = Trust({"schema": "opentapeout.trust/v1", "keys": entries})
    policy = default_policy()
    policy.update(require_git=False, require_hashed_pdk=False)
    policy["required_checks"] = []
    for name, (kind, corner, fmt, inputs, _, _) in configurations.items():
        metrics = ({"rule:WIDTH:checked": {"min": 1}, "rule:SPACE:checked": {"min": 1}, "violation_count": {"max": 0}}
                   if kind == "DRC" else {"matched": {"min": 1}, "layout_devices": {"min": 1}}
                   if kind == "LVS" else {"setup_worst_slack_ns": {"min": 0}, "hold_worst_slack_ns": {"min": 0},
                                          "constraints_ok": {"min": 1}})
        kinds = sorted({engine.state()["resources"][key]["kind"] for key in inputs})
        policy["required_checks"].append({"kind": kind, "corner": corner, "required_resource_kinds": kinds,
                                         "metrics": metrics, "max_age_hours": 1})
    policy = pin_policy(engine, policy)
    engine.candidate("RC-PHYSICAL", "Cell-scale positive controls, not a tapeout", {"educational.gds": "layout"}, policy, trust, "author")
    for role in policy["approval_roles"]:
        engine.approve("RC-PHYSICAL", role, keys[role], policy, trust)
    ensure(engine.gate("RC-PHYSICAL", policy, trust)["ready"], "Reviewed exact-pin positive candidate failed")
    archive = root.parent / "physical-evidence.zip"
    sealed = seal(engine, "RC-PHYSICAL", archive, keys["release"], policy, trust)
    ensure(verify_bundle(archive, policy, trust)["verified"], "Native evidence failed offline verification")
    negative_gates = {}
    def blocked(name, case):
        kind, corner, _, _, _, _ = configurations[name]
        focused = copy.deepcopy(policy)
        focused["required_checks"] = [c for c in focused["required_checks"] if (c["kind"],c["corner"]) == (kind,corner)]
        # Refresh pins solely to ensure a defect is blocked by its evidence, not old hashes or missing approvals.
        focused = pin_policy(engine, focused)
        engine.candidate(case, "Deliberate negative control; never release", {"educational.gds":"layout"}, focused, trust, "author")
        gate = engine.gate(case, focused, trust, include_approvals=False)
        codes = {b["code"] for b in gate["blockers"]}
        ensure(not gate["ready"] and codes & {"UNWAIVED_VIOLATION", "METRIC_THRESHOLD", "RESULT_UNKNOWN"}, "Defective evidence did not block the gate")
        ensure(not codes & {"RESULT_STALE", "INPUT_PIN_MISMATCH", "CANDIDATE_CHANGED", "APPROVALS_MISSING"}, "Negative control confounded by stale pins or reviews")
        negative_gates[case] = sorted(codes)
    subprocess.run([tools["klayout"], "-b", "-rd", "defect=width", "-r", "make_layout.rb"], cwd=root, check=True, timeout=60)
    drift = engine.gate("RC-PHYSICAL", policy, trust)
    ensure(any(b["code"] == "WORKSPACE_DRIFT" for b in drift["blockers"]), "Unregistered layout drift not detected")
    engine.register("layout", "layout", path="resistor.gds")
    stale = engine.gate("RC-PHYSICAL", policy, trust)
    ensure(any(b["code"] == "RESULT_STALE" for b in stale["blockers"]), "Registered layout ECO did not invalidate evidence")
    bad_drc = run("drc")
    ensure(bad_drc["result"]["status"] == "fail" and bad_drc["result"]["metrics"]["rule:WIDTH:violations"] > 0,
           "Actual width violation not detected")
    blocked("drc", "BAD-WIDTH")
    # Restore geometry, then deliberately mismatch the electrical reference.
    subprocess.run([tools["klayout"], "-b", "-r", "make_layout.rb"], cwd=root, check=True, timeout=60)
    engine.register("layout", "layout", path="resistor.gds")
    (root/"resistor.cir").write_text((root/"resistor.cir").read_text().replace("A B 500", "A B 750"))
    engine.register("schematic", "netlist", path="resistor.cir")
    bad_lvs = run("lvs")
    ensure(bad_lvs["result"]["status"] == "fail", "Actual resistor mismatch not detected")
    blocked("lvs", "BAD-LVS")
    original_sdc = (root/"timing.sdc").read_text()
    (root/"timing.sdc").write_text(original_sdc.replace("-period 10", "-period 1"))
    engine.register("sdc", "constraints", path="timing.sdc")
    bad_sta = run("sta-tt")
    ensure(bad_sta["result"]["status"] == "fail" and bad_sta["result"]["metrics"]["setup_worst_slack_ns"] < 0,
           "Actual negative setup slack not detected")
    blocked("sta-tt", "BAD-STA")
    (root/"timing.sdc").write_text("\n".join(line for line in original_sdc.splitlines() if not line.startswith("set_output_delay")))
    engine.register("sdc", "constraints", path="timing.sdc")
    uncovered = run("sta-tt")
    ensure(uncovered["result"]["status"] != "pass", "Missing endpoint constraints must not pass")
    blocked("sta-tt", "BAD-CONSTRAINTS")
    return {"offline_archive_verified": True, "archive_sha256": sealed["archive_sha256"], "negative_gate_codes": negative_gates,
            "qualified": True, "scope": "educational cell-scale native DRC/LVS and two timing libraries; NOT foundry or full-chip signoff",
            "versions": versions, "positive_metrics": {name: r["result"]["metrics"] for name,r in passing.items()},
            "exact_pin_gate_passed": True, "layout_drift_blocked": True, "layout_eco_stale": True,
            "width_defect_blocked": True, "schematic_mismatch_blocked": True, "negative_setup_slack_blocked": True,
            "unconstrained_output_blocked": True,
            "negative_metrics": {"drc": bad_drc["result"]["metrics"], "lvs": bad_lvs["result"]["metrics"],
                                 "sta": bad_sta["result"]["metrics"]},
            "executable_identities": {name: r["execution_identity"] for name,r in passing.items()}}


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", type=Path, required=True)
    args = p.parse_args()
    with tempfile.TemporaryDirectory(prefix="opentapeout-physical-") as tmp:
        result = qualify(Path(tmp)/"workspace")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
