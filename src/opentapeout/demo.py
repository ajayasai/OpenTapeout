"""A visibly synthetic six-check demo. No EDA license, PDK or real signoff required."""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from .engine import Engine
from .git_capture import inspect_git
from .policy import default_policy
from .signing import Trust, generate_key, load_key
from .util import ensure, write_json

SYNTHETIC_RUNNER = '''"""SYNTHETIC test fixture. This does not run any real EDA check."""
import json, os
from pathlib import Path
result = {"schema": "opentapeout.result/v1", "run_id": os.environ["OPENTAPEOUT_RUN_ID"],
          "status": "pass", "complete": True, "metrics": {"wns_ns": 0.14, "tns_ns": 0.0, "power_mw": 32.8},
          "violations": []}
Path(os.environ["OPENTAPEOUT_REPORT"]).write_text(json.dumps(result))
print("SYNTHETIC fixture completed. NOT silicon signoff.")
'''


def build_demo(root: Path, *, stale: bool = False) -> dict:
    root = root.resolve()
    ensure(not root.exists() or not any(root.iterdir()), "Demo destination must be empty")
    root.mkdir(parents=True, exist_ok=True)
    design = root / "design"
    design.mkdir()
    contents = {"top.v": "module top(input a, output y); assign y = a; endmodule\n",
        "top.net.v": "module top(input a, output y); assign y = a; endmodule\n",
        "chip.gds": "SYNTHETIC DEMO: NOT A VALID/MANUFACTURABLE GDS FILE\n",
        "pdk.lock": '{"name":"synthetic-pdk","version":"demo-1","not_for_manufacturing":true}\n',
        "rules.drc": "# Synthetic rules fixture; not foundry signoff\n",
        "timing.sdc": "create_clock -name clk -period 10 [get_ports a]\n",
        "cells.lib": "/* Synthetic library fixture */\n",
        "power.upf": "# Synthetic power-intent fixture\n",
        "synthetic_runner.py": SYNTHETIC_RUNNER}
    for name, content in contents.items():
        (design / name).write_text(content)
    def git(*args: str) -> None:
        subprocess.run(["git", "-C", str(design), *args], check=True, capture_output=True)
    git("init", "-b", "main")
    git("add", ".")
    git("-c", "user.name=OpenTapeout demo", "-c", "user.email=demo@example.invalid",
        "commit", "-m", "Synthetic demonstration inputs; not manufacturing data")
    engine = Engine.init(root, "Aurora • SYNTHETIC DEMO", "release-author")
    policy = default_policy()
    write_json(root / "policy.json", policy)
    keys = {}
    (root / "keys").mkdir(mode=0o700)
    for principal, roles in [("physical-reviewer", ["physical", "waiver"]),
                             ("verification-reviewer", ["verification"]),
                             ("release-engineer", ["release"])]:
        public = generate_key(root / "keys" / (principal + ".pem"))
        keys[public["key_id"]] = {"principal": principal, "roles": roles, "public_key": public["public_key"]}
    trust_data = {"schema": "opentapeout.trust/v1", "keys": keys}
    write_json(root / "trust.json", trust_data)
    trust = Trust(trust_data)
    engine.register("source-commit", "git", metadata=inspect_git(root, "design"))
    registrations = [
        ("rtl", "rtl", "top.v", [], {}),
        ("pdk", "pdk", "pdk.lock", [], {"version": "demo-1", "synthetic": True}),
        ("rules", "rule_deck", "rules.drc", ["pdk"], {}),
        ("constraints", "constraints", "timing.sdc", [], {}),
        ("library", "library", "cells.lib", ["pdk"], {}),
        ("power-intent", "power_intent", "power.upf", [], {}),
        ("runner-script", "config", "synthetic_runner.py", [], {}),
        ("netlist", "netlist", "top.net.v", ["rtl", "library"], {}),
        ("layout", "layout", "chip.gds", ["netlist", "pdk"], {})]
    for rid, kind, file, deps, metadata in registrations:
        engine.register(rid, kind, path="design/" + file, metadata=metadata, depends_on=deps)
    engine.register("nominal", "corner", metadata={"process": "synthetic-tt", "voltage_v": 1.8, "temperature_c": 25})
    engine.register("demo-tool", "tool", depends_on=["runner-script"], metadata={
        "name": "SYNTHETIC fixture (NOT EDA)", "version": "1.0", "argv": [sys.executable, "design/synthetic_runner.py"]})
    inputs = ["rtl", "netlist", "layout", "pdk", "rules", "constraints", "library", "power-intent"]
    # Production integrations should choose check-specific roots. The demo intentionally binds
    # all fixture inputs so a single file edit illustrates conservative multi-check invalidation.
    (root / "reports").mkdir()
    for check in policy["required_checks"]:
        engine.run(check["kind"], inputs, "demo-tool", "nominal", f"reports/{check['kind']}.json")
    engine.candidate("RC-001", "Synthetic review example. No real tool results, real PDK, or manufacturing GDS.",
                     {"aurora.gds": "layout"}, policy, trust, "release-author")
    for role, principal in [("physical", "physical-reviewer"), ("verification", "verification-reviewer")]:
        engine.approve("RC-001", role, load_key(root / "keys" / f"{principal}.pem"), policy, trust)
    baseline = engine.gate("RC-001", policy, trust)
    ensure(baseline["ready"], f"Demo setup failed: {baseline['blockers']}")
    if stale:
        with (design / "top.net.v").open("a") as handle:
            handle.write("// Synthetic ECO applied after signoff\n")
        git("add", "top.net.v")
        git("-c", "user.name=OpenTapeout demo", "-c", "user.email=demo@example.invalid",
            "commit", "-m", "Synthetic ECO after evidence capture")
        engine.register("source-commit", "git", metadata=inspect_git(root, "design"))
        engine.register("netlist", "netlist", path="design/top.net.v", depends_on=["rtl", "library"])
    return {"workspace": str(root), "synthetic": True, "baseline_ready": baseline["ready"],
            "current_gate": engine.gate("RC-001", policy, trust),
            "serve": f"opentapeout --root {root} serve"}
