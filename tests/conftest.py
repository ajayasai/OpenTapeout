from __future__ import annotations

import base64
import copy
import json
import sys
from types import SimpleNamespace

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from opentapeout.engine import Engine
from opentapeout.policy import default_policy
from opentapeout.signing import Trust, key_id
from opentapeout.util import write_json


@pytest.fixture
def ctx(tmp_path):
    root = tmp_path / "workspace"
    root.mkdir()
    engine = Engine.init(root, "TEST FIXTURE — NOT SIGNOFF", "author")
    for name, content in {"rtl.v": "rtl1", "netlist.v": "net1", "chip.gds": "synthetic layout",
                           "pdk.lock": "pdk1"}.items():
        (root / name).write_text(content)
    engine.register("pdk", "pdk", path="pdk.lock", metadata={"version": "1"})
    engine.register("rtl", "rtl", path="rtl.v")
    engine.register("netlist", "netlist", path="netlist.v", depends_on=["rtl", "pdk"])
    engine.register("layout", "layout", path="chip.gds", depends_on=["netlist"])
    engine.register("nominal", "corner", metadata={"voltage_v": 1.0, "temperature_c": 25})
    script = ("import os,json;from pathlib import Path;"
              "Path(os.environ['OPENTAPEOUT_REPORT']).write_text(json.dumps({"
              "'schema':'opentapeout.result/v1','run_id':os.environ['OPENTAPEOUT_RUN_ID'],"
              "'status':'pass','complete':True,'metrics':{},'violations':[]}))")
    engine.register("tool", "tool", metadata={"name": "fixture", "version": "1", "argv": [sys.executable, "-c", script]})
    keys, entries = {}, {}
    for principal, roles in [("alice", ["physical", "waiver"]), ("bob", ["verification"]),
                              ("release", ["release"]), ("author", ["physical"]),
                              ("flexible", ["physical", "verification", "waiver"])]:
        key = Ed25519PrivateKey.generate()
        public = base64.b64encode(key.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
        keys[principal] = key
        entries[key_id(public)] = {"public_key": public, "principal": principal, "roles": roles}
    trust = Trust({"schema": "opentapeout.trust/v1", "keys": entries})
    policy = default_policy()
    policy["required_checks"] = [{"kind": "LVS", "corner": "nominal", "required_resource_kinds": ["netlist", "layout", "pdk"],
                                  "max_age_hours": 168, "metrics": {}}]
    policy["require_git"] = False  # Unit fixture is not a real Git/EDA flow; production defaults remain strict.
    policy["require_managed_runs"] = False
    counter = [0]
    def run(*, status="pass", violations=None, exit_code=0, metrics=None, complete=True):
        rid = engine.begin("LVS", ["netlist", "layout", "pdk"], "tool", "nominal", "runner")
        filename = f"report-{counter[0]}.json"
        counter[0] += 1
        write_json(root / filename, {"schema": "opentapeout.result/v1", "run_id": rid, "status": status,
                   "complete": complete, "metrics": metrics or {}, "violations": violations or []})
        return engine.finish(rid, filename, exit_code=exit_code)
    def candidate(name="RC1", notes="Unit-test synthetic release notes"):
        engine.candidate(name, notes, {"chip.gds": "layout"}, policy, trust, "author")
        return name
    def approve(name="RC1"):
        engine.approve(name, "physical", keys["alice"], policy, trust)
        engine.approve(name, "verification", keys["bob"], policy, trust)
    def ready():
        run()
        candidate()
        approve()
    def gate(name="RC1"):
        return engine.gate(name, policy, trust)
    write_json(root / "policy.json", policy)
    write_json(root / "trust.json", trust.data)
    return SimpleNamespace(root=root, engine=engine, policy=policy, trust=trust, keys=keys,
                           run=run, candidate=candidate, approve=approve, ready=ready, gate=gate,
                           policy_copy=lambda: copy.deepcopy(policy))


@pytest.fixture
def violation():
    return {"rule": "LVS.NET_MISMATCH", "location": "top/u0/net0", "message": "Synthetic unconnected fixture net",
            "severity": "error"}
