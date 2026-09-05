"""Fail-closed, run-bound collector protocols for KLayout and OpenSTA.

These are deliberately narrow contracts for the reviewed collector scripts, not
universal parsers for arbitrary vendor reports. Native computation happens inside
KLayout/OpenSTA. The captured collector source and executable remain trust inputs.
"""
from __future__ import annotations

import re
from collections import Counter

from .parsers import SCHEMA, validate_result
from .util import TapeoutError, ensure, finite_number, identifier, loads

NUMBER = r"[-+]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][-+]?[0-9]+)?"
DIAGNOSTIC = re.compile(r"^\s*(?:ERROR|FATAL|WARNING|Error|Warning)(?:\s|:)", re.MULTILINE)


def _frame(data: bytes, backend: str, run_id: str) -> str:
    try:
        text = data.decode("utf-8-sig").replace("\r\n", "\n")
    except UnicodeDecodeError as exc:
        raise TapeoutError("Physical transcript must be UTF-8") from exc
    ensure("\x00" not in text, "NUL in physical transcript")
    lines = text.splitlines()
    begin, end = f"OT_BEGIN {backend} {run_id}", f"OT_END {backend} {run_id}"
    markers = [line for line in lines if line.startswith(("OT_BEGIN", "OT_END"))]
    ensure(markers == [begin, end], "Missing, duplicated, wrong-run or reordered physical transcript frame")
    ensure(not DIAGNOSTIC.search(text), "Native tool diagnostic requires review; no automatic pass")
    start, stop = lines.index(begin), lines.index(end)
    ensure(start < stop, "Physical report ends before it begins")
    outside = lines[:start] + lines[stop+1:]
    ensure(not any(line.startswith("OT_") for line in outside), "Collector data outside completion frame")
    return "\n".join(lines[start+1:stop])


def _integer(value, label: str, minimum: int = 0) -> int:
    ensure(type(value) is int and minimum <= value <= 10**12, f"Invalid {label} count")
    return value


def _klayout(body: str, backend: str, run_id: str) -> dict:
    lines = body.splitlines()
    data_lines = [line for line in lines if line.startswith("OT_DATA ")]
    ensure(len(data_lines) == 1, "Exactly one native collector data record required")
    ensure(not any(line.startswith("OT_") and line != data_lines[0] for line in lines), "Unknown collector record")
    value = loads(data_lines[0][8:])
    ensure(isinstance(value, dict), "Native collector data must be an object")
    violations, metrics = [], {}
    if backend == "klayout-drc":
        ensure(set(value) == {"rules", "shapes_checked", "violations"}, "Invalid DRC collector fields")
        metrics["shapes_checked"] = _integer(value["shapes_checked"], "shape", 1)
        rules = value["rules"]
        ensure(isinstance(rules, dict) and 0 < len(rules) <= 10000, "DRC must execute explicit named rules")
        for rule, count in rules.items():
            identifier(rule)
            _integer(count, "violation")
            metrics[f"rule:{rule}:checked"] = 1
            metrics[f"rule:{rule}:violations"] = count
        violations = value["violations"]
        ensure(isinstance(violations, list) and all(isinstance(v, dict) for v in violations), "DRC markers must be a list")
        counts = Counter(v.get("rule") for v in violations if isinstance(v.get("rule"), str))
        ensure(set(counts) <= set(rules) and all(counts[r] == n for r, n in rules.items())
               and sum(rules.values()) == len(violations), "DRC marker and rule counts disagree")
        metrics["rules_checked"] = len(rules)
    else:
        ensure(set(value) == {"matched", "layout_devices", "reference_devices", "layout_nets",
                              "reference_nets", "circuits_compared"}, "Invalid LVS collector fields")
        ensure(type(value["matched"]) is bool, "LVS match result must be a boolean")
        for name in ("layout_devices", "reference_devices", "layout_nets", "reference_nets", "circuits_compared"):
            metrics[name] = _integer(value[name], name, 1)
        # Counts are a vacuity guard, not an independent netlist equivalence proof.
        if value["matched"]:
            ensure(metrics["layout_devices"] == metrics["reference_devices"], "Matched LVS device counts disagree")
        else:
            violations.append({"rule": "LVS.MISMATCH", "location": "compared-netlists",
                               "message": "Native KLayout netlist comparison returned false", "severity": "error"})
        metrics["matched"] = int(value["matched"])
    metrics["violation_count"] = len(violations)
    return validate_result({"schema": SCHEMA, "run_id": run_id, "status": "fail" if violations else "pass",
                            "complete": True, "metrics": metrics, "violations": violations}, run_id)


def _one(body: str, pattern: str, label: str) -> str:
    matches = re.findall(pattern, body, re.MULTILINE)
    ensure(len(matches) == 1, f"Missing or duplicated {label}")
    return matches[0]


def _opensta(body: str, run_id: str) -> dict:
    # The collector sets command units to ns and emits all six mandatory sections.
    ensure(_one(body, r"^OT_TIME_UNIT (\S+)$", "time unit") == "ns", "OpenSTA collector must use nanoseconds")
    clocks = int(_one(body, r"^OT_CLOCKS ([0-9]{1,12})$", "clock count"))
    ensure(clocks > 0, "No clocks; zero slack is not timing coverage")
    setup_ok = _one(body, r"^OT_CONSTRAINTS_OK ([01])$", "constraint coverage")
    order = ["SETUP_PATHS", "HOLD_PATHS", "SETUP_WORST", "HOLD_WORST", "SETUP_TNS", "HOLD_TNS"]
    boundaries = [line for line in body.splitlines() if line.startswith(("OT_SECTION ", "OT_SECTION_END "))]
    expected = [x for name in order for x in (f"OT_SECTION {name}", f"OT_SECTION_END {name}")]
    allowed = {"OT_TIME_UNIT ns", f"OT_CLOCKS {clocks}", f"OT_CONSTRAINTS_OK {setup_ok}", *expected}
    ensure(all(not line.startswith("OT_") or line in allowed for line in body.splitlines()), "Unknown timing collector record")
    ensure(boundaries == expected, "Timing sections missing, duplicated or out of order")
    sections = {}
    for name in order:
        sections[name] = _one(body, rf"(?s)^OT_SECTION {name}\n(.*?)\nOT_SECTION_END {name}$", name)
    metrics = {"clocks": clocks, "constraints_ok": int(setup_ok)}
    violations = []
    if setup_ok != "1":
        violations.append({"rule": "STA.CONSTRAINTS", "location": "check_setup",
                           "message": "OpenSTA check_setup found unconstrained or invalid timing coverage", "severity": "error"})
    for mode in ("setup", "hold"):
        paths = sections[f"{mode.upper()}_PATHS"]
        starts = re.findall(r"^Startpoint: .+", paths, re.MULTILINE)
        ends = re.findall(r"^Endpoint: .+", paths, re.MULTILINE)
        slacks = re.findall(rf"^\s*({NUMBER})\s+slack \((MET|VIOLATED)\)\s*$", paths, re.MULTILINE)
        ensure(len(starts) > 0 and len(starts) == len(ends) == len(slacks), "Empty or truncated timing paths")
        path_values = [float(value) for value, _ in slacks]
        ensure(all(finite_number(v) for v in path_values), "Nonfinite timing path slack")
        for (value, status) in slacks:
            ensure((float(value) >= 0) == (status == "MET"), "Timing slack sign disagrees with path status")
        worst = float(_one(sections[f"{mode.upper()}_WORST"], rf"^worst slack\s+({NUMBER})\s*$", "worst slack"))
        tns = float(_one(sections[f"{mode.upper()}_TNS"], rf"^tns\s+({NUMBER})\s*$", "total negative slack"))
        ensure(finite_number(worst) and finite_number(tns) and tns <= 0, "Invalid timing summary")
        ensure(abs(worst - min(path_values)) <= 1e-9, "Worst path and timing summary disagree")
        ensure((worst >= 0 and tns == 0) or (worst < 0 and tns <= worst + 1e-9), "WNS/TNS summaries contradict")
        metrics[f"{mode}_paths_reported"] = len(starts)
        metrics[f"{mode}_worst_slack_ns"] = worst
        metrics[f"{mode}_tns_ns"] = tns
        if worst < 0:
            violations.append({"rule": f"STA.{mode.upper()}", "location": f"{mode}-worst-path",
                               "message": f"Native {mode} worst slack is {worst} ns", "severity": "error"})
    metrics["wns_ns"] = min(0, metrics["setup_worst_slack_ns"])
    metrics["tns_ns"] = metrics["setup_tns_ns"]
    metrics["violation_count"] = len(violations)
    return validate_result({"schema": SCHEMA, "run_id": run_id, "status": "fail" if violations else "pass",
                            "complete": True, "metrics": metrics, "violations": violations}, run_id)


def parse_physical(data: bytes, backend: str, run_id: str) -> dict:
    body = _frame(data, backend, run_id)
    return _opensta(body, run_id) if backend == "opensta" else _klayout(body, backend, run_id)
