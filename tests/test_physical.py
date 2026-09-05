"""Parser tests use hand-authored fixtures. Native execution is a separate mandatory CI job."""
import json

import pytest

from opentapeout.parsers import parse
from opentapeout.util import TapeoutError


def framed(backend, body, run_id="run1"):
    return f"OT_BEGIN {backend} {run_id}\n{body}\nOT_END {backend} {run_id}\n".encode()


def klayout(backend="klayout-drc", **changes):
    if backend == "klayout-drc":
        value = {"rules": {"WIDTH": 0, "SPACE": 0}, "shapes_checked": 3, "violations": []}
    else:
        value = {"matched": True, "layout_devices": 1, "reference_devices": 1,
                 "layout_nets": 2, "reference_nets": 2, "circuits_compared": 1}
    value.update(changes)
    return framed(backend, "OT_DATA " + json.dumps(value))


def sta(*, setup=7.6, hold=0.6, clocks=1, constraints=1):
    lines = ["OT_TIME_UNIT ns", f"OT_CLOCKS {clocks}", f"OT_CONSTRAINTS_OK {constraints}"]
    for name, slack in [("SETUP_PATHS", setup), ("HOLD_PATHS", hold),
                        ("SETUP_WORST", setup), ("HOLD_WORST", hold),
                        ("SETUP_TNS", min(setup, 0)), ("HOLD_TNS", min(hold, 0))]:
        lines.append(f"OT_SECTION {name}")
        if name.endswith("PATHS"):
            lines.extend(["Startpoint: a", "Endpoint: y", f" {slack} slack ({'VIOLATED' if slack < 0 else 'MET'})"])
        else:
            lines.append(("tns " if name.endswith("TNS") else "worst slack ") + str(slack))
        lines.append(f"OT_SECTION_END {name}")
    return framed("opensta", "\n".join(lines))


def test_drc_pass_and_named_coverage():
    result = parse(klayout(), "klayout-drc", "run1")
    assert result["status"] == "pass"
    assert result["metrics"]["rules_checked"] == 2
    assert result["metrics"]["rule:WIDTH:checked"] == 1


def test_drc_actual_markers_preserved():
    violation = {"rule": "WIDTH", "location": "TOP/0", "message": "width marker", "severity": "error", "geometry": ["(0,0;1,0)"]}
    value = klayout(rules={"WIDTH": 1}, violations=[violation])
    result = parse(value, "klayout-drc", "run1")
    assert result["status"] == "fail"
    assert result["violations"][0]["geometry"] == violation["geometry"]
    assert len(result["violations"][0]["fingerprint"]) == 64


@pytest.mark.parametrize("changes", [
    {"rules": {}}, {"rules": {"WIDTH": True}}, {"rules": {"WIDTH": -1}},
    {"rules": {"WIDTH": 1}}, {"shapes_checked": 0}, {"shapes_checked": True},
    {"shapes_checked": 10**13}, {"violations": {}}, {"rules": {"bad name": 0}},
    {"rules": []}, {"extra": 1}, {"violations": [42]},
])
def test_invalid_drc(changes):
    with pytest.raises(TapeoutError):
        parse(klayout(**changes), "klayout-drc", "run1")


@pytest.mark.parametrize("matched", [True, False])
def test_lvs_boolean_comparison(matched):
    result = parse(klayout("klayout-lvs", matched=matched), "klayout-lvs", "run1")
    assert (result["status"] == "pass") == matched


@pytest.mark.parametrize("changes", [{"layout_devices": 0}, {"reference_devices": 0},
    {"circuits_compared": 0}, {"layout_nets": -1}, {"matched": "true"},
    {"reference_devices": 2}, {"extra": 1}, {"layout_devices": 1.0}])
def test_lvs_vacuity_and_invalid_data(changes):
    with pytest.raises(TapeoutError):
        parse(klayout("klayout-lvs", **changes), "klayout-lvs", "run1")


@pytest.mark.parametrize("backend,data", [("klayout-drc", klayout()),
    ("klayout-lvs", klayout("klayout-lvs")), ("opensta", sta())])
@pytest.mark.parametrize("mutation", [lambda b: b.replace(b"run1", b"wrong"),
    lambda b: b + b"OT_EXTRA 1\n", lambda b: b + b"ERROR: native failure\n",
    lambda b: b + b"Warning: ignored library\n", lambda b: b.replace(b"OT_END", b"INCOMPLETE"),
    lambda b: b + b, lambda b: b + b"\x00", lambda b: b + b"\xff"])
def test_invalid_transcript_frame(backend, data, mutation):
    with pytest.raises(TapeoutError):
        parse(mutation(data), backend, "run1")


def test_sta_pass():
    r = parse(sta(), "opensta", "run1")
    assert r["status"] == "pass"
    assert r["metrics"]["setup_worst_slack_ns"] == 7.6
    assert r["metrics"]["hold_worst_slack_ns"] == 0.6
    assert r["metrics"]["wns_ns"] == r["metrics"]["tns_ns"] == 0


@pytest.mark.parametrize("changes,rule", [({"setup": -1.5}, "STA.SETUP"),
    ({"hold": -0.1}, "STA.HOLD"), ({"constraints": 0}, "STA.CONSTRAINTS")])
def test_sta_failures(changes, rule):
    r = parse(sta(**changes), "opensta", "run1")
    assert r["status"] == "fail"
    assert rule in {v["rule"] for v in r["violations"]}


@pytest.mark.parametrize("a,b", [(b"OT_TIME_UNIT ns", b"OT_TIME_UNIT ps"),
    (b"OT_CLOCKS 1", b"OT_CLOCKS 0"), (b"Endpoint: y", b"No paths"),
    (b"7.6 slack (MET)", b"7.6 slack (VIOLATED)"),
    (b"worst slack 7.6", b"worst slack 8.0"), (b"tns 0", b"tns 1"),
    (b"worst slack 7.6", b"worst slack 1e999"), (b"OT_SECTION HOLD_PATHS", b"OT_SECTION OTHER"),
    (b"OT_CONSTRAINTS_OK 1", b"OT_CONSTRAINTS_OK 1\nOT_CONSTRAINTS_OK 1"),
    (b"7.6 slack (MET)", b"1e999 slack (MET)")])
def test_sta_missing_or_contradictory_data(a,b):
    with pytest.raises(TapeoutError):
        parse(sta().replace(a,b), "opensta", "run1")


def test_drc_unknown_rule_and_bad_json():
    marker={"rule":"OTHER", "location":"a", "message":"b", "severity":"error"}
    with pytest.raises(TapeoutError):
        parse(klayout(violations=[marker]), "klayout-drc", "run1")
    for body in ["OT_DATA {}\nOT_DATA {}", "OT_DATA []", "OT_DATA {\"rules\":1,\"rules\":2}", "OT_DATA {}\nOT_OTHER"]:
        with pytest.raises(TapeoutError):
            parse(framed("klayout-drc", body), "klayout-drc", "run1")
