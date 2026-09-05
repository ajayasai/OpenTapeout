"""Fail-closed adapters. Parsing establishes report contents, not tool honesty.

Every import is separately bound to a captured run, process exit code and raw report
hash. Unknown/incomplete reports can be retained as evidence but cannot pass a gate.
"""
from __future__ import annotations

import csv
import io
import xml.etree.ElementTree as ET

from .util import TapeoutError, digest, ensure, finite_number, loads

SCHEMA = "opentapeout.result/v1"
CHECKS = {"DRC", "LVS", "STA", "CDC", "RDC", "POWER", "FORMAL", "LINT", "ERC", "EMIR"}
MAX_REPORT = 32 * 1024 * 1024


def validate_result(result: dict, run_id: str) -> dict:
    ensure(isinstance(result, dict) and result.get("schema") == SCHEMA, "Unsupported result schema")
    ensure(result.get("run_id") == run_id, "Report run_id does not match captured run")
    ensure(result.get("status") in {"pass", "fail", "unknown"}, "Invalid result status")
    ensure(type(result.get("complete")) is bool, "Result must declare complete as a boolean")
    metrics, violations = result.get("metrics"), result.get("violations")
    ensure(isinstance(metrics, dict) and all(isinstance(k, str) and finite_number(v)
                                            for k, v in metrics.items()), "Metrics must be finite numbers")
    ensure(isinstance(violations, list), "violations must be a list")
    seen, normalized = set(), []
    for violation in violations:
        ensure(isinstance(violation, dict), "Violation must be an object")
        ensure(set(violation) <= {"rule", "location", "message", "severity", "geometry", "fingerprint"},
               "Unknown violation fields")
        for field in ("rule", "location", "message"):
            ensure(isinstance(violation.get(field), str) and bool(violation[field].strip()),
                   f"Violation {field} required")
        ensure(violation.get("severity") in {"error", "warning", "info"}, "Invalid violation severity")
        body = {k: v for k, v in violation.items() if k != "fingerprint"}
        fingerprint = digest(body)
        ensure(violation.get("fingerprint", fingerprint) == fingerprint, "Invalid violation fingerprint")
        ensure(fingerprint not in seen, "Duplicate violation fingerprint; disambiguate location")
        seen.add(fingerprint)
        normalized.append({**body, "fingerprint": fingerprint})
    ensure(not (result["status"] == "pass" and violations), "A passing report cannot contain violations")
    ensure(not (result["status"] == "pass" and not result["complete"]), "Incomplete report cannot pass")
    ensure(set(result) == {"schema", "run_id", "status", "complete", "metrics", "violations"},
           "Result has missing or unknown fields")
    return {**result, "violations": normalized}


def _xml(data: bytes) -> ET.Element:
    # Decode before screening so UTF-16 cannot bypass the DTD/entity prohibition.
    try:
        text = data.decode("utf-8-sig")
        ensure("<!DOCTYPE" not in text.upper() and "<!ENTITY" not in text.upper(),
               "XML DTDs/entities are forbidden")
        return ET.fromstring(text)
    except (UnicodeDecodeError, ET.ParseError) as exc:
        raise TapeoutError("Malformed XML or unsupported encoding; expected UTF-8") from exc


def parse(data: bytes, format_name: str, run_id: str) -> dict:
    ensure(len(data) <= MAX_REPORT, "Report exceeds parser size limit; use a normalized summary")
    if format_name == "json":
        return validate_result(loads(data), run_id)
    result = {"schema": SCHEMA, "run_id": run_id, "status": "pass", "complete": True,
              "metrics": {}, "violations": []}
    if format_name == "junit":
        root = _xml(data)
        ensure(root.tag in {"testsuite", "testsuites"}, "Not a JUnit report")
        tests = list(root.iter("testcase"))
        ensure(bool(tests), "Empty JUnit report cannot establish success")
        # Verify declared counts when present; an arbitrary <testsuite/> is not a pass.
        suites = list(root.iter("testsuite"))
        if root.tag == "testsuites":
            suites.append(root)
        ensure(all(test.get("name", "").strip() for test in tests), "JUnit testcase names are required")
        for suite in suites:
            ensure(not any(child.tag in {"failure", "error", "skipped"} for child in suite),
                   "Suite-level failure/error/skipped must be normalized explicitly")
            cases = list(suite.iter("testcase"))
            counts = {"tests": len(cases), "failures": sum(t.find("failure") is not None for t in cases),
                      "errors": sum(t.find("error") is not None for t in cases),
                      "skipped": sum(t.find("skipped") is not None for t in cases)}
            for field, expected in counts.items():
                if field in suite.attrib:
                    ensure(suite.attrib[field] == str(expected), f"JUnit {field} count mismatch")
        for index, test in enumerate(tests):
            for tag in ("failure", "error", "skipped"):
                failure = test.find(tag)
                if failure is not None:
                    result["violations"].append({"rule": f"junit.{tag}",
                        "location": f"{test.get('classname', 'suite')}/{test.get('name', 'test')}#{index}",
                        "message": failure.get("message") or failure.text or tag, "severity": "error"})
                    if tag == "skipped":
                        result["complete"] = False
        result["metrics"]["tests"] = len(tests)
    elif format_name == "klayout-rdb":
        root = _xml(data)
        ensure(root.tag == "report-database", "Not a KLayout report database")
        ensure(root.find("items") is not None and root.find("categories") is not None
               and root.find("cells") is not None, "Incomplete KLayout RDB structure")
        for index, item in enumerate(root.findall("./items/item")):
            category, cell = item.findtext("category"), item.findtext("cell")
            ensure(bool(category) and bool(cell), "KLayout item missing category/cell")
            values = [v.text or "" for v in item.findall("./values/value")]
            result["violations"].append({"rule": category, "location": f"{cell}#{index}",
                 "message": "; ".join(values) or "DRC marker", "geometry": values, "severity": "error"})
    elif format_name == "csv":
        try:
            reader = csv.DictReader(io.StringIO(data.decode("utf-8-sig")))
            ensure(reader.fieldnames == ["rule", "location", "message", "severity"],
                   "CSV header must be rule,location,message,severity")
            for row in reader:
                ensure(None not in row and all(value is not None for value in row.values()),
                       "Malformed CSV row")
                result["violations"].append(row)
        except (UnicodeDecodeError, csv.Error) as exc:
            raise TapeoutError("Malformed CSV report") from exc
    else:
        raise TapeoutError(f"Unknown report format: {format_name}")
    result["metrics"]["violation_count"] = len(result["violations"])
    if result["violations"]:
        result["status"] = "fail"
    if not result["complete"]:
        result["status"] = "unknown"
    return validate_result(result, run_id)
