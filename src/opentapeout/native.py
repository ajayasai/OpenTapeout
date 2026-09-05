"""Conservative native Yosys SAT transcript adapter.

Accepts complete ordinary/bounded SAT proof transcripts, not induction logs,
coverage reports, 'sat' model searches, or arbitrary lines containing 'SUCCESS'.
Proof constraints and invocation scripts must be declared inputs to the run.
"""
from __future__ import annotations

import re

from .util import TapeoutError, ensure

SOLVE = re.compile(r"^Solving problem with ([0-9]+) variables and ([0-9]+) clauses\.\.$", re.MULTILINE)
OUTCOME = re.compile(r"^SAT proof finished - (no model found: SUCCESS!|model found: FAIL!)$", re.MULTILINE)
END = re.compile(r"^End of script\. Logfile hash: [0-9a-f]+.*$", re.MULTILINE)
ERROR = re.compile(r"^ERROR:.*$", re.MULTILINE)


def yosys_sat(data: bytes, run_id: str) -> dict:
    from .parsers import SCHEMA, validate_result
    try:
        text = data.decode("utf-8-sig").replace("\r\n", "\n")
    except UnicodeDecodeError as exc:
        raise TapeoutError("Yosys transcript must be UTF-8") from exc
    ensure("\x00" not in text, "NUL in Yosys transcript")
    solves, outcomes, endings = list(SOLVE.finditer(text)), list(OUTCOME.finditer(text)), list(END.finditer(text))
    ensure(re.search(r"^Import proof-constraint: .+ = .+$", text, re.MULTILINE),
           "An explicit SAT proof constraint is required; vacuous/unsupported proof modes are not accepted")
    ensure(bool(solves) and bool(outcomes), "No completed SAT proofs in transcript")
    # A complete report must pair every solver invocation with a terminal result.
    complete = (len(solves) == len(outcomes) and len(endings) == 1 and not ERROR.search(text))
    if complete:
        for i, (solve, outcome) in enumerate(zip(solves, outcomes)):
            complete &= solve.end() < outcome.start() < endings[0].start()
            if i + 1 < len(solves):
                complete &= outcome.end() < solves[i+1].start()
    failures = [i for i, match in enumerate(outcomes) if match.group(1) == "model found: FAIL!"]
    try:
        metrics = {"proofs_passed": len(outcomes) - len(failures), "proofs_failed": len(failures),
                   "proofs_total": len(outcomes), "problems_started": len(solves),
                   "sat_variables": sum(int(m.group(1)) for m in solves),
                   "sat_clauses": sum(int(m.group(2)) for m in solves)}
    except ValueError as exc:
        raise TapeoutError("Invalid Yosys solver counts") from exc
    result = {"schema": SCHEMA, "run_id": run_id,
              "status": "unknown" if not complete else "fail" if failures else "pass",
              "complete": bool(complete), "metrics": metrics,
              "violations": [{"rule": "yosys.sat.counterexample", "location": f"proof#{i+1}",
                              "message": "SAT solver found a counterexample to the configured proof constraint",
                              "severity": "error"} for i in failures]}
    return validate_result(result, run_id)
