"""Reproducible microbenchmark of latest-run selection: former scan vs indexed path.

Not a whole-application or commercial benchmark. Excludes ledger replay, hashing,
EDA execution and object storage; no timing threshold is used as a correctness test.
"""
import argparse
import copy
import json
import platform
import statistics
import time
from types import SimpleNamespace

from opentapeout.engine import scope_view
from opentapeout.policy import check_key
from opentapeout.util import digest


def former_selection(state, candidate, policy, trust):
    runs = {}
    for check in policy["required_checks"]:
        matching = [r for r in state["runs"].values() if check_key(r) == check_key(check)]
        if matching:
            latest = max(matching, key=lambda run: run["sequence"])
            runs[latest["id"]] = copy.deepcopy(latest)
    return {**candidate, "resources": copy.deepcopy(state["resources"]), "runs": runs,
            "waivers": [], "deliveries": [], "policy_sha256": digest(policy), "trust_sha256": trust.sha256}


def benchmark(runs=20000, checks=100, repetitions=5):
    assert runs >= checks > 0 and repetitions > 0
    state = {"resources": {}, "runs": {str(i): {"id": str(i), "sequence": i+1, "kind": "STA", "corner": f"c{i%checks}"}
                                     for i in range(runs)}, "waivers": {}, "revoked_waivers": set()}
    policy = {"required_checks": [{"kind": "STA", "corner": f"c{i}"} for i in range(checks)]}
    candidate, trust = {"deliveries": []}, SimpleNamespace(sha256="0"*64)
    assert former_selection(state, candidate, policy, trust) == scope_view(state, candidate, policy, trust)
    timings = {}
    for name, function in (("former_scan", former_selection), ("indexed_selection", scope_view)):
        samples = []
        for _ in range(repetitions):
            start = time.perf_counter()
            function(state, candidate, policy, trust)
            samples.append(time.perf_counter() - start)
        timings[name] = {"median_seconds": statistics.median(samples), "samples_seconds": samples}
    return {"benchmark": "latest-run-selection-only", "runs": runs, "required_checks": checks,
            "repetitions": repetitions, "python": platform.python_version(), "platform": platform.platform(),
            "identical_outputs": True, "timings": timings,
            "median_speedup": timings["former_scan"]["median_seconds"] / timings["indexed_selection"]["median_seconds"],
            "limitations": "Synthetic in-memory selection only; excludes ledger replay, file hashing, storage and EDA. No vendor comparison."}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runs", type=int, default=20000)
    parser.add_argument("--checks", type=int, default=100)
    parser.add_argument("--repetitions", type=int, default=5)
    args = parser.parse_args()
    print(json.dumps(benchmark(args.runs, args.checks, args.repetitions), indent=2))


if __name__ == "__main__":
    main()
