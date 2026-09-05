# Validation record

## v0.2.0 local validation — 2026-09-05

300 tests passed; no failures or skips. Python 3.13.5. Python statement coverage:
1,891 covered of 1,995 statements (94.79%). Scope includes the existing 198 tests
plus 102 new tests for lifecycle controls, capsule integrity/confidentiality,
recipient identity, status expiry/replay, planning, CLI/API access, native parser
failure modes and numerical overflow. Test count is not proof of production safety.

The actual new-suite results, source hashes and tested dependency versions are in
`validation/v0.2.0/summary.json`; the test output is in `validation/v0.2.0/pytest.log`.

Chromium 144.0.7559.96 passed the self-contained synthetic dashboard checks for
navigation, search, evidence inspection, dependencies, what-if planning, comparisons,
delivery lifecycle, approvals, audit, export and mobile-width layout. No JavaScript
errors or horizontal overflow were observed. Screenshot and standalone HTML are
generated artifacts, not committed private workspaces.

## Evidence-selection microbenchmark

`python scripts/benchmark_selection.py`: 20,000 runs, 100 required checks, five
repetitions. Former median 0.299482116 s; indexed median 0.003684737 s; ratio 81.276x.
Outputs were identical. Details and environment are in
`validation/v0.2.0/selection-benchmark.json`.

This compares only latest-run selection against the previous scan algorithm. It
excludes ledger replay, workspace drift hashing, object verification, EDA execution,
network/storage and user interaction. It is not whole-application or commercial
performance evidence. Timings are observations, not CI pass thresholds.

## Remote qualification

The GitHub workflow tests Python 3.11, 3.12 and 3.13, builds packages, enforces 90%
minimum statement coverage, checks publication hygiene and reproduces the synthetic
stale-result gate. A separate Ubuntu 24.04 job installs and executes real Yosys.
Its qualification report and exact tool version are published as a workflow artifact.
**Observed run:** [33962688030](https://github.com/ajayasai/OpenTapeout/actions/runs/33962688030),
commit `a23de6effcdb4748b3feb20d0656c0c9443f50ad`. All four jobs passed: Python
3.11, 3.12, 3.13 and native Yosys. The executed tool was **Yosys 0.33
(git sha1 2584903a060)** on Ubuntu 24.04.4 / Python 3.12.14.
The downloaded workflow artifact is retained as `validation/v0.2.0/yosys-qualification.json`.
It records one successful proof (105 variables, 270 clauses), both stale/drift
checks, zero reused checks after the ECO and a rejected counterexample (exit 1).
This observed result is distinct from merely having a workflow configured.

Yosys acceptance criteria: actual combinational miter proof succeeds; unregistered
RTL edits block; registered ECO invalidates the old proof; the planner reuses no
stale proof; an actual counterexample returns nonzero and cannot release. The
harness fails, rather than skips or fabricates a result, when Yosys is unavailable.
Yosys was not available in the local authoring container, so native execution is
verified in the remote job, not claimed as a local result. The pinned GitHub
actions emitted Node-target deprecation warnings while successfully running on
Node 24; these were runner/action warnings, not failures in the Python test suite.

## Not established

No actual tapeout, sanctioned foundry PDK/DRC/LVS/STA qualification, commercial
head-to-head benchmark, independent security audit, multi-tenant deployment,
HSM signing, real foundry upload or million-event replay qualification was performed.
Docker is provided but was not validated in this upgrade. The managed runner is
not a sandbox. Browser review does not constitute a security audit.

## Historical v0.1.0 records

The original validation files directly under `validation/` remain historical v0.1.0
records (198 tests). They are not the source-hash manifest for v0.2.0. Use the
versioned subdirectory for this upgrade.
