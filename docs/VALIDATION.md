# Validation record

## v0.4.0 — observed 2026-09-06

**574 local tests passed, no failures or skips**, including 165 new team tests.
Python 3.13.5 statement coverage: **2,648 / 2,756 statements (96.08%)**.
The four new team modules have 100% statement coverage in this run; that is not
branch coverage, security assurance, or independent review. Raw test output,
dependency versions, code hashes and HTTPS results are in `validation/v0.4.0/`.

The added tests exercise real RSA access-token and Ed25519 command signatures,
wrong issuer/audience/client/type, expired and malformed tokens, untrusted JWT
key URLs, principal impersonation, project isolation, read/write/audit permissions,
revocation, exact checkpoint/governance conflicts, retry durability, pagination,
HTTPS defaults and safe failures. Existing 409 tests remain in the suite.

Eight competing threads produce exactly one committed mutation and seven explicit
conflicts; four competing processes produce one commit and three conflicts. Eight
retries of identical signed bytes produce one mutation and identical receipts. A
real child process terminated with `os._exit(23)` after candidate insertion and
before receipt/commit leaves neither partial state nor a consumed request ID;
retry after reopening succeeds. Injected governance changes and token expiry during
validation roll back the entire transaction.

### Observed live HTTPS workflow

`python scripts/qualify_team.py --output team-qualification.json` starts a real
Uvicorn subprocess, creates an ephemeral TLS certificate and RSA test issuer,
and sends signed requests through the normal HTTPS client. The client rejects
the untrusted certificate, then verifies the explicitly trusted certificate.
A candidate is created, two distinct reviewers approve it, the resulting full
archive verifies offline, one of eight competing HTTP writes commits while seven
return HTTP 409, and revoking a review blocks the live gate. Reviewer private
keys remain in the test client process, not API request bodies.

The issuer and EDA evidence are synthetic. This test is not a production IdP,
enterprise SSO, hardware-key, external-network, load or penetration test. The
existing read-only dashboard was not redesigned in v0.4. No new browser usability
claim is inferred from API tests. Native Yosys and physical CI jobs are retained;
versioned v0.3 native observations below remain historical until a newer run is
explicitly recorded. A configured workflow is not by itself a passing run.

### Remaining qualification boundaries

No commercial head-to-head trial, production tapeout, external IdP deployment,
independent security audit, per-artifact permissions, hostile-tenant isolation,
geo-restriction, distributed database/storage, million-event replay, HSM signing
or real foundry API acceptance was established. Governance reloads are not an
atomic transaction with operator filesystem changes or IdP sessions. Full-history
replay remains on every request. Existing local CLI operators retain filesystem
trust; the gateway does not turn a shared writable filesystem into a security
boundary. Docker was not tested in this upgrade.

## v0.3.0 — observed 2026-09-05

**409 local tests passed, no failures or skips.** Python 3.13.5. Python statement
coverage is **2,122 of 2,230 statements (95.16%)**. The 109 new tests cover exact
input/tool/corner policy binding, canonical definitions, executable identity,
review-only policy drafts, stdout/stderr capture, nonvacuous physical reports,
missing constraints, malformed numbers and contradictory or swapped timing modes.
This is statement coverage, not branch coverage, native tool coverage or proof of safety.

The source hashes and dependency versions are in `validation/v0.3.0/summary.json`;
raw local test output is in `validation/v0.3.0/pytest.log`. A clean installed wheel
reported version 0.3.0 and reproduced the synthetic stale-netlist gate with exit 2
and CANDIDATE_CHANGED, DERIVATION_STALE and RESULT_STALE blockers. Source compilation,
package building and the repository's heuristic publication scan also passed.
The heuristic scan is not a comprehensive secret scanner or security audit.

Chromium 144.0.7559.96 passed the synthetic dashboard checks for navigation, search,
evidence inspection, dependencies, planning, candidate comparison, delivery status,
approvals, audit and export. No JavaScript errors or horizontal overflow were
observed at the tested desktop/mobile sizes. See `validation/v0.3.0/browser.json`.
The browser is still read-only; these checks do not qualify multi-user writes.

## Remote native qualification

**All five jobs passed** in [CI run 33970046491](https://github.com/ajayasai/OpenTapeout/actions/runs/33970046491)
at commit `3151525fa9055d8dcd2741ba0441e57c122f79ef`: Python 3.11, 3.12 and 3.13,
real Yosys SAT qualification, and real KLayout DRC/LVS plus OpenSTA qualification.
The Python jobs also built distributions and enforced a minimum 90% statement
coverage. Native execution was observed in GitHub CI, not the local authoring container.

The physical job used **KLayout 0.28.16** and **OpenSTA 3.1.0**. The installer
verified exact upstream OpenSTA/CUDD commits and invoked KLayout's actual ELF
executable `/usr/lib/klayout/klayout`, not the 78-byte `/usr/bin/klayout` shell
wrapper. It captured before/after launcher SHA-256 values. Shared libraries,
plugins and environment dependencies are not covered by that single hash.
The recorded tool versions are observations, not assertions that they are the newest.

The workflow artifact was downloaded and its ZIP SHA-256 matched GitHub's artifact
digest. The exact JSON is retained in `validation/v0.3.0/physical-qualification.json`.
The source commit, run, artifact ID/digest and upstream pins are recorded separately
in `validation/v0.3.0/native-provenance.json` so the observations remain attributable.

| Executed test | Observed result |
|---|---|
| Native width/spacing checks | Two named rules executed; one resistor shape; zero violations in the positive control. |
| Native extracted-netlist comparison | One device and two nets in each netlist; comparison matched. |
| Timing with educational typical library | Setup worst slack approximately +7.600 ns; hold approximately +0.400 ns. |
| Timing with separate educational slow library | Setup approximately +7.300 ns; hold approximately +0.700 ns. |
| Unregistered layout change | WORKSPACE_DRIFT blocked the old candidate. |
| Registered layout ECO | RESULT_STALE invalidated the old evidence. |
| Introduced width defect | One native WIDTH violation; fresh focused candidate blocked by metric and violation checks. |
| Reference resistance changed from 500 to 750 ohms | Native LVS mismatch; fresh focused candidate blocked. |
| Clock period shortened from 10 to 1 ns | Native setup slack approximately -1.400 ns; fresh focused candidate blocked. |
| Output constraints removed | Candidate blocked by unknown/incomplete evidence and missing required metrics, not accepted as zero slack. |
| Signed full-evidence archive | Positive exact-policy candidate approved by two distinct reviewer keys, sealed, then verified offline against external policy/trust. |

The negative candidates used current pins and evaluated evidence without requiring
approvals solely to isolate the failure cause. They did not fail merely because
of old hashes or missing signatures. The normal positive candidate still required
two authorized reviewers. See the harness for these explicit assertions.

These are **separate cell-scale educational physical and timing microflows**, not
one chip taken from RTL through foundry signoff. The resistor technology, Liberty
values and constraints are original examples, not a qualified PDK or measured
silicon characterization. No licensed commercial engine was installed or compared.

## Development failures preserved in CI

Earlier development runs caught a missing Ubuntu OpenSTA package, old CUDD
Autotools requirements, missing Flex development headers, incorrect KLayout
plain-text script extensions and unsupported OpenSTA min/max summary labels.
Those failures did not pass the gate. The installer/collectors were corrected and
the regression suite expanded. An initial successful native run (33969715603)
hashed the KLayout wrapper; the subsequent run above strengthened the invocation
to hash the ELF executable. Compiler and action-runtime deprecation warnings were
observed; a passing workflow is not a claim of warning-free builds.

## Not established

No production tapeout, sanctioned full-chip multi-mode/multi-corner PDK signoff,
Calibre/IC Validator/PrimeTime/Tempus qualification, commercial head-to-head
benchmark, independent security audit, multi-tenant deployment, distributed
million-event replay, HSM signing or real foundry API acceptance was performed.
Docker remains provided but unvalidated in this upgrade. The runner is not a
sandbox; pinning does not defeat a hostile administrator, infer every input or
make the runtime hermetic. Native collector success does not certify manufacturing.

## Historical records

v0.2.0 records remain in `validation/v0.2.0/` (300 tests, 94.79% statement coverage,
real Yosys qualification). Its 20,000-run/100-check benchmark measured about 81.3x
improvement only in latest-run selection versus our earlier repeated-scan code,
not end-to-end or vendor performance. Original files directly in `validation/`
remain historical v0.1.0 observations (198 tests), not current source hashes.
