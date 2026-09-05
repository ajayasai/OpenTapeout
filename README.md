# OpenTapeout

### Every signoff result belongs to an exact design. Know when it stops belonging.

[![Tests](https://github.com/ajayasai/OpenTapeout/actions/workflows/ci.yml/badge.svg)](https://github.com/ajayasai/OpenTapeout/actions/workflows/ci.yml)

**v0.2.0 alpha — Apache-2.0.** Offline-first tapeout evidence, dependency-aware release gates, signed reviewer decisions, minimal delivery capsules and verifiable release history. Public source: [ajayasai/OpenTapeout](https://github.com/ajayasai/OpenTapeout).

This is release-evidence software, not a DRC/LVS/STA implementation or a certified signoff system. Real foundry qualification and commercial head-to-head evaluation remain outstanding. Synthetic examples are labeled; the separate Yosys CI job executes an actual combinational proof and counterexample, not a fabricated passing report.

## Start the dashboard

With Python 3.11+ and Git:

```bash
git clone https://github.com/ajayasai/OpenTapeout.git
cd OpenTapeout
python -m pip install '.[web]'
opentapeout demo /tmp/opentapeout-demo --stale
opentapeout --root /tmp/opentapeout-demo serve
```

Open `http://127.0.0.1:8080`. Omit `--stale` for a fresh, passing synthetic example. Demo keys are generated locally and must never be reused in production. The browser is read-only: signing keys remain outside it.

## What's new in v0.2.0

| Capability | Behavior |
|---|---|
| Change planning | Read-only, hypothetical or observed ECO analysis; topological rebuild waves; reuse, rerun, wait and repair recommendations. Corrupt reports are never advertised as reusable. |
| Candidate comparison | Immutable resource changes, check transitions and numerical metric deltas; no unsupported assumption that a larger number is better. |
| Minimal disclosure | Exact file-and-SHA-256 allowlist, recipient binding, byte budget and portable aliases. Capsules contain only selected delivery bytes and small signed metadata, not private reports, RTL, PDKs or release notes. |
| Recipient acknowledgment | The designated recipient verifies a capsule and signs its exact archive/manifest hashes. Wrong-recipient and changed-byte receipts are rejected. No network upload or independent foundry attestation is implied. |
| Approval revocation | An individual reviewer can revoke their own exact approval; an explicitly authorized `release-admin` can revoke another reviewer's approval. Other signatures and original history remain intact. |
| Release withdrawal | Signed, irreversible withdrawal of a sealed release. The live gate blocks it; historical archives are preserved. |
| Offline status | Short-lived signed revocation/withdrawal snapshots, project scope, expiry and caller-retained minimum-sequence anti-replay checks. |
| Native proof capture | Conservative `yosys-sat` adapter for explicit `sat -prove SIGNAL VALUE` transcripts. Missing constraints, incomplete/mixed output and errors cannot establish success. |
| Faster evidence selection | Indexed latest-run selection replaces repeated scans, preserving the no-fallback rule. Measured separately from ledger replay and file hashing. |

See [upgrade guide and commands](docs/UPGRADE_V0_2.md) and [validation](docs/VALIDATION.md).

## Core evidence controls

The existing content-addressed ledger still captures Git commits and recursive submodule pins, hashed PDK files or directory trees, IP revisions, tool versions and argv, corner definitions, reports, stdout/stderr, waivers, approvals, GDS/OASIS delivery hashes and release notes. Direct or transitive input changes invalidate affected evidence. A new report cannot bless a netlist derived from obsolete RTL. Unregistered on-disk changes are detected too.

Release policies require check/corner coverage, input kinds, finite metric thresholds, evidence age, managed execution, clean Git provenance, hashed PDKs and distinct authorized reviewers. Unknown/incomplete runs, nonzero exits and the latest failing run cannot silently fall back to an older pass. Waivers remain exact-evidence, exact-violation, expiring, signed and revocable.

Full evidence archives have signed manifests, deterministic ZIP member metadata, streaming artifact hashes and an independent offline verifier supplied with external policy and trust keys. The SQLite event chain and externally retained signed checkpoints make history inspection possible; they do not defeat a hostile administrator who also controls every external trust anchor.

## Plan an ECO without changing anything

```bash
opentapeout --root /tmp/opentapeout-demo plan RC-001 --changed rtl
opentapeout --root /tmp/opentapeout-demo plan RC-001
# On a workspace containing two immutable candidates:
opentapeout --root ./workspace compare RC-001 RC-002
```

Plans are advisory. They do not execute tools, alter inputs, waive violations, renew approvals or authorize release. All results depend on the correctness of the declared dependency graph. Changes may allow reuse of unaffected evidence while still requiring a new candidate and new signatures.

## Separate private evidence from recipient deliveries

```bash
opentapeout --root ./workspace seal RC-001 /secure/full-evidence.zip --key /secure/release.pem
opentapeout --root ./workspace disclosure RC-001 --recipient foundry-review --output disclosure.json
# Review the generated allowlist, hashes, aliases, recipient and disclosure obligations.
opentapeout --root ./workspace deliver RC-001 DELIVERY-001 ./delivery.zip \
  --disclosure disclosure.json --key /secure/release.pem
opentapeout --trust /secure/trust.json verify-delivery ./delivery.zip --disclosure disclosure.json
```

**Full evidence is confidential by default:** it can contain proprietary RTL, IP, PDK material and logs. Keep full archives out of public source repositories. A minimal capsule intentionally withholds that evidence: its verifier establishes approved bytes and sender authorization, **not independent physical signoff or foundry acceptance**. Neither package proves that its bytes are valid manufacturing geometry. Disclosure allowlists do not replace NDA/export/license review.

## Historical verification versus current status

```bash
opentapeout --root ./workspace release-status --key /secure/release.pem --output status.json
opentapeout --policy /secure/policy.json --trust /secure/trust.json verify /secure/full-evidence.zip \
  --status status.json --min-status-seq "$LAST_VERIFIED_SEQUENCE"
```

Retain the last verified sequence in an independent location. A signed status snapshot expires within 24 hours (one hour by default); it cannot reveal events that happened after it was issued. Verification without `--status` remains historical verification at sealing time, not a statement about present release authorization.

## Test and qualify

```bash
python -m pip install '.[web,dev]'
pytest --cov=opentapeout --cov-report=term-missing
python -m build
python scripts/benchmark_selection.py
# Requires an actual Yosys installation; absence is an error, not a skipped pass.
python scripts/qualify_yosys.py --output yosys-qualification.json
```

The v0.2.0 local suite has 300 passing tests and 94.79% Python statement coverage. The reproducible 20,000-run/100-check selection microbenchmark measured 0.2995 s before versus 0.003685 s after (median of five runs, approximately 81.3x). **That is not an end-to-end speedup or a vendor comparison.** See [recorded scope and evidence](docs/VALIDATION.md).

## Scope and next qualification steps

This release does not establish superiority over every commercial product. Perforce IPLM, Keysight SOS and Siemens semiconductor lifecycle products have documented enterprise capabilities outside this application's scope. See [source-backed competitive scope](docs/COMPETITIVE_SCOPE.md) and [roadmap](docs/ROADMAP.md).

Still outstanding: sanctioned native DRC/LVS/STA adapters and PDK coverage, actual tapeout qualification, enterprise SSO and multi-tenant write authorization, distributed object storage, million-event replay benchmarks, independent security review, HSM signing and real foundry API receipts. Dependency ranges are not a hermetic environment lock. The managed runner is not a sandbox or remotely authenticated execution service.

## Documentation and contribution

[Quickstart](docs/QUICKSTART.md) · [v0.2 commands](docs/UPGRADE_V0_2.md) · [Adapters](docs/ADAPTERS.md) · [Architecture](docs/ARCHITECTURE.md) · [Security](docs/SECURITY.md) · [Contributing](CONTRIBUTING.md)

Generate a self-contained synthetic dashboard snapshot with `python scripts/build_demo_preview.py`; browser checks are in `scripts/check_demo_browser.py`. Generated snapshots and screenshots are not committed. No proprietary EDA code, licensed PDK, production design or private signing key is shipped. Apache-2.0; copyright 2026 OpenTapeout contributors.
