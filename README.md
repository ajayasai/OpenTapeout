# OpenTapeout

### Every signoff result belongs to an exact design. Know when it stops belonging.

OpenTapeout is an **offline-first tapeout evidence and release ledger**. It binds DRC, LVS, STA, CDC, power, formal and other results to content-addressed inputs, detects direct and transitive changes, and blocks release when evidence or approvals no longer match.

**Status: v0.1.0 alpha.** Working software with automated adversarial tests, not a certified signoff system. No real foundry tapeout or commercial head-to-head evaluation has been performed. The included demo is visibly synthetic and contains no manufacturing-ready GDS, real PDK, or real EDA results. The application source is published publicly at [ajayasai/OpenTapeout](https://github.com/ajayasai/OpenTapeout).

[![Tests](https://github.com/ajayasai/OpenTapeout/actions/workflows/ci.yml/badge.svg)](https://github.com/ajayasai/OpenTapeout/actions/workflows/ci.yml)

The dashboard ships with the Python package. The commands below launch it locally without a hosted account.

## Try the complete workflow

From the source directory, with Python 3.11+ and Git installed:

```bash
git clone https://github.com/ajayasai/OpenTapeout.git
cd OpenTapeout
python -m pip install '.[web]'
opentapeout demo /tmp/opentapeout-demo
opentapeout --root /tmp/opentapeout-demo serve
```

Open `http://127.0.0.1:8080`. The demo creates six executed **synthetic fixtures**, a real hash-linked ledger, content-addressed objects, a candidate, and two real Ed25519 approval signatures. Demo private keys are generated locally in the demo workspace; they are never shipped in this source repository. Never reuse demo keys in production.

To reproduce the core failure mode:

```bash
opentapeout demo /tmp/opentapeout-stale --stale
opentapeout --root /tmp/opentapeout-stale gate RC-001
# Exit 2: RESULT_STALE, DERIVATION_STALE, CANDIDATE_CHANGED.
# The netlist changed after the evidence was captured.
```

Generate a self-contained, interactive offline snapshot with `python scripts/build_demo_preview.py`, then open the generated `docs/demo.html`. It is a synthetic review snapshot, not a live workspace or an authenticated release. Generated previews, screenshots, and the original bulky JUnit XML are not checked into this repository; their generators and tests are included.

## What works today

| Area | Implemented behavior |
|---|---|
| Input provenance | Streaming SHA-256 file capture; full Git commits, clean-worktree checks and recursive submodule pins; versioned IP; PDK archives/manifests or full directory-tree capture. |
| Stale-result detection | Exact input snapshots at run start; tool/version/argv and corner definitions; transitive dependency fingerprints; persistent input-drift detection at completion; unregistered on-disk edits. |
| Derived artifacts | A netlist built from old RTL remains obsolete even when its bytes have not changed. A new LVS run cannot bless an obsolete derived netlist. |
| Evidence capture | Managed subprocess runner without a shell; timeout/nonzero-exit handling; captured stdout/stderr; raw report hashes; normalized JSON, JUnit, KLayout RDB and strict CSV adapters. |
| Release gates | Required check/corner matrix, input-kind requirements, evidence-age limits, finite numerical thresholds, conservative latest-started-run selection, no fallback to an older passing run. |
| Waivers | Ed25519-signed, exact-evidence/exact-violation scope, rationale, separate owner/reviewer, UTC expiry, attachments, signed revocation. No wildcard waivers. |
| Approvals | External trust store, role authorization, candidate-bound signatures, self-approval prohibition, distinct-principal matching across roles, expiry and key revocation handling. |
| Audit ledger | SQLite single-writer transactions, append-only SQL guards, SHA-256 event chain, signed externally retained checkpoints to detect prefix rewriting/truncation. |
| Release packages | Deterministic ZIP member ordering/metadata, ZIP64 streaming, full evidence, GDS/OASIS delivery aliases, signed manifest, offline verification against caller-supplied policy and keys. |
| Delivery checks | Exact comparison of an operator-supplied foundry-upload SHA-256 with the recorded sealed archive. No foundry upload is performed or independently attested. |
| Review interface | Responsive read-only dashboard, evidence drill-down, dependency impact paths, approvals/waivers, audit history, candidate selection and JSON export. |
| CI | Reusable GitHub Action, Markdown gate summaries, exit-code contract, and a Python-version test workflow. |

The ledger stores and validates evidence; it does **not** implement DRC/LVS/STA, parse manufacturing geometry for correctness, infer every tool input automatically, or certify silicon.

## A real project

Start with the walkthrough in [docs/QUICKSTART.md](docs/QUICKSTART.md). At a minimum:

```bash
opentapeout --root ./workspace init chip-project
# Create reviewer keys OUTSIDE the workspace; distribute only public keys.
opentapeout keygen /secure/alice.pem > alice-public.json
opentapeout --root ./workspace trust-key alice --public alice-public.json --roles physical waiver

opentapeout --root ./workspace capture-git source-commit design
opentapeout --root ./workspace capture-tree pdk technology/pdk --kind pdk --revision vendor-revision-42
opentapeout --root ./workspace register rtl --kind rtl --file design/top.v
opentapeout --root ./workspace register netlist --kind netlist --file build/top.v --depends rtl pdk
```

The default policy requires six checks and two separate reviewers. Deliberately configure the policy to the actual signoff plan, including all required corners and numerical units. Do not weaken it merely to make a status turn green.

For an external EDA runner, use `begin` before execution and `finish` afterward. Imported evidence is explicitly labeled **unmanaged** and is rejected by the default policy. See the [adapter contract](docs/ADAPTERS.md) before connecting vendor tools.

## Signed release and independent verification

```bash
opentapeout --root /tmp/opentapeout-demo seal RC-001 /tmp/evidence.zip \
  --key /tmp/opentapeout-demo/keys/release-engineer.pem

opentapeout --policy /tmp/opentapeout-demo/policy.json \
  --trust /tmp/opentapeout-demo/trust.json verify /tmp/evidence.zip
```

**Confidentiality warning:** full evidence archives can contain RTL, IP, PDK material, tool invocations and logs. Do not upload them to public GitHub or a foundry without reviewing the disclosure and license obligations. The public repository should contain application source and synthetic examples only. A minimal, NDA-aware delivery-only exporter is not implemented in this version.

Offline verification checks artifact bytes, manifest signature, approval authorization and the gate **at sealing time**. It does not prove that today’s design is unchanged, that the EDA tool honestly executed every required rule, or that a foundry accepted an upload.

## Test and build

```bash
python -m pip install '.[web,dev]'
pytest --cov=opentapeout --cov-report=term-missing
python -m build
```

See [validation results](docs/VALIDATION.md), the [security/threat model](docs/SECURITY.md), and the [architecture](docs/ARCHITECTURE.md). Runtime source hashes and tested dependency versions are recorded in the distribution's validation manifest. Dependency ranges are not a hermetic environment lock; production deployments should create an internally reviewed, hash-pinned wheel set.

## Is it better than commercial alternatives?

This release is intentionally strong in one measurable area: inspectable, portable evidence-to-release integrity. It is **not proven superior to every closed-source alternative**. Commercial products have broader IP lifecycle management, EDA integrations, enterprise access control, deployment experience and support. Our capability comparison marks unevaluated vendor behavior as **not assessed**, rather than inventing deficiencies. See [competitive scope](docs/COMPETITIVE_SCOPE.md) and [roadmap](docs/ROADMAP.md).

## Repository and contributions

Public source: [ajayasai/OpenTapeout](https://github.com/ajayasai/OpenTapeout). Use the repository's issue templates for synthetic reproducers and documented adapter requests. See [CONTRIBUTING.md](CONTRIBUTING.md) before sharing data.

`scripts/publish_github.py` is an optional helper for creating a **new** public repository through your own authenticated GitHub CLI. It is not needed to use this already-published project, refuses an existing remote, never force-pushes, and does not replace a confidentiality review. For ordinary contributions, fork this repository and open a pull request instead.

## License

Apache-2.0. Copyright 2026 OpenTapeout contributors. No proprietary EDA code, licensed PDK, or third-party design dataset is included. Contributing instructions and security reporting guidance are in [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
