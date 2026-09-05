# OpenTapeout

### Every signoff result belongs to an exact design. Know when it stops belonging.

[![Tests](https://github.com/ajayasai/OpenTapeout/actions/workflows/ci.yml/badge.svg)](https://github.com/ajayasai/OpenTapeout/actions/workflows/ci.yml)

**v0.3.0 alpha — Apache-2.0.** An offline-first tapeout evidence and release ledger:
content-addressed inputs, dependency-aware freshness, exact-input policies, signed
reviewer decisions, controlled deliveries and verifiable release history.

This is evidence software, not a replacement for DRC/LVS/STA engines or a certified
signoff system. Commercial head-to-head evaluation and production foundry
qualification remain outstanding. Native tool tests use original educational
microflows; they are not a complete industrial chip release.

## Run the dashboard

With Python 3.11+ and Git:

```bash
git clone https://github.com/ajayasai/OpenTapeout.git
cd OpenTapeout
python -m pip install '.[web]'
opentapeout demo /tmp/opentapeout-demo --stale
opentapeout --root /tmp/opentapeout-demo serve
```

Open `http://127.0.0.1:8080`. Omit `--stale` for a passing synthetic example. Demo
keys are generated locally; never use them in production. The dashboard is read-only:
private signing keys stay outside the browser. `plan RC-001 --changed rtl` explains
hypothetical rebuilds without executing tools or authorizing release.

## What changed in v0.3

| Capability | Implemented behavior |
|---|---|
| Exact-input policy | Requires particular resource IDs and SHA-256 pins, allowed tool IDs, exact corner definitions and report formats, beyond merely requiring some resource of the right kind. |
| Executable identity | A registered launcher SHA-256 is checked before execution and afterward; mismatches block. The observed identity is preserved in evidence and checked by policy. |
| Reviewed policy locks | `pin-policy` produces a separate v2 review draft from fresh managed runs. It never overwrites active policy, changes the ledger or approves a release. |
| Native stdout capture | Captures tool stdout directly by hash; physical adapters are bound to their check kinds. Native diagnostics or nonempty stderr cannot silently become success. |
| Physical collectors | Narrow KLayout DRC/LVS and OpenSTA setup/hold protocols with explicit completion, named rules, nonempty geometry/netlists/paths, finite metrics and consistency checks. |
| Native qualification | Separate CI microflows exercise actual geometry checks, extracted-netlist comparison, two timing libraries, stale input detection, deliberate defects and signed offline archive verification. |

Read [exact policy migration and trust boundaries](docs/POLICY_V2.md),
[physical collectors and qualification scope](docs/PHYSICAL_QUALIFICATION.md), and
[observed validation](docs/VALIDATION.md). A configured workflow is not by itself a
passed qualification. The v1 policy and existing workflows remain supported.

## Core release controls

The ledger captures Git commits and recursive submodule pins, IP revisions, PDK
files or directory trees, tool versions/arguments, corner definitions, reports,
stdout/stderr, waivers, approvals, release notes and GDS/OASIS delivery hashes.
Direct or transitive input changes invalidate affected evidence. A new LVS report
cannot bless a netlist built against obsolete RTL. Unregistered file edits are
also detected.

Policies enforce required check/corner coverage, metrics and units, evidence age,
managed execution, provenance and separate authorized reviewers. The latest
failing or unfinished run cannot fall back to an older pass. Waivers cover exact
evidence and violations, with rationale, expiry and signatures. Reviewers can revoke
their own approval; a separate administrative role is required to revoke another's.
Sealed releases can be irreversibly withdrawn without deleting historical evidence.

The dashboard provides evidence drill-down, dependency impact, candidate comparison,
rebuild planning, delivery status and audit inspection. Plans are advisory and depend
on accurate declared dependencies. Reusable evidence does not automatically preserve
approval of a changed candidate.

## Exact configuration before release

Register reviewed tool metadata with `executable_sha256`, actual inputs, collector
scripts and corners; capture managed runs, then create a separate policy draft:

```bash
opentapeout --root ./workspace pin-policy --output ./policy.review.json
# Independently review the pins, rule coverage, metric units and runtime.
# Use the reviewed policy explicitly to create and approve a NEW candidate.
```

Never regenerate the authorization policy automatically just to match a changed
design. Executable hashing is not hermetic execution, sandboxing, dependency
discovery or protection against a hostile administrator. Shared libraries, plugins,
startup scripts, child tools and environment settings need separate control.

## Separate private evidence from delivery bytes

```bash
opentapeout --root ./workspace seal RC-001 /secure/full-evidence.zip --key /secure/release.pem
opentapeout --root ./workspace disclosure RC-001 --recipient foundry-review --output disclosure.json
# Review the recipient, exact file allowlist, hashes and disclosure obligations.
opentapeout --root ./workspace deliver RC-001 DELIVERY-001 ./delivery.zip \
  --disclosure disclosure.json --key /secure/release.pem
opentapeout --trust /secure/trust.json verify-delivery ./delivery.zip --disclosure disclosure.json
```

Full evidence archives can contain confidential RTL, IP, PDK material and logs.
Keep them out of public repositories. Minimal capsules contain only explicitly
allowlisted delivery files and small signed metadata, with recipient binding and a
byte budget. The designated recipient can sign the exact archive and manifest
hashes. This is a byte acknowledgment, **not independent foundry acceptance**.
Minimal verification cannot recheck evidence that was deliberately withheld.

Full archives can be verified offline using independently supplied policy and keys.
Short-lived signed status snapshots add revocation/withdrawal checking; the caller
must retain a sequence high-water mark independently to reject older snapshots.
Verification without current status is historical verification at sealing time.
See [v0.2 lifecycle commands](docs/UPGRADE_V0_2.md) for the retained delivery workflow.

## Test and reproduce native checks

```bash
python -m pip install '.[web,dev]'
pytest --cov=opentapeout --cov-report=term-missing
python -m build
# Requires actual tools; missing executables are errors, not skipped passes.
python scripts/qualify_yosys.py --output yosys-qualification.json
python scripts/qualify_physical.py --output physical-qualification.json
```

The local v0.3 suite has 409 passing tests and 95.16% Python statement coverage.
The separate native CI jobs test real tools, not only hand-authored parser fixtures.
See [validation records](docs/VALIDATION.md) for exact versions, results and limits.
The earlier 81.3x measurement concerned only latest-run selection versus our own
old scan algorithm; it was not end-to-end performance or a vendor comparison.

## Where the evidence stops

No claim of superiority over every commercial product is established. Perforce
IPLM, Keysight SOS and Siemens lifecycle offerings have documented enterprise
capabilities beyond this application's tested scope. [Competitive scope](docs/COMPETITIVE_SCOPE.md)
distinguishes advertised vendor capabilities, tested OpenTapeout behavior and unknowns.

Outstanding work includes full-chip/PDK and proprietary-tool qualification, complete
signoff modes and corners, enterprise SSO and permission-scoped multi-user writes,
distributed storage and million-event replay, hardware-backed signing, independent
security review and real foundry-service integration. Dependency ranges are not an
environment lock. The managed runner is not a sandbox. A hash and signature do not
prove correct manufacturing geometry or truthful tool execution.

## Documentation and license

[Quickstart](docs/QUICKSTART.md) · [Exact policy](docs/POLICY_V2.md) ·
[Physical collectors](docs/PHYSICAL_QUALIFICATION.md) · [Existing adapters](docs/ADAPTERS.md) ·
[Architecture](docs/ARCHITECTURE.md) · [Security](SECURITY.md) · [Roadmap](docs/ROADMAP.md)

Generate a self-contained synthetic review with `python scripts/build_demo_preview.py`;
check it with `python scripts/check_demo_browser.py`. Generated previews, real design
workspaces and private keys are not committed. No licensed PDK or production design
is shipped. External tools retain their own licenses. OpenTapeout source and original
examples: Apache-2.0, copyright 2026 OpenTapeout contributors. See [CONTRIBUTING.md](CONTRIBUTING.md).
