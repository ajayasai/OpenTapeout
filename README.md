# OpenTapeout

### Every signoff result belongs to an exact design. Know when it stops belonging.

[![Tests](https://github.com/ajayasai/OpenTapeout/actions/workflows/ci.yml/badge.svg)](https://github.com/ajayasai/OpenTapeout/actions/workflows/ci.yml)

**v0.4.0 alpha — Apache-2.0.** An offline-first tapeout evidence and release ledger:
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

## What changed in v0.4

**A project-scoped team review API, not just another report adapter.** Compatible
OAuth access tokens establish identity; external project permissions grant access;
detached Ed25519 commands authorize exact changes. Reviewer private keys stay on
client machines. The gateway can create candidates, accept independent approvals,
revoke reviews and withdraw releases. It cannot execute EDA tools or change policy.

Each command binds the project, ledger sequence/hash, governance digest and a
five-minute validity window. Mutation and durable retry receipt commit in one
transaction. Concurrent writers receive explicit conflicts, never silent overwrite.
Policy, access and key changes are rechecked before commit. Audit pagination uses
hash-bound cursors, and lost responses can be recovered as historical receipts.

```bash
python -m pip install '.[team]'
# Requires independently provisioned identity, project configuration and TLS:
opentapeout serve-team --config /etc/opentapeout/team.json \
  --ssl-certfile /etc/opentapeout/tls.crt --ssl-keyfile /etc/opentapeout/tls.key
```

Read [team deployment, permissions and client commands](docs/TEAM_API.md).
This is an OAuth access-token resource server, **not a turnkey browser SSO login**.
The original dashboard remains read-only. Project-level API isolation is not OS,
container or per-artifact isolation. Local filesystem administrators remain trusted.

The v0.3 [exact-input policy](docs/POLICY_V2.md), executable identity checks and
[native physical collectors](docs/PHYSICAL_QUALIFICATION.md) remain available.

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
python -m pip install '.[web,dev,team]'
pytest --cov=opentapeout --cov-report=term-missing
python -m build
# Requires actual tools; missing executables are errors, not skipped passes.
python scripts/qualify_yosys.py --output yosys-qualification.json
python scripts/qualify_physical.py --output physical-qualification.json
```

The v0.4 upgrade adds real-token, real-signature team tests, concurrent-thread and
process races, real process-crash rollback, and a live HTTPS qualification harness.
Run `python scripts/qualify_team.py --output team-qualification.json` after installing
`.[team]`. Current observed counts and coverage are recorded in the validation report.
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
signoff modes and corners, turnkey IdP/browser SSO integration and per-artifact authorization beyond the new
project-scoped team gateway, distributed storage and million-event replay, hardware-backed signing, independent
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
