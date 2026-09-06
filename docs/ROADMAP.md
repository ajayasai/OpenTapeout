# Roadmap and acceptance criteria

## Delivered in v0.4.0

Optional project-scoped API with verified RS256 access-token identity, explicit
permissions, detached Ed25519 commands, atomic checkpoint compare-and-swap,
idempotent retries, historical receipts and hash-bound audit pages. Real HTTPS,
thread/process concurrency, authorization rollback and process-death tests run
against synthetic evidence. This is not interactive SSO, adversarial multi-tenant
isolation or distributed storage. See TEAM_API.md and VALIDATION.md.

## Delivered in v0.3.0

Exact-input policy v2, tool/format allowlists, executable SHA-256 checks, reviewed
policy-lock generation and framed physical collectors. The native qualification
harness includes KLayout DRC/LVS and two OpenSTA library cases with defects and
offline archive verification. See VALIDATION.md for observed execution. These
cell-scale examples are not an end-to-end production chip release.

## Delivered in v0.2.0

Exact disclosure allowlists and minimal signed delivery capsules; designated-recipient
signed receipts; per-approval revocation; irreversible signed release withdrawal;
short-lived offline status with caller-retained anti-replay sequence; read-only
rebuild planning and metric comparisons; an indexed evidence selector; conservative
native Yosys SAT parsing and a real-executable CI qualification harness. See the
validation report for what was actually run, rather than interpreting this list as
production qualification.

## P0 — qualify physical flows

Sanctioned OpenROAD/OpenSTA/KLayout and licensed vendor/version adapters, explicit
rule and corner coverage, complete real-design release plus ECO invalidation, parser
fuzzing, process-cancellation/TOCTOU tests and independent security review. The native
Yosys and physical microflows do not meet these full-chip signoff goals.

## P1 — enterprise trust and deployment

OIDC-backed runner identity, enterprise SSO deployment and external-provider interoperability,
per-artifact authorization, read-access audit, remote/HSM signing, independent
status distribution and real foundry receipt integration. A recipient signature is
not yet a foundry API acknowledgment. Disclosure allowlists are not legal compliance.

## P2 — distributed scale and interoperability

PostgreSQL/distributed concurrency beyond the tested local SQLite gateway, pluggable object storage, cache/snapshot-backed
replay and recovery drills; benchmarks with million-event ledgers and realistic
large artifacts. The selector optimization does not solve full-history replay or
rehashing costs. Qualify a documented hardware BOM exchange schema and actual
OpenWaiver interoperability before claiming standards/vendor compatibility.

## P3 — workflow breadth

Multi-project dashboards, scheduler integration, auditable dependency extraction,
role-specific review queues and careful selective approval invalidation. Preserve
explicit input declarations and fail-closed behavior; no AI-generated signoff
assertions, wildcard waivers, forced release bypass or private keys in the browser.
