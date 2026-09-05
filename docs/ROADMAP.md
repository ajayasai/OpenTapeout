# Roadmap and acceptance criteria

This is a roadmap, not a list of delivered features.

## P0 — validate on real flows before production release

Qualify report adapters using sanctioned OpenROAD/OpenSTA/KLayout and licensed vendor/version reports. Add coverage/completion checks for the specific configured rules and corners. Demonstrate a full real-design release and ECO invalidation without false-fresh evidence. Perform independent security review, parser fuzzing, process-cancellation/TOCTOU tests, cross-platform testing, and crash/recovery drills.

## P1 — confidentiality and authenticated operations

Add a minimal delivery-only package that excludes private evidence by an explicit disclosure policy, authenticated foundry-upload receipt integrations, remote signing/HSM support, OIDC-backed runner attestations, enterprise SSO and independently authenticated reviewer identities. Introduce permission-scoped authenticated write APIs only after authorization and concurrency review. Preserve the current no-private-keys-in-browser design.

## P2 — interoperability and scale

Qualify native tool/version adapters, OpenWaiver interoperability against its actual schema, declarative IP/BOM import/export, pluggable object storage, signed external checkpoint destinations, snapshot-backed event replay, and PostgreSQL/multi-user concurrency. Benchmark release-scale objects and >1 million events; current in-memory replay and full rehash costs are not claimed to scale to that workload.

## P3 — product workflows

Add approval-specific revocation, explicit release withdrawal events, multi-project dashboards, scheduler integration, role-specific review experiences, automated graph extraction with auditable manual overrides, and careful selective invalidation to reduce conservative false-stale approvals.

## Avoided shortcuts

No blanket “all commercial tools are worse” claims, AI-generated signoff assertions, hidden fallback from a failed run to an older pass, broad wildcard waivers, magic “force release” bypass, built-in universal signing key, mutation over an unauthenticated browser API, or public upload of proprietary input data.
