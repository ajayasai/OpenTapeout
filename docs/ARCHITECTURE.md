# Architecture and invariants

## Data flow

`Files / directory trees / Git / metadata -> resource DAG -> run-start snapshot -> completed evidence -> signed waivers -> frozen candidate -> role approvals -> gated signed ZIP64 release -> checksum receipt`

The Python package is the authoritative implementation. The CLI calls the same application API. The web surface is deliberately read-only and contains no signing keys. There is no hosted control plane, background scheduler, telemetry or external database requirement.

## Storage

A workspace contains `.opentapeout/ledger.sqlite3` (SQLite WAL) and `.opentapeout/objects/sha256/<prefix>/<suffix>` (content-addressed regular files). Raw reports, input files, captured directory files, metadata and execution logs are hashed in bounded-size chunks. Existing CAS objects are verified rather than trusted by their names. Object writes may precede a ledger transaction; a rolled-back operation can leave an unreferenced object but cannot leave an authorized release. Garbage collection is intentionally not provided yet.

Events contain sequence, previous hash, actor label, timestamp, event type and payload. Their SHA-256 uses project-canonical JSON v1. `BEGIN IMMEDIATE` serializes read-validate-write mutations, avoiding a race between gate evaluation and approval registration. Event replay verifies the sequence and chain on every transaction. SQL triggers reject update/delete operations. A database administrator can remove the triggers; they are accident guards, not a security boundary. Signed external checkpoints protect their anchored prefix.

No mutable projections can silently disagree with the ledger: state is replayed from events. The tradeoff is replay cost proportional to event count. SQLite is a single-writer, single-workspace implementation, not a globally replicated multi-tenant database.

## Resource and freshness model

Each resource records kind, SHA-256, byte size, relative path or metadata, dependency IDs, and the effective dependency fingerprints against which it was built. Its effective fingerprint is the hash of that record plus current effective dependency fingerprints. Kahn topological traversal detects cycles and avoids call-stack limits on deep IP graphs.

Run start captures the complete closure of declared roots, including tool and corner resources. Run completion compares the closure and on-disk bytes to the snapshot. A run observed with changed inputs remains blocked even if those files are restored later. Gate evaluation also compares current bytes and current graph state: timestamps alone cannot rescue stale evidence.

For a derived netlist, merely updating the RTL record does not regenerate the netlist. Its `built_from` pins retain the old dependency fingerprints. Dependent results are stale, and a new run using that obsolete netlist is rejected. The tool does not prove that an operator actually rebuilt an artifact before deliberately re-registering its provenance; that is within the trusted capture boundary.

Scope selection uses the latest **started** run for each policy check/corner. An older run completing later cannot override it. A new failed or incomplete run cannot fall back to an older success.

## Approval and release model

The candidate is an immutable content snapshot, not a mutable branch label. All project resources are currently included conservatively, including unrelated additions; this can invalidate more approvals than strictly necessary. Review policy and external trust store digests are bound to the candidate. Waivers are specific to a completed run digest and violation fingerprint, signed by a different principal from the owner, and reevaluated for expiry/revocation.

Approvals bind the candidate digest and role. The release gate validates signatures and finds a distinct-principal role assignment using augmenting-path bipartite matching. Two keys for one principal do not count as two people. Local actor labels are not authenticated identities; production deployments must authenticate the runner and preserve separation of duties outside the local CLI.

Sealing rechecks the live gate, streams verified objects into a signed archive, verifies the archive independently, rechecks the gate again, and records the archive checksum under the writer lock. Archive member metadata, order and uncompressed bytes are deterministic for the same frozen manifest/signature. Independently repeated sealing invocations have different timestamps and are not promised to be byte-identical. A crash between ledger commit and final archive publication can leave a recorded checksum plus a `.release-*.zip` recovery file; no distributed transaction across SQLite and the filesystem is claimed.

## Verification boundary

The offline verifier accepts external policy and trust, checks all archive members without extracting them, rejects duplicates/traversal/symlinks/encryption/compression/unexpected members, validates the signed manifest, checks every object hash and delivery alias, and reevaluates the gate at sealing time. Current trust-key revocation is honored. Verification of an old archive is a historical statement, not current-design readiness.

The producer is trusted to provide truthful tool/version metadata and complete declarations. No mathematical proof of silicon correctness, RFC 8785 compliance, SLSA level, DSSE interoperability, blockchain immutability, trusted timestamping or regulatory certification is claimed.
