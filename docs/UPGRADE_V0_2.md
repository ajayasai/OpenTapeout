# v0.2.0 release-control upgrade

## Compatibility

Existing v0.1.0 workspaces and historical archives remain readable. The project,
policy, candidate and full-release schemas remain v1. New ledger event types
record approval revocation, withdrawal, delivery sealing and recipient receipts.
Back up the workspace before upgrading; v0.1.0 deliberately rejects unknown new
event types rather than silently ignoring them. Do not downgrade a mutated ledger.
Maximum policy ages are now capped at 100 years; nonfinite/overflowing numbers and
unbounded process timeouts fail closed. No deployment or database migration is automatic.

## Establish trust before freezing a candidate

Declare all reviewer, release and recipient public keys in the external trust store
before creating the release candidate. Trust-store changes invalidate existing
candidate approval scope; do not add a recipient key afterward and expect old
approvals to remain valid. Private keys belong outside the public repo and browser.

`release` authorizes sealing, withdrawal and status publication. `delivery-receiver`
authorizes receipt signing, but only the exact principal named in the disclosure
policy can acknowledge that delivery. `release-admin` is an explicit override for
revoking someone else's approval; ordinary release keys do not get this privilege.

## Change planning and candidate comparison

```bash
opentapeout --root ./workspace plan RC-001 --changed rtl
opentapeout --root ./workspace plan RC-001
opentapeout --root ./workspace compare RC-001 RC-002
```

The first command is a read-only what-if. Plans show resource rebuild waves,
one causal path per affected resource, missing check configuration, pending latest
runs, reusable evidence and corrupted evidence requiring repair. They never create
runs or approve releases. Fixing a failure may require engineering work, a legitimate
waiver, a corrected capture or a rerun; a rerun is not itself a guarantee of success.

Comparisons are between immutable candidates. Numeric deltas preserve metric names
and units encoded by the integration. They do not guess improvement direction.
Overflowing deltas are reported as null with `delta_overflow: true`.

## Revocation and withdrawal

Find an approval's SHA-256 in `status` / `/api/summary` under `approval_states`.

```bash
opentapeout --root ./workspace revoke-approval APPROVAL_SHA256 \
  --reason 'Physical review must be repeated after a process concern' --key /secure/reviewer.pem
opentapeout --root ./workspace withdraw RC-001 \
  --reason 'Post-release defect requires withdrawal and a replacement release' --key /secure/release.pem
```

Revocation affects one exact signed envelope; it does not erase or rewrite it.
The original reviewer may make a fresh approval if the evidence gate is still valid.
Withdrawal applies to a sealed release and is irreversible. Issue a new candidate
rather than trying to restore the withdrawn one. The old sealed archive remains
historically verifiable, so consumers needing present status must supply a status snapshot.

```bash
opentapeout --root ./workspace release-status --valid-hours 1 \
  --key /secure/release.pem --output status.json
opentapeout --policy /secure/policy.json --trust /secure/trust.json verify /secure/release.zip \
  --status status.json --min-status-seq "$LAST_VERIFIED_SEQUENCE"
```

The minimum sequence is an externally retained high-water mark, not a number
invented by the untrusted archive. Status signatures are project-bound; future,
expired and older-than-minimum snapshots are rejected. Signatures do not prove
that a status publisher has supplied the latest available snapshot. Keep status
validity short and distribute newer snapshots after revocation/withdrawal.

## Minimal recipient-bound delivery

1. Seal the private full-evidence release and retain it under access control.
2. Generate and review an exact allowlist.
3. Sign a separate capsule for the designated recipient.

```bash
opentapeout --root ./workspace disclosure RC-001 --recipient foundry-review --output disclosure.json
opentapeout --root ./workspace deliver RC-001 DELIVERY-001 delivery.zip \
  --disclosure disclosure.json --key /secure/release.pem
opentapeout --trust /secure/trust.json verify-delivery delivery.zip --disclosure disclosure.json
```

Disclosure schema example (replace the placeholder with the actual recorded hash):

```json
{
  "schema": "opentapeout.disclosure/v1",
  "recipient": "foundry-review",
  "max_bytes": 1000000000,
  "files": [{"delivery": "chip.gds", "name": "approved-die.gds", "sha256": "EXACT_64_HEX_ARTIFACT_HASH"}]
}
```

Only declared candidate deliveries can be selected. Unknown fields, empty lists,
duplicate/case-colliding aliases, unsafe paths, reserved names, hash changes and
budget overruns fail. Renaming a GDS file to OASIS is rejected; this is not a converter.
A capsule contains only manifest.json, signature.json and the named delivery files.
No raw private report, source file, invocation, PDK metadata or release note is copied.
Opaque project/candidate/source-release hashes remain as provenance commitments.
The approved layout bytes themselves may contain names or IP: review those bytes.

At the designated recipient, after adding its public key to the agreed trust store
**before the candidate was frozen**:

```bash
opentapeout --trust /secure/trust.json sign-receipt delivery.zip --disclosure disclosure.json \
  --reference 'RECEIVER-ACK-001' --key /secure/recipient.pem --output receipt.json
# Return the signed statement to the sender:
opentapeout --root ./workspace record-receipt receipt.json
```

A receipt is idempotently recorded after checking the recipient, project, timestamp,
manifest and archive hashes. It is a recipient's acknowledgment of bytes, not an
independent foundry API assertion, process acceptance or manufacturing signoff.
The original `receipt` command remains available for explicitly operator-supplied
checksums; it is distinct from this signed-recipient workflow.

## Native Yosys proof capture

Register the actual executable/version/argv and the RTL plus proof script as inputs.
Use `--format yosys-sat` only for a FORMAL run and an explicit `sat -prove SIGNAL VALUE`
proof. Preserve the ordinary Yosys end-of-script footer; do not use `-T` to suppress it.
The adapter rejects missing explicit proof constraints and cannot qualify arbitrary
induction, zero-assertion, cover or pure satisfiability logs. A nonzero process exit
still blocks regardless of parsed content. Never treat a transcript as proof that
a dishonest runner or tool executed correctly.

`python scripts/qualify_yosys.py` requires an actual installed Yosys. It proves a
small combinational miter, changes the RTL, checks both unregistered drift and
registered stale-result detection, then runs a real failing proof and checks release
rejection. This focused policy does not pretend to be the default six-check signoff plan.
