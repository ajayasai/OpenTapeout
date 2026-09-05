# Real-project walkthrough

## 1. Establish the trusted boundary

Use a dedicated Linux workspace, a trusted runner, and a separate clean Git design repository inside the workspace. Install from reviewed source or a verified wheel. Python 3.13/Linux is locally tested; CI is configured for Python 3.11–3.13. A Git working tree is required only when the configured policy requires captured Git provenance.

```bash
python -m pip install '.[web]'
opentapeout --root workspace init aurora
```

The command writes a strict `workspace/policy.json`. Set the actual required corners, evidence validity periods, metric limits/units, and reviewer roles. Power's illustrative 100 mW limit is a template, not a recommendation for your chip. Preserve the policy on a protected branch or read-only deployment mount.

Generate each reviewer's key on their own trusted system, outside project, runner and CI checkout directories. Set `OT_KEY_PASSWORD` to encrypt newly generated PEMs or decrypt existing ones. The CLI does not prompt for passwords and does not log the variable. An unencrypted local key is supported for development; apply restrictive filesystem permissions. Hardware-backed keys and a centralized signing service are not implemented.

```bash
opentapeout keygen /secure/alice.pem > alice-public.json
opentapeout keygen /secure/bob.pem > bob-public.json
opentapeout keygen /secure/release.pem > release-public.json
opentapeout --root workspace trust-key alice --public alice-public.json --roles physical waiver
opentapeout --root workspace trust-key bob --public bob-public.json --roles verification
opentapeout --root workspace trust-key release-service --public release-public.json --roles release
```

This establishes local authorization, not identity proof. A production administrator must independently verify the principal-to-key mapping. Different keys attributed to the same principal cannot satisfy two distinct-reviewer roles.

## 2. Register the complete input graph

Register a clean Git repository and every materially relevant file or directory. Git metadata is not a substitute for artifact-level dependencies.

```bash
opentapeout --root workspace capture-git source-commit design
opentapeout --root workspace capture-tree pdk technology/vendor-pdk --kind pdk --revision rev-42
opentapeout --root workspace register rtl --kind rtl --file design/top.v
opentapeout --root workspace register library --kind library --file technology/cells.lib --depends pdk
opentapeout --root workspace register netlist --kind netlist --file build/top.v --depends rtl library
opentapeout --root workspace register layout --kind layout --file build/top.gds --depends netlist pdk
opentapeout --root workspace register constraints --kind constraints --file design/timing.sdc
opentapeout --root workspace register rules --kind rule_deck --file technology/signoff.drc --depends pdk
opentapeout --root workspace register power-intent --kind power_intent --file design/power.upf
opentapeout --root workspace register nominal --kind corner --metadata @corner.json
opentapeout --root workspace register lvs-tool --kind tool --metadata @lvs-tool.json
```

`corner.json` describes the full process/voltage/temperature/RC/library configuration; register large supporting files separately and add them as dependencies. `lvs-tool.json` records `name`, `version`, and `argv` as an array, not a shell command. Run wrappers and configuration files should themselves be hashed dependencies of the tool resource. Do not place secrets in argv.

`capture-tree` hashes file bytes and paths, stores each file in CAS, rejects symlinks, and detects later additions/deletions/edits. It takes storage proportional to the captured files. Alternatively, register a PDK archive or explicit lockfile; **hashing a lockfile alone does not verify that installed files match it**. Register the used files or capture the actual tree when that guarantee is required.

## 3. Capture execution, not a retrospective timestamp

```bash
opentapeout --root workspace run LVS --inputs netlist layout pdk rules \
  --tool lvs-tool --corner nominal --report reports/lvs.json --format json --timeout 7200
```

The runner checks all declared inputs, creates an immutable run-start snapshot, supplies `OPENTAPEOUT_RUN_ID` and `OPENTAPEOUT_REPORT` to the explicitly registered process, waits for it, captures raw output and the report, and checks for observable input drift. Pre-existing report paths are rejected. The tool wrapper must write its normalized result with the supplied run ID. The runner inherits the host environment and is **not a process sandbox**; use containers/VMs and immutable input mounts for hermetic builds.

For a scheduler you already operate, `begin` prints a run ID. Execute the actual tool with the captured inputs and then `finish RUN_ID --report ... --exit-code ...`. This is marked unmanaged; opt into unmanaged imports only after establishing and documenting an external capture trust boundary.

A failed command, timeout, incomplete report, unknown result, missing metric, stale input or obsolete derived artifact cannot be waived. A later failed/incomplete run supersedes an older pass for the same check/corner.

## 4. Review exceptions and freeze a candidate

```bash
opentapeout --root workspace waive RUN_ID VIOLATION_FINGERPRINT \
  --owner design-owner --reason 'Reviewed intentional isolation structure; evidence attached' \
  --expires 2026-12-01T00:00:00Z --attachment reviews/exception.txt --key /secure/alice.pem

opentapeout --root workspace --actor release-author candidate RC-001 \
  --notes @release-notes.txt --delivery aurora.gds=layout
opentapeout --root workspace gate RC-001
```

Expiration above is illustrative; choose a future UTC time appropriate to your release. Waivers apply to an exact run digest and violation fingerprint, not to every future instance of a rule. Reruns require renewed exception review. Geometry arrays participate in fingerprints; the KLayout adapter currently includes item order in its location string, so reordered exports conservatively require re-review.

## 5. Approve, seal and verify

```bash
opentapeout --root workspace approve RC-001 --role physical --key /secure/alice.pem
opentapeout --root workspace approve RC-001 --role verification --key /secure/bob.pem
opentapeout --root workspace gate RC-001 --markdown
opentapeout --root workspace seal RC-001 private-evidence.zip --key /secure/release.pem
opentapeout --policy workspace/policy.json --trust workspace/trust.json verify private-evidence.zip
```

Every signature binds project, candidate content, role and timestamp. Candidate content includes resources, exact selected evidence, applicable waivers, delivery hashes, release notes, policy digest and trust-store digest. New evidence, modified notes or a policy/trust change requires a new candidate and fresh signatures. A successful gate is never cached as permanent permission to seal.

After a separately authorized manual foundry upload, compare the checksum returned by that upload process:

```bash
opentapeout --root workspace receipt RC-001 --sha256 ACTUAL_ARCHIVE_SHA256 --reference ACTUAL_RECEIPT_ID
```

This records an operator-supplied assertion and verifies checksum equality. It does not call or authenticate a foundry API. Do not upload the full evidence archive by default: review confidential content and foundry requirements first.

## 6. Anchor the ledger externally

```bash
opentapeout --root workspace checkpoint --key /secure/release.pem --output checkpoint.json
opentapeout --root workspace audit --checkpoint checkpoint.json
```

Store `checkpoint.json` in independently controlled storage (protected repository, signed release, or WORM system). A hash chain without an external anchor cannot detect a fully rewritten history or a valid-prefix rollback. Back up SQLite using its backup API or a coordinated snapshot including WAL state; do not copy an actively written database file in isolation.
