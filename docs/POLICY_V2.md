# Exact-input release policy (v0.3)

## Why resource kinds alone are insufficient

A requirement for a `library` establishes the presence of some library, not the
correct library at the correct corner. Policy v2 adds resource-ID/SHA-256 pins,
allowed tool IDs and report formats, and an observed executable-pin requirement.
The same evaluator enforces these requirements in the live gate and offline
full-evidence verification. It does not establish that an undeclared dependency
was observed or that the tool is honest.

## Migration without silently weakening an existing gate

Existing v1 policies remain valid. `init` still generates the six-check v1 template:
there are no universal correct pins for an unknown project. Register the actual
inputs, review dependencies, define each corner, and capture fresh managed runs.
Then produce a *separate* review draft:

```bash
opentapeout --root ./workspace --policy ./workspace/policy.json \
  pin-policy --output ./policy.review.json
```

The command never changes the active policy or ledger, signs a decision, or
approves a candidate. It requires a completed latest managed run for each required
check, unchanged registered input snapshots, intact captured objects and an
observed matching executable pin. An incomplete latest run cannot fall back to an
older completed one. Failed checks can be pinned as configuration; they still
fail release evaluation. Pinning a failed result is not accepting it.

Review the complete input list, library/corner pairing, collector, rule coverage,
metric units, thresholds and waiver constraints. Protect the reviewed policy
outside a writable project workspace. Use it explicitly when creating and
approving a **new candidate**. Do not auto-regenerate policy pins in the same CI
step that seeks authorization: doing so would defeat independent configuration
approval.

## Additional fields on each required check

| Field | Meaning |
|---|---|
| `input_pins` | Nonempty object mapping required resource IDs to SHA-256. Each must occur in the captured dependency closure and match its expected bytes. |
| `allowed_tools` | Nonempty unique list of tool IDs. Every alternative must also have an exact metadata pin. Only the selected alternative is required in a run. |
| `report_formats` | Nonempty unique allowlist of implemented adapters; prevents a generic passing JSON from substituting for a required native collector. |
| `require_pinned_executable` | When true, requires managed execution with matching SHA-256 and unchanged executable bytes after execution. |

The corner must appear in `input_pins`. Tool and corner resources must be
metadata-only definitions with SHA-256 over their canonical metadata. A
file-backed tool resource is insufficient: pinning that file alone would not pin
its metadata, including argv. Captured `tool_spec` must match the pinned definition.
Data resources and collector scripts are normally file-backed; directory captures
can pin an entire declared dependency tree.

New blocker codes include `EXACT_INPUT_MISSING`, `INPUT_PIN_MISMATCH`,
`TOOL_NOT_ALLOWED`, `REPORT_FORMAT_NOT_ALLOWED`, `EXECUTABLE_IDENTITY`,
`DEFINITION_PIN_INVALID` and `TOOL_SPEC_MISMATCH`. Existing stale, incomplete,
process-exit, metric, waiver and reviewer checks still apply.

## Registering an executable pin

A tool's metadata can include `executable_sha256` alongside `name`, `version` and
`argv`. Compute the hash of the resolved executable in your controlled environment,
review it, and register it before the run. The runner resolves the launcher once,
compares its bytes before spawning, and compares them again after completion.
A mismatch before execution stops the launch; changed bytes afterward fail the run.

This is **not hermetic execution or remote attestation**. Shared libraries,
plugins, Tcl/Ruby/Python imports, startup scripts, child tools, environment
variables, OS behavior and a malicious local administrator are outside that
single-executable hash. Register known scripts and dependencies explicitly, use
reviewed isolated build images, and control the runtime independently. Before/after
hashing does not eliminate a hostile TOCTOU substitution or mutate-and-restore attack.

## Coverage is part of policy

For KLayout DRC, require `rule:WIDTH:checked >= 1` and the corresponding named
rules from the approved deck, not just `violation_count == 0`. For the provided
OpenSTA collector, require positive path coverage, `constraints_ok >= 1`, and
setup **and hold** slack thresholds in nanoseconds. An absent metric fails rather
than defaulting to zero. A required metric threshold is not satisfied by signing a
waiver for an unrelated violation. Full-chip exceptions and asynchronous paths
need an independently reviewed constraint methodology, not these tiny examples.
