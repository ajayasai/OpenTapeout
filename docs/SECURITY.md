# Security model, limitations, and deployment boundaries

## Supported adversarial cases

The tests cover accidental/manual byte changes, post-run design changes, stale derivations, incomplete/unknown reports, false positive pass text, nonzero exit codes, imported-vs-managed policy, invalid/future/expired signatures, forged approvals, unauthorized roles, one principal using multiple keys, narrow waiver scope, malicious archive members and digest substitution. Strict JSON rejects duplicate keys and nonfinite numbers. XML adapters reject DTD/entity declarations, malformed documents and non-UTF-8 encoding. Report parsing is size-bounded; raw evidence capture is streamed.

## Trusted components and remaining threats

The operating system, local filesystem administrator, Python interpreter, installed dependencies, EDA executables/wrappers, external policy, reviewer identity-to-key mapping, signer and capture runner remain trusted. There is no SSO/OIDC integration, tenant isolation, network write API, HSM, hardware execution attestation, encrypted-at-rest object store, automated secret redaction or independently authenticated foundry transport.

Input declarations must be complete. A registered PDK lockfile proves its own bytes, not the installed technology tree. Use `capture-tree` or register every relevant technology input. Directory capture is conservative, can be expensive for large trees, rejects symlinks, and currently caps a resource at 100,000 files. Partition larger trees.

The managed runner is not a sandbox. It inherits the host environment and executes explicitly registered argv without a shell. Capture uses pre/post comparisons, not a snapshot filesystem: a hostile writer can change a file and restore it between observations. Use immutable input mounts, isolated containers/VMs, authenticated runners and least-privilege EDA service accounts. Runtime cancellation by killing the coordinator can leave an incomplete run, which blocks release. Process timeouts kill the POSIX process group; Windows does not have equivalent child-tree termination here.

Local `.opentapeout` state is writable by its owner. A hostile administrator can rewrite/re-hash history or delete valid suffixes. SQL guards and a hash chain alone do not prevent that. Retain signed checkpoints outside the workspace; they detect alterations/truncation of their anchored prefix. They cannot discover deletion of unanchored events appended after the last checkpoint. No trusted timestamp authority is implemented.

Keys are generated through the `cryptography` library's Ed25519 API. Statements use a project-specific domain-separated encoding: `b"OpenTapeout signed statement v1\\x00" + canonical(payload)`. Canonical JSON sorts keys, uses ASCII escapes and compact separators, and rejects NaN/infinity; this is **not RFC 8785** and cross-language reimplementations need conformance tests, especially for floats. Cryptographic primitives do not make local actor labels authenticated identities. Keep signing keys outside workspaces, use encrypted PEMs where practical, and consider a hardware-backed signing service before production use.

## Browser and API

The dashboard is read-only. It uses text nodes rather than `innerHTML` for report/user content, has no third-party assets, and does not keep tokens in persistent browser storage. API data are returned with `Cache-Control: no-store`; CSP disallows inline scripts, framing, external connections and object embeds. Without a token, the service defaults to loopback and verifies Host headers to reduce DNS-rebinding risk. Non-loopback CLI binding requires a 32+ character bearer token. Terminate TLS at a correctly configured reverse proxy and restrict the network; a bearer token does not provide enterprise user-level auditability. `/health` and static UI assets contain no workspace evidence and remain public; all `/api/` routes require the token when configured.

A repository's CI must use policy and trust from an independently protected source, not from the untrusted pull request being evaluated. Do not provide signing keys to fork-PR jobs. The provided action does not approve or seal releases. Pin the action itself to a reviewed commit and run it with minimal GitHub permissions. Consult the repository's actual workflow runs for CI outcomes; the presence of a workflow file alone does not establish successful execution.

## Confidentiality

Source publication and design-data publication are separate decisions. Never commit production `.opentapeout` objects, reports, layout/netlist files, PDK/IP trees, reviewer keys or foundry credentials to the public application repository. Full evidence ZIPs contain their selected objects and can expose licensed/confidential material. The export warning is intentional. A minimal NDA-aware delivery exporter, per-object disclosure policies, envelope encryption and authenticated foundry receipts remain future work.

The public publish script performs a narrow heuristic check, not a proven secret/IP scanner. Review its staged-file list and run organizational DLP/secret scanning before publishing real projects. The source distribution contains synthetic fixtures only.

## Operational limitations

No live commercial tools/foundry account were available for validation. No independent penetration test, fuzzing campaign, supply-chain audit, production failure-recovery exercise, disaster recovery drill or million-event scale certification has been performed. Do not interpret passing unit tests as production certification. See ROADMAP.md for the required next validation work.
