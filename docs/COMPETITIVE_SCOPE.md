# Competitive scope — evidence, not superiority claims

Reviewed against official product descriptions on 5 September 2026. No commercial licenses, production datasets or vendor sandboxes were available for a head-to-head test. “Not assessed” means exactly that; it must not be interpreted as an absent commercial feature.

| Dimension | OpenTapeout 0.1.0 | Commercial reference point |
|---|---|---|
| Inspectable implementation / self-hosted local ledger | Apache-2.0 source; SQLite and ordinary files; no hosted account required. | Vendor products use their own licensing/deployment models; a cost/security comparison was not performed. |
| Evidence invalidation behavior | Exact hash/closure comparison, obsolete-derivation tracking, before/after input checks, failing-case tests. | IPLM/SOS traceability and governance are documented; their detailed stale-result semantics were not assessed. |
| IP lifecycle/catalog/workspace management | Input/version records, Git/submodule capture and release snapshots only. | Perforce IPLM documents cross-project IP and metadata traceability, catalog/reuse and governance; substantially broader scope. |
| Native engineering-data integrations | Four report-adapter contracts and Python/CLI APIs; no qualified proprietary native plugins. | Keysight SOS documents integrations with major EDA design environments, including Cadence Virtuoso and other vendors. |
| GitHub-native workflows | Source-delivered composite gate action and CI workflow; consult actual workflow runs for execution status. | Synopsys documents GitHub-triggered EDA execution with results returned to pull requests. |
| Portable signed evidence | Implemented Ed25519 candidate approvals and offline signed ZIP verification against external policy/trust. | Detailed commercial export/signature interoperability was not assessed. |
| Enterprise identity, global deployments, commercial support | Not implemented/proven. Read-only token-protected API and trusted local operators only. | Enterprise breadth and product support are material reasons not to describe this alpha as universally superior. |
| Real tapeout readiness | Synthetic workflow and adversarial software tests only. | No comparative real-design benchmark or foundry qualification was performed. |

## What could become a genuine advantage

A vendor-neutral evidence model whose invalidation rules are inspectable, tested and portable is a concrete design choice. OpenTapeout exposes explanations, checks derived-artifact provenance, keeps policy decisions reproducible, and deliberately separates artifact integrity from execution trust. These are implemented capabilities, not proof that proprietary systems lack equivalent features.

## Required head-to-head experiment

Obtain lawful access to competing systems and the same licensed representative design flows. Freeze tool/PDK versions and define expected outcomes before testing. Inject controlled RTL/netlist/layout, PDK-file, rule-deck, SDC, corner, invocation-option, waiver and approval changes. Measure false-fresh and false-stale decisions, explanation completeness, time to identify the affected evidence, import effort, user review time, cold/full rehash costs, concurrent writer throughput, large-object behavior, recovery after interruption, and operational/security overhead. Publish the raw permitted test vectors and exact configuration with uncertainty, not an unsupported ranking.

## Official sources

Perforce IPLM product: https://www.perforce.com/products/helix-iplm

Perforce IP governance: https://www.perforce.com/blog/iplm/ip-governance

Keysight SOS Core: https://www.keysight.com/us/en/products/design-engineering-software/engineering-data-management/sos-core.html

Synopsys GitHub EDA workflow (27 May 2026): https://www.synopsys.com/blogs/chip-design/chip-design-tools-github-hardware-development.html

GitHub secure-use guidance for commit pinning: https://docs.github.com/en/actions/reference/security/secure-use
