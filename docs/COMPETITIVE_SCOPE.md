# Competitive scope — reviewed 2026-09-06

Universal superiority has not been established. A public feature page can establish
that a capability is advertised; silence on that page cannot establish its absence.
No licensed commercial product was installed or benchmarked for this release.

## What primary sources establish

- Perforce IPLM describes cross-project IP metadata, traceability and reuse. Its
  documentation explicitly covers immutable release workspaces, hierarchical IP/BOM
  relationships and staged subsystem updates. These are not missing features we can
  honestly claim to have invented.
  https://www.perforce.com/products/helix-iplm
  https://help.perforce.com/helix-iplm/public-latest/latest/Content/MethodicsIPLM/Workspaces.htm
  https://help.perforce.com/helix-iplm/public-latest/latest/Content/MethodicsIPLM/From_IPs_to_Projects__IP_Hierarchies_.htm
- Keysight SOS Core describes engineering data/version management and integration
  with Cadence, Synopsys and Siemens environments. Keysight's 2026 Virtuoso discussion
  covers visual design diff and embedded workflows.
  https://www.keysight.com/us/en/products/design-engineering-software/engineering-data-management/sos-core.html
  https://www.keysight.com/blogs/en/tech/sim-des/sos-core-and-cadence-virtuoso-modernizing-design-data-management
- Siemens describes semiconductor lifecycle management spanning engineering,
  manufacturing and supply-chain traceability. OpenTapeout is not a replacement
  for that entire scope.
  https://www.siemens.com/en-us/digital-thread/integrated-lifecycle-management/semiconductor/
  https://blogs.sw.siemens.com/electronics-semiconductors/2025/01/29/one-end-to-end-lifecycle-management-solution-is-built-for-todays-rapidly-evolving-ecosystem/

## Current enterprise comparison (v0.4)

Perforce's published 2026 releases include protected-property permissions, release
previews and coordinated SSO configuration. Keysight's SOS Enterprise announcement
of February 10, 2026 describes role-based access, audit trails, fine-grained
permissions and geofencing. These are advertised vendor capabilities, not results
from our own licensed-product evaluation.

- https://www.perforce.com/products/helix-iplm/whats-new
- https://www.keysight.com/ie/en/about/newsroom/catalog/news-release.2026.0210-pr26-034-keysight-enables-enterprise-scale-ai-adoption-in-semiconductor-design-with-sos-enterprise.html

OpenTapeout v0.4 adds tested project-scoped permissions and signed team writes with
verified access-token identity, exact-state concurrency checks and durable retry
receipts. Its HTTPS qualification uses an ephemeral test issuer, not a deployed
corporate identity provider. It does not provide geofencing, per-IP/property ACLs,
interactive SSO, distributed replication, administrator UI or a support SLA.

The intended differentiator is an inspectable combination of signed exact-state
review commands and independently verifiable evidence. The equivalence or absence
of that combination in commercial systems remains **unknown**. Source access and
our own tests do not prove feature or performance superiority.

## What OpenTapeout demonstrates

Inspectable and locally tested content-bound evidence, no old-pass fallback, exact
waivers, independently supplied keys/policies, explicit minimal disclosure,
recipient-signed byte acknowledgment, per-approval revocation, irreversible release
withdrawal, expiring offline status and read-only rebuild planning. These are
available as Apache-2.0 source and reproducible tests. The commercial equivalents
of these exact semantics are **not assessed**, not assumed absent.

v0.3 adds exact resource/tool/corner policy pins and native physical collector
contracts. The physical microflow tests are described separately in
PHYSICAL_QUALIFICATION.md, with observed results in VALIDATION.md. They close a
local integration gap, not a demonstrated gap in commercial tools.

A before/after microbenchmark measured latest-run selection on our own code. It
is not an end-to-end or commercial-product performance comparison. The real Yosys
CI qualification covers a small combinational proof, not a production tapeout.

## Acceptance work needed for a stronger comparison

Use the same sanctioned project and change sequence in every product. Measure false
freshness and false staleness separately; include missing dependencies, PDK/rule-deck
updates, ECOs, tool failures, interrupted reports, waived violations, expired and
revoked approvals, recipient substitution and archive tampering. Record cold/warm
latency, memory, storage, administrator actions and operator effort, with versions,
configuration and public reproducers wherever disclosure permits.

Qualify multi-corner DRC/LVS/STA with approved tools/PDKs, expand recovery and
multi-user authorization trials on production workloads, and conduct an independent security review. Industrial
support, native integrations, SSO, availability and scale must be measured rather
than replaced with an untested checkbox. See ROADMAP.md for the remaining gaps.
