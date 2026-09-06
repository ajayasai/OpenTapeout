# Security reporting

OpenTapeout is an alpha, not independently audited or foundry-qualified. Read
[the security model](docs/SECURITY.md), [exact-policy trust boundaries](docs/POLICY_V2.md)
and [physical collector scope](docs/PHYSICAL_QUALIFICATION.md) before using real data.

Use the repository's private vulnerability-reporting channel when enabled. If
unavailable, request a private contact from the maintainer without posting exploit
details, private design data or secrets publicly. No monitored security email
address or response-time SLA is claimed.

Only the current development version is targeted for fixes; no long-term-supported
release exists yet. Keep deployment access private until production qualification
and independent review. The managed runner executes code; it is not a sandbox.

## Optional team gateway

Read [the team threat model](docs/TEAM_API.md) before deployment. Keep IdP JWKS,
policy, trust and access files outside all workspaces and protect them with OS
permissions. Reviewer keys must not be accessible to the gateway service identity.
The gateway is not independently audited, a sandbox or an untrusted-tenant boundary.
