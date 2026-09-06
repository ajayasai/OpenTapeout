# Team gateway: identity, permissions and detached review commands (v0.4)

The optional team API adds **project-scoped remote review**, not a complete enterprise
PLM platform. Existing local CLI workflows and the read-only dashboard remain available.
It does not execute tools, accept arbitrary file paths, change policy/trust/access files,
upload design data, or accept reviewer private keys. The supported write operations are
`candidate.create`, `approval.submit`, `approval.revoke` and `release.withdraw`.

## Authorization model

Every data endpoint requires an OAuth access token. The gateway verifies a fixed RS256
algorithm using an operator-provisioned **local public JWKS**, exact issuer and intended
audience, approved client ID, token type (`at+jwt`), signature, expiration, issue time,
optional not-before, subject and JWT ID. Tokens may live no longer than the configured
maximum (at most one hour). Duplicate JSON keys, unexpected JOSE headers, embedded keys,
remote key URLs, unsigned tokens and HMAC tokens are rejected. No runtime discovery or
JWKS URL is fetched. An operator must provision and rotate the JWKS securely.

An external access file maps the verified issuer subject to one project principal and
an explicit permission list. User-supplied names, email addresses, groups and role claims
do not grant access. Both token scope and project permission are required. A reader
cannot mutate or read the audit trail merely because the token has a write scope.
Subjects without project membership receive the same 404 response as a missing project.
Project-level isolation does **not** imply per-artifact permissions or OS/container isolation.

Writes additionally require a domain-separated Ed25519 command signature. Its trusted
principal must match the access-token principal. A trusted key needs the `team` role
for command submission, and a decision key also needs its actual approval/release role.
An access token alone cannot approve a candidate. Two keys for the same principal are
still only one reviewer under the existing release policy.

Each command binds an exact project UUID, action, parameters, request UUID, ledger
sequence **and hash**, governance digest, creation time and expiration (five minutes
maximum). The governance digest includes the external policy, trust store and access
file. This is a custom OpenTapeout signed protocol, not a claimed standards-certified
signature format. Review the returned context and candidate before signing.

## Consistency and retries

Authorization, current evidence evaluation, mutation and the signed-command receipt
execute within one SQLite `BEGIN IMMEDIATE` transaction. Competing commands signed
against the same checkpoint cannot overwrite each other: one commits and the others
receive `409 STALE_CHECKPOINT`. Clients must fetch and review a new context, not silently
re-sign. Token validity and observable governance changes are checked again before
commit; changes during a slow validation roll the transaction back.

Retrying the *same signed bytes and request ID*, while the command is valid and its
signer remains authorized, returns the stored receipt without another mutation. Reusing
that ID for different bytes is rejected. The receipt and mutation commit together, so
an exception or process death before commit cannot leave half a command. After command
expiry, `GET .../commands/REQUEST-UUID` recovers its historical receipt without executing
it. A historical receipt is not proof that a release is currently authorized.

Governance files and JWKS are reloaded, not permanently cached. Removing a membership
or revoking a signing key affects subsequent requests. External IdP token introspection
and immediate IdP-session revocation are **not** implemented: otherwise-valid bearer
tokens remain usable until expiry unless local membership or keys are removed.
Configuration changes are operator-managed files, not a distributed transaction;
before/after checks are not protection from a hostile filesystem administrator.

## Deployment configuration

Install `python -m pip install '.[team]'`. Provision workspaces using the ordinary
trusted local CLI/runner. Keep the configuration, JWKS, policy, trust and access files
**outside every configured workspace**. The gateway rejects overlapping workspace
paths, duplicate project IDs, project-ID mismatches and governance inside a workspace.
Protect all these files and their parent directories with OS permissions. Run the
service as a dedicated identity with no access to reviewer private-key directories.

Example `/etc/opentapeout/team.json` (replace all example values):

```json
{
  "schema": "opentapeout.team/v1",
  "identity": {
    "issuer": "https://identity.example.org/realm",
    "audience": "opentapeout-api",
    "jwks_file": "/etc/opentapeout/jwks.json",
    "client_ids": ["review-cli"],
    "max_lifetime_seconds": 600
  },
  "projects": {
    "chip-a": {
      "project_id": "EXACT-UUID-FROM-WORKSPACE-GENESIS",
      "workspace": "/srv/opentapeout/chip-a",
      "policy": "/etc/opentapeout/chip-a/policy.json",
      "trust": "/etc/opentapeout/chip-a/trust.json",
      "access": "/etc/opentapeout/chip-a/access.json"
    }
  }
}
```

Example access file:

```json
{
  "schema": "opentapeout.team-access/v1",
  "project_id": "EXACT-UUID-FROM-WORKSPACE-GENESIS",
  "members": {
    "issuer-subject-for-author": {
      "principal": "release-author",
      "permissions": ["read", "candidate.create"]
    },
    "issuer-subject-for-physical-reviewer": {
      "principal": "physical-reviewer",
      "permissions": ["read", "approval.submit", "approval.revoke"]
    },
    "issuer-subject-for-auditor": {
      "principal": "auditor",
      "permissions": ["read", "audit"]
    }
  }
}
```

JWKS entries must be public RSA keys of at least 2048 bits with unique `kid`, `use: sig`
and `alg: RS256`. Add the `team` role to appropriate existing public-key trust entries
**before creating a new candidate**: changing trust invalidates old candidate approval
contexts by design. Never automatically regenerate trust or policy to make a gate pass.

Start with a trusted TLS certificate and its separate TLS server key:

```bash
opentapeout serve-team --config /etc/opentapeout/team.json \
  --host 127.0.0.1 --port 8081 \
  --ssl-certfile /etc/opentapeout/tls.crt --ssl-keyfile /etc/opentapeout/tls.key
```

The TLS server key is not a reviewer signing key. Forwarded identity/scheme headers
are not trusted by the supplied CLI. Non-TLS requests are rejected. An explicit
`--allow-insecure-loopback` mode is limited to a literal loopback bind and loopback
peers for development; never expose or proxy that development mode to other users.
No browser login, authorization-code flow, refresh-token storage or IdP provisioning
is supplied. This is an access-token resource server for a compatible identity provider,
not a turnkey SSO deployment. In particular, generic `typ: JWT` ID tokens are rejected.

## Review from a client machine

Obtain a short-lived access token from your configured identity provider into
`OT_ACCESS_TOKEN`. Do not put tokens in URLs, command arguments, Git or shell history.
The client reads the token from the environment, verifies TLS normally, refuses
redirects, and never automatically retries with newly signed content.

```bash
opentapeout team-get \
  --url https://tapeout.example.org/v1/projects/chip-a/candidates/RC-001 \
  --output candidate.json
opentapeout team-get \
  --url https://tapeout.example.org/v1/projects/chip-a/context \
  --output context.json
# Review the exact candidate and independently governed configuration.
opentapeout team-approve --context context.json --candidate candidate.json \
  --role physical --key /secure/physical-reviewer.pem --output approval-command.json
opentapeout team-submit \
  --url https://tapeout.example.org/v1/projects/chip-a/commands \
  --command-file approval-command.json --output receipt.json
```

A second reviewer fetches a fresh context after the first command commits. The same
reviewer-count, role matching, self-approval prohibition, freshness, metric, waiver,
withdrawal and object-integrity controls used by the CLI remain in force.

For candidate creation, use `team-sign --action candidate.create --parameters params.json`
with the same context/key/output flags. Parameters have exactly `name`, `notes` and
`deliveries`; delivery aliases map only to registered layout resource IDs. No caller
can supply an `actor` or server filesystem path. For revocation and withdrawal,
`team-sign --statement decision.json` signs an unsigned decision with the command key;
the statement fields follow existing approval-revocation/release-withdrawal types.
Only the original reviewer or a `release-admin` can revoke another reviewer's approval;
withdrawal requires the `release` role and exact sealed archive and candidate hashes.

## Read API and audit export

`GET /v1/projects` lists only accessible projects. Per-project routes are `/context`,
`/candidates`, `/candidates/{name}`, `/gate/{name}`, `/commands/{request_id}`, and `/audit`.
The last requires `audit` permission. Candidate lists use `offset`/`limit`; audit pages
use `after`, `after_hash`, `until`, `until_hash`, and `limit` (1..100). Retain the first
page's end checkpoint and pass it on subsequent pages. Each page links to the previous
hash; additions do not change the selected history prefix. Compare the final hash with
an independently retained signed checkpoint rather than blindly trusting the server.

Signed command envelopes, verified identity identifiers and receipts are recorded in
the project ledger. **Bearer tokens are not recorded.** Denial logs contain safe error
codes, not raw credentials or paths. This is not a complete read-access/compliance audit.
Responses are noncacheable. Origin-bearing browser requests are rejected; the existing
local dashboard is not silently turned into an authenticated team-write frontend.

Commands have a 128 KiB body cap, no compressed-body input and strict JSON parsing.
The CLI sets an ASGI concurrency limit; production still needs connection, request-rate,
body-read-timeout and resource controls at a correctly configured trusted edge.
Audit responses are paginated, but current ledger verification/replay still scans the
whole history: **no million-event scaling or distributed database claim is made**.

## Compatibility and evidence boundaries

Old local projects need no migration to use v0.4 locally. Team events extend the ledger:
a v0.3 application refuses unknown team event types rather than misreading history.
Retain a backup before upgrade and do not downgrade an actively team-managed workspace.
Existing signed release archive schemas and independently verified signatures are unchanged.

`python scripts/qualify_team.py --output team-qualification.json` runs an actual local
HTTPS service with a temporary certificate and RSA issuer, sends real signed commands,
performs two approvals, checks concurrent conflicts, verifies an archive offline and
revokes a review. It rejects an untrusted TLS certificate. EDA evidence in this harness
is explicitly synthetic. No production IdP, customer infrastructure, external security
review, adversarial OS isolation or enterprise performance qualification is implied.

## Primary references

- OAuth JWT access-token validation: https://www.rfc-editor.org/rfc/rfc9068.html
- Fixed algorithm/claim verification: https://pyjwt.readthedocs.io/en/stable/api.html
- Write serialization: https://www.sqlite.org/lang_transaction.html
- Snapshot semantics: https://www.sqlite.org/isolation.html
