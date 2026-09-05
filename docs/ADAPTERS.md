# Evidence adapter contract

## Normalized JSON v1

The preferred tool-neutral interface is a complete normalized summary written by the trusted tool wrapper. It must contain **exactly** these top-level fields:

```json
{
  "schema": "opentapeout.result/v1",
  "run_id": "the-exact-run-ID-from-OPENTAPEOUT_RUN_ID",
  "status": "pass",
  "complete": true,
  "metrics": {"wns_ns": 0.125, "tns_ns": 0.0},
  "violations": []
}
```

`status` is `pass`, `fail`, or `unknown`; `complete` is a JSON boolean. All metric values must be finite numbers, not strings or booleans. Establish numerical units in the metric name and policy. A pass cannot contain violations or be incomplete. A failure with no individually identified violations is not waiverable. The raw report is stored even when parsing fails; parsing errors produce unknown/incomplete evidence.

Every violation requires nonempty `rule`, `location`, `message`, and `severity` (`error`, `warning`, or `info`). Optional `geometry` participates in the content fingerprint. All reported severities are conservatively gating unless individually waived. The normalized violation fingerprint is computed from those fields; a supplied fingerprint must match. Duplicates are rejected so an adapter must disambiguate occurrence locations. A waiver never means every violation with the same rule is accepted.

Set `complete=true` only after verifying the entire expected rule/corner/view coverage and report completion. A file named `PASS` is not evidence. Validate tool-specific exit behavior; many EDA tools return zero even when design violations exist. The process exit code and result status are independent gates. Unknown report conventions must fail closed, not be guessed by loose regular expressions.

## Other implemented adapters

| Adapter name | Input contract | Important limit |
|---|---|---|
| `junit` | UTF-8 `testsuite`/`testsuites`; named testcases; declared counts consistent at suite and aggregate levels. | Empty suites do not prove success. Failures/errors block; skipped cases make completion unknown. Unsupported suite-level errors require normalization. |
| `klayout-rdb` | UTF-8 KLayout `report-database` with `categories`, `cells`, and `items`; item category/cell and values. | Parses markers, not foundry-qualified rule coverage. Empty items are meaningful only with a trusted completed run and correct rule deck. Item ordering currently affects violation fingerprints. |
| `csv` | Exact header `rule,location,message,severity`, one violation per row. | A header-only file represents zero *reported* violations, not proof of full rule execution. Trust the wrapper/capture boundary. |

All imports retain the raw captured report's SHA-256. Adapters do not license, run, emulate, or certify Calibre, IC Validator, PrimeTime, Tempus, Jasper, VC Formal or other commercial engines. Normalized JSON can represent their documented exported results, but vendor/version-specific converters need sanctioned example reports and independent tests before claiming native support.

## Tools, options, corners and remote schedulers

Register exact tool `name`, `version` and `argv` (including invocation flags). Register the wrapper source, configuration, rule deck, libraries and PDK as dependencies. Corner IDs map to versioned metadata resources, and each policy kind/corner pair is evaluated independently. Root selection must include every input that affects the claim.

The managed runner supplies `OPENTAPEOUT_RUN_ID` and `OPENTAPEOUT_REPORT`; a wrapper writes the result there. `begin`/`finish` support outside schedulers but label them unmanaged. Enabling unmanaged results is a policy decision, not an implicit upgrade to verified execution. GitHub OIDC attestations, scheduler identity, remote execution proof and SBOM/SLSA interoperability are not implemented.

## Source references

KLayout RDB structure: https://www.klayout.de/rdb_format.html

KLayout DRC basics: https://www.klayout.de/doc/manual/drc_basic.html

Ed25519 API used for signatures: https://cryptography.io/en/latest/hazmat/primitives/asymmetric/ed25519/

## v0.2.0 native Yosys SAT adapter

`--format yosys-sat` is restricted to FORMAL runs. It accepts ordinary Yosys
transcripts containing explicit `Import proof-constraint` lines from
`sat -prove SIGNAL VALUE`, paired solver/outcome records and a single end-of-script
footer. Errors, incomplete/mixed logs and missing proof constraints cannot pass.
Zero-assertion/vacuous, induction and arbitrary coverage/satisfiability logs are not
qualified. Register the proof script and relevant RTL as dependencies and bind the
actual argv/version. Parsing cannot authenticate a dishonest execution environment.

Run `scripts/qualify_yosys.py` with an actual Yosys executable; see the separate
GitHub CI job for its exact installed version and report. This qualifies the small
combinational example only. At v0.2, native physical qualification was outstanding;
the v0.3 collector section below describes subsequent work. Foundry coverage is
still not established. Primary source for the explicit proof command and success transcript:
https://github.com/YosysHQ/yosys/blob/main/docs/source/using_yosys/more_scripting/model_checking.rst


## Physical collectors (v0.3)

The `klayout-drc`, `klayout-lvs` and `opensta` adapters use strict run-bound
collector frames and can consume managed stdout with `--report-source stdout`.
They enforce native-format/check-kind pairing and reject nonempty native stderr.
They are narrow, version-qualified collector contracts, not universal vendor parsers.
See [physical qualification](PHYSICAL_QUALIFICATION.md) for scripts, rule and
constraint coverage, defect controls and limits, and [policy v2](POLICY_V2.md) for
exact input, format, corner and executable binding. Observed native execution is
recorded separately in [validation](VALIDATION.md).
