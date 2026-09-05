# Native physical-check collectors (v0.3)

OpenTapeout remains evidence software. KLayout performs layout operations and
netlist extraction/comparison; OpenSTA performs timing analysis. The application
captures their reports and checks provenance, coverage, policy and release approval.
The collectors in `examples/physical/` are original educational examples, **not a
foundry PDK, an approved signoff deck or characterized manufacturing cells**.

## Reproduce the qualification

Install the Python package and actual `klayout` and `sta` executables, then run:

```bash
python -m pip install .
python scripts/qualify_physical.py --output physical-qualification.json
```

Missing tools fail; the harness never substitutes fixtures or a skipped success.
The GitHub workflow has a separate mandatory physical job. Its disposable-runner
installer installs KLayout from Ubuntu and builds CUDD/OpenSTA from exact upstream
commits. It includes required development headers and regenerates the old CUDD
Autotools build system. It does not vendor or redistribute those tools under
OpenTapeout's license. Package dependencies and compiler/system images are not
fully locked, so this is not a hermetic reproducible-build claim.

## What the harness exercises

The physical example generates actual GDS with a rectangular resistor, contacts
and labels. KLayout executes width/spacing checks and extracts/compares its
resistance against a SPICE reference. A separate two-buffer netlist is analyzed by
OpenSTA with two separately captured educational Liberty files and invocations.
Their values illustrate corner binding; they are not measured silicon data.
**These are separate microflows, not one chip taken from RTL through physical signoff.**

The positive candidate binds all four checks under exact-input policy v2, obtains
two reviewer signatures, seals a full evidence archive and verifies it offline.
Negative controls modify layout bytes without registration, register a layout ECO,
introduce a width defect, change reference resistance, shorten the timing period,
and remove output constraints. For each defect, the harness evaluates a fresh
focused candidate with matching pins and ignores approval requirements solely for
that negative test. This establishes that the defective evidence itself blocks;
it is not a misleading failure caused only by stale pins or missing reviewers.
The normal positive gate still requires two authorized reviewers.

The generated JSON records actual tool versions, binary identities, positive and
negative metrics, gate blocker codes and archive verification. Observed runs and
limitations belong in [VALIDATION.md](VALIDATION.md); having this script alone does
not constitute a passed native qualification.

## Collector protocol and failure behavior

Use `run --report-source stdout` with `--format klayout-drc`, `klayout-lvs` or
`opensta`. A required `--report` argument must name a nonexistent workspace path;
stdout mode captures the managed stdout log instead of reading that output path.
The raw log is retained by hash before it is parsed.

Reports have one matching `OT_BEGIN backend RUN_ID` / `OT_END backend RUN_ID`
frame. Missing, repeated, mixed-run or reordered framing fails. Native diagnostic
lines and any nonempty managed stderr cannot establish automatic success. This
conservative policy may reject benign diagnostics; review a tool/collector version
rather than globally suppressing warnings or weakening the evidence gate.

KLayout DRC supplies exact named-rule counts, positive geometry coverage and
individual markers. Declared counts must agree with the marker list. KLayout LVS
supplies a native comparison result and nonzero circuit/device/net counts, preventing
empty-vs-empty from appearing successful. Matching device counts are only a
vacuity guard, not an independent equivalence proof.

OpenSTA supplies clock and constraint checks and six mandatory setup/hold sections:
paths, worst slack and total negative slack for both modes. Paths must exist and
have matching startpoint/endpoint/slack records. Units are explicitly nanoseconds;
numbers must be finite, slack signs must match MET/VIOLATED, worst-path and summary
values must agree, and WNS/TNS must be consistent. Missing timing coverage is not a
zero-slack pass. Physical formats can only satisfy their corresponding check kind.

The protocol is narrow and version-tested. It is not a universal parser for all
KLayout/OpenSTA output versions, and it does not parse Calibre, PrimeTime, Tempus,
IC Validator or proprietary foundry reports. A trustworthy framed report still
depends on a reviewed collector, declared inputs, tool and controlled runtime.

## Extending beyond these examples

An integration needs an approved design/PDK license, complete tool dependency
capture, qualified decks/libraries, every required corner/mode, extraction and
constraint coverage, and positive and negative controls reviewed by signoff
engineers. Archive confidentiality and export/license obligations remain separate
from technical verification. Nothing here uploads to a foundry or certifies a tapeout.

Primary references:
- [KLayout DRC basics](https://www.klayout.de/doc/manual/drc_basic.html)
- [KLayout device extraction](https://www.klayout.de/doc/manual/lvs_device_extractors.html)
- [KLayout LVS comparison](https://www.klayout.de/doc/manual/lvs_compare.html)
- [OpenSTA upstream](https://github.com/parallaxsw/OpenSTA)
