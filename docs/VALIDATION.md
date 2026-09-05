# OpenTapeout 0.1.0 — measured local validation

**Date: 5 September 2026. This is the historical local validation record from before publication, not signoff certification. Remote CI is reported separately by GitHub Actions.**

## Results

| Check actually performed | Result |
|---|---|
| Automated tests, Linux / Python 3.13.5 | **198 passed**, zero failures, zero skips, zero warnings |
| Python runtime statement coverage | **93.07%** (1,410 / 1,515 statements); not branch coverage |
| Signed synthetic baseline | All six required check/corner gates passed, two distinct reviewers assigned |
| Netlist engineering change | Release blocked: candidate changed, derived layout stale, affected evidence stale |
| Full-evidence synthetic ZIP | Manifest signature, objects, required gates and reviewer signatures verified offline |
| Built Python wheel | Installed into a clean target directory using existing environment dependencies; assets present; complete synthetic stale-result scenario reproduced |
| CI entrypoint run locally | Ready candidate exit 0; stale candidate exit 2; Markdown summaries and output variables produced |
| Chromium 144.0.7559.96 | Standalone embedded review passed navigation, evidence search/drill-down, dependency impact, approvals, audit and JSON-export checks; zero JavaScript errors |
| Responsive review | 1512×1050 desktop and 390×844 mobile viewport; no mobile horizontal document overflow |
| API | HTTP TestClient tests cover authentication, read-only behavior, trusted hosts and security headers |
| Source publication hygiene | Heuristic scanner run against the packaged source; not a complete secret or design-data audit |

The browser check used the self-contained HTML document with `page.set_content`. Live localhost navigation in this environment was blocked by browser administration policy; the live API was separately exercised through HTTP TestClient and the server health endpoint. This is not a claim of live browser-to-server end-to-end coverage.

An additional regression test was added after coverage exposed unclosed SQLite initialization connections. The final run has no resource warnings.

## Reproduce

```bash
python -m pip install '.[web,dev]'
python -m compileall -q src scripts
pytest --cov=opentapeout --cov-report=term-missing --junitxml=test-results.xml
python scripts/scan_public_source.py
python -m build
```

Optional standalone browser check (requires Playwright and a compatible installed Chromium):

```bash
python -m pip install playwright
python scripts/build_demo_preview.py
python scripts/check_demo_browser.py --chromium /usr/bin/chromium
```

The synthetic demo generates fresh random project/run IDs and signing keys, so a regenerated demo is functionally reproducible, not byte-identical to this snapshot. Demo keys are generated temporarily and never included in the source distribution.

## Detailed records

[Validation manifest](validation/manifest.json) records exact runtime/script/test hashes, dependency versions and performed/unperformed checks. [Pytest log](validation/pytest.log) contains the actual final local test output. The original downloadable source distribution additionally contains its full JUnit XML; regenerate a fresh report with the command above. [Archive verification](validation/synthetic-bundle-verification.json) records synthetic archive verification. [Blocked gate summary](validation/ci-blocked.md) demonstrates the CI output.

The wheel was built through the installed setuptools build backend and installed with `--no-index --no-deps` into a clean target directory. Its smoke test reused this environment's already installed runtime dependencies; it was not a hermetic fresh-OS install. The source distribution was also built. Dependency ranges are not a full transitive/hash-pinned lock.

## Explicit boundaries

No real EDA tool, proprietary parser corpus, PDK, manufacturing GDS, foundry portal, industrial tapeout, commercial comparison, external security audit or Docker build was tested. Python 3.11/3.12 are configured in the supplied CI matrix but were not executed here. No linter was available locally. Code compilation and tests did run.

At the time of the original local validation, the repository did not yet exist, and no remote GitHub Actions run had occurred. The user subsequently created public `ajayasai/OpenTapeout`, and the source was uploaded to `main`. The historical validation manifest retains its original `not_performed` list; that list describes the pre-publication local run, not the current repository state. Consult [GitHub Actions](https://github.com/ajayasai/OpenTapeout/actions/workflows/ci.yml) for actual remote runs and their outcomes.

Current readiness means the configured policy accepted recorded evidence, not that the chip is physically correct or a foundry accepted its delivery.

## Remote CI after publication

[GitHub Actions run 33957144000](https://github.com/ajayasai/OpenTapeout/actions/runs/33957144000) completed successfully on 5 September 2026 at code commit `ab921e93ec1e3fed50be7399a3c3a43445594044`. All three jobs — Python 3.11, 3.12, and 3.13 — passed dependency installation, source compilation, tests with coverage, the source hygiene scan, package builds, and the synthetic stale-result gate check. Later documentation-only changes do not alter the tested application source. This is software CI, not real EDA or foundry validation.
