"""Smoke-test the standalone synthetic review. Requires Playwright and local Chromium.

Uses an embedded document: no network navigation or server is required.
"""
import argparse
import json
import shutil
from pathlib import Path


def main() -> None:
    from playwright.sync_api import sync_playwright

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--chromium", default=shutil.which("chromium"))
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    html = (root / "docs/demo.html").read_text(encoding="utf-8")
    errors = []
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch(executable_path=args.chromium, headless=True)
        page = browser.new_page(viewport={"width": 1512, "height": 1050})
        page.on("pageerror", lambda error: errors.append(str(error)))
        page.set_content(html)
        page.wait_for_function("document.getElementById('metric-checks').textContent !== '—'")
        assert page.locator("#demo-pill").is_visible()
        assert page.locator("#gate-badge").inner_text() == "REVIEW REQUIRED"
        page.screenshot(path=str(root / "docs/dashboard.png"), full_page=True)
        page.locator("[data-view=evidence]").click()
        page.locator("#search").fill("LVS")
        assert page.locator("#evidence-list tbody tr").count() == 1
        page.locator("#evidence-list tbody tr").click()
        assert "LVS" in page.locator("#run-detail").inner_text()
        page.locator("[data-view=dependencies]").click()
        page.locator("#resource-table tbody tr").filter(has_text="netlist").first.click()
        page.wait_for_selector("#impact-detail:not(.hidden)")
        assert "evidence runs" in page.locator("#impact-detail").inner_text()
        page.locator("[data-view=approvals]").click()
        assert page.locator("#approval-list .identity").count() == 2
        page.locator("[data-view=audit]").click()
        page.wait_for_selector("#audit-list tbody tr")
        assert page.locator("#audit-list tbody tr").count() > 20
        with page.expect_download() as download:
            page.locator("#export-json").click()
        assert download.value.suggested_filename == "opentapeout-review.json"
        page.locator("[data-view=overview]").click()
        page.set_viewport_size({"width": 390, "height": 844})
        assert not page.evaluate("document.documentElement.scrollWidth > innerWidth")
        assert not errors, errors
        print(json.dumps({"browser": browser.version, "passed": True,
                          "javascript_errors": errors, "mobile_horizontal_overflow": False}))
        browser.close()


if __name__ == "__main__":
    main()
