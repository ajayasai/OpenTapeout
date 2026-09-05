"""Regenerate the standalone review from fresh, explicitly synthetic demo data only."""
import json
import tempfile
from pathlib import Path

from opentapeout.demo import build_demo
from opentapeout.engine import Engine
from opentapeout.planning import plan, compare
from urllib.parse import urlencode
from opentapeout.signing import Trust
from opentapeout.util import read_json
from opentapeout.web import STATIC, summary


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="opentapeout-preview-") as directory:
        root = Path(directory)
        build_demo(root, stale=True)
        engine = Engine(root)
        policy, trust = read_json(root / "policy.json"), Trust.from_file(root / "trust.json")
        original = engine.state()["candidates"]["RC-001"]
        engine.candidate("RC-002", "SYNTHETIC ECO pending revalidation", {d["name"]:d["resource_id"] for d in original["deliveries"]}, policy, trust)
        data = summary(engine, policy, trust)
        seed = {"/api/summary": data}
        with engine.store.transaction() as tx:
            seed["/api/audit"] = {"checkpoint": tx.checkpoint, "events": tx.events}
        for resource in data["resources"]:
            seed["/api/impact/" + resource["id"]] = engine.impact(resource["id"])
        for candidate in data["candidates"]:
            seed["/api/gate/" + candidate["name"]] = candidate["gate"]
            for change in [""] + [r["id"] for r in data["resources"]]:
                query = urlencode({"name": candidate["name"], "changed": change})
                seed["/api/plan?" + query] = plan(engine, policy, trust, candidate_name=candidate["name"], changed=[change] if change else [])
            for other in data["candidates"]:
                seed["/api/compare/" + candidate["name"] + "/" + other["name"]] = compare(engine, candidate["name"], other["name"])
        html = (STATIC / "index.html").read_text(encoding="utf-8")
        html = html.replace('<link rel="stylesheet" href="/static/style.css">',
                            "<style>" + (STATIC / "style.css").read_text(encoding="utf-8") + "</style>")
        html = html.replace('<script defer src="/static/app.js"></script>', "").replace('<script defer src="/static/control.js"></script>', "")
        data_json = json.dumps(seed, ensure_ascii=True).replace("<", "\\u003c")
        html = html.replace("</body>", '<script type="application/json" id="offline-data">' + data_json +
                            '</script>\n<script>' + (STATIC / "app.js").read_text(encoding="utf-8") +
                            "</script>\n<script>" + (STATIC / "control.js").read_text(encoding="utf-8") + "</script>\n</body>")
    destination = Path(__file__).resolve().parents[1] / "docs" / "demo.html"
    destination.write_text(html, encoding="utf-8")
    print(destination)


if __name__ == "__main__":
    main()
