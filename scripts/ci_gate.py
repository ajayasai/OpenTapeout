"""Small trusted-runner entrypoint; never signs or mutates release evidence."""
import os
from pathlib import Path

from opentapeout.cli import markdown_gate
from opentapeout.engine import Engine
from opentapeout.signing import Trust
from opentapeout.util import read_json


def main() -> int:
    report = Engine(Path(os.environ["OT_WORKSPACE"])).gate(
        os.environ["OT_CANDIDATE"], read_json(os.environ["OT_POLICY"]),
        Trust.from_file(Path(os.environ["OT_TRUST"])))
    markdown = markdown_gate(report)
    print(markdown)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as handle:
            handle.write(markdown)
    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as handle:
            handle.write("ready=" + str(report["ready"]).lower() + "\n")
            handle.write("candidate_sha256=" + report["candidate_sha256"] + "\n")
    return 0 if report["ready"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
