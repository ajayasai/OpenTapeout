"""Explicit public publication via the user's authenticated GitHub CLI; never force-pushes."""
from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from pathlib import Path

from scan_public_source import scan

ROOT = Path(__file__).resolve().parents[1]


def run(*command: str, capture: bool = False, check: bool = True):
    return subprocess.run(command, cwd=ROOT, check=check, text=True, capture_output=capture)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--owner", default="ajayasai")
    parser.add_argument("--name", default="OpenTapeout")
    parser.add_argument("--public", action="store_true", required=True,
                        help="Explicitly authorize public source publication")
    args = parser.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9-]+", args.owner) or not re.fullmatch(r"[A-Za-z0-9_.-]+", args.name):
        parser.error("Invalid GitHub owner/repository name")
    for command in ("git", "gh"):
        if not shutil.which(command):
            raise RuntimeError(f"Install {command} before publishing. No remote changes were made.")
    run("gh", "auth", "status")
    account = json.loads(run("gh", "api", "user", capture=True).stdout)
    if account["login"].lower() != args.owner.lower():
        raise RuntimeError(f"Authenticated account is {account['login']}, not requested owner {args.owner}.")
    checked, problems = scan(ROOT)
    if problems:
        raise RuntimeError("Publication hygiene check failed:\n" + "\n".join(problems))
    if not (ROOT / ".git").exists():
        run("git", "init", "-b", "main")
    top = Path(run("git", "rev-parse", "--show-toplevel", capture=True).stdout.strip()).resolve()
    if top != ROOT:
        raise RuntimeError("Refusing to publish from within another Git repository")
    if run("git", "remote", capture=True).stdout.strip():
        raise RuntimeError("Repository already has a remote. Refusing to overwrite, change visibility, or force-push.")
    # Avoid guessing/impersonating an author. Git must already have the user's chosen identity.
    run("git", "var", "GIT_AUTHOR_IDENT", capture=True)
    allowed = [name for name in checked if not name.startswith(".") or
               name.startswith(".github/") or name in {".gitignore", ".dockerignore"}]
    for offset in range(0, len(allowed), 50):
        run("git", "add", "--", *allowed[offset:offset + 50])
    changed = run("git", "diff", "--cached", "--quiet", check=False).returncode
    if changed == 1:
        run("git", "commit", "-m", "OpenTapeout: evidence-bound tapeout release ledger")
    elif changed != 0:
        raise RuntimeError("Cannot inspect staged changes")
    print(f"Publishing {args.owner}/{args.name} PUBLICLY: application source and synthetic fixtures only.")
    run("gh", "repo", "create", f"{args.owner}/{args.name}", "--public", "--source", ".",
        "--remote", "origin", "--push", "--description",
        "Open-source tapeout evidence ledger: dependency-aware stale results, signed approvals, and verifiable releases")
    # Verify the resulting identity and visibility rather than just assuming success.
    remote = json.loads(run("gh", "repo", "view", f"{args.owner}/{args.name}", "--json",
                            "nameWithOwner,isPrivate,url", capture=True).stdout)
    if remote["isPrivate"] or remote["nameWithOwner"].lower() != f"{args.owner}/{args.name}".lower():
        raise RuntimeError("Repository visibility/identity verification failed")
    print(remote["url"])
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (RuntimeError, subprocess.CalledProcessError, OSError, ValueError) as exc:
        print(f"Publication stopped: {exc}", file=sys.stderr)
        raise SystemExit(1)
