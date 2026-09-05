"""Narrow publication hygiene check, not a substitute for DLP or human review."""
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
SKIP = {".git", ".venv", "venv", "__pycache__", ".pytest_cache", ".ruff_cache", "build", "dist", "htmlcov"}
FORBIDDEN = {".pem", ".key", ".p12", ".pfx", ".gds", ".gdsii", ".oas", ".oasis", ".sqlite3"}
PATTERNS = [re.compile(rb"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
            re.compile(rb"ghp_[A-Za-z0-9]{36}"), re.compile(rb"github_pat_[A-Za-z0-9_]{40,}")]


def scan(root: Path = ROOT) -> tuple[list[str], list[str]]:
    checked, problems = [], []
    for path in sorted(root.rglob("*")):
        relative = path.relative_to(root)
        if path.name in {".coverage", "coverage.xml"} or any(part in SKIP or part.endswith(".egg-info") for part in relative.parts):
            continue
        if path.is_symlink():
            problems.append(f"Symlink: {relative}")
            continue
        if path.is_dir():
            if path.name in {".opentapeout", "keys"}:
                problems.append(f"Private workspace/key directory: {relative}")
            continue
        if path.suffix.lower() in FORBIDDEN or path.name == ".env" or path.name.startswith(".env."):
            problems.append(f"Potential design data/secret: {relative}")
        if path.stat().st_size > 10 * 1024 * 1024:
            problems.append(f"Large file requires review: {relative}")
        else:
            data = path.read_bytes()
            if any(pattern.search(data) for pattern in PATTERNS):
                problems.append(f"Potential embedded credential: {relative}")
        checked.append(relative.as_posix())
    return checked, problems


def main() -> int:
    checked, problems = scan()
    print(f"Checked {len(checked)} source files. Heuristic findings: {len(problems)}")
    for problem in problems:
        print(problem)
    return 1 if problems else 0


if __name__ == "__main__":
    raise SystemExit(main())
