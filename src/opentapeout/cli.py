"""Command-line interface. Exit 0=success, 1=invalid operation, 2=blocked gate."""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from . import __version__
from .bundle import seal, verify_bundle
from .commands import register as register_commands, dispatch as dispatch_commands
from .engine import Engine
from .git_capture import inspect_git
from .policy import default_policy
from .signing import Trust, generate_key, load_key, sign
from .util import TapeoutError, ensure, loads, now, read_json, write_json


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(prog="opentapeout", description="Verifiable tapeout evidence and release gates")
    root.add_argument("--version", action="version", version=__version__)
    root.add_argument("--root", type=Path, default=Path("."), help="Workspace directory")
    root.add_argument("--policy", type=Path, help="External release policy; default ROOT/policy.json")
    root.add_argument("--trust", type=Path, help="External trust store; default ROOT/trust.json")
    root.add_argument("--actor", default="operator", help="Local operator label; not an authenticated identity")
    sub = root.add_subparsers(dest="command", required=True)
    p = sub.add_parser("init", help="Initialize a ledger and strict six-check policy")
    p.add_argument("name")
    p = sub.add_parser("keygen", help="Create an Ed25519 key; optional OT_KEY_PASSWORD encryption")
    p.add_argument("output", type=Path)
    p = sub.add_parser("trust-key", help="Add a public key to the explicit trust store")
    p.add_argument("principal")
    p.add_argument("--public", type=Path, required=True, help="keygen JSON output file")
    p.add_argument("--roles", nargs="+", required=True)
    p = sub.add_parser("register", help="Hash a file or versioned metadata, with derivation dependencies")
    p.add_argument("id")
    p.add_argument("--kind", required=True)
    p.add_argument("--file", help="Workspace-relative file path")
    p.add_argument("--metadata", default="{}", help="JSON object or @JSON-file")
    p.add_argument("--depends", nargs="*", default=[])
    p = sub.add_parser("capture-tree", help="Hash and retain every file in a PDK or IP directory")
    p.add_argument("id")
    p.add_argument("directory", help="Workspace-relative directory; rejects symlinks")
    p.add_argument("--kind", required=True, choices=["pdk", "ip", "submodule", "other"])
    p.add_argument("--revision", required=True)
    p.add_argument("--depends", nargs="*", default=[])
    p = sub.add_parser("capture-git", help="Capture a clean repository and recursive submodule pins")
    p.add_argument("id")
    p.add_argument("repository", help="Workspace-relative actual Git repository root")
    for cmd in ("begin", "run"):
        p = sub.add_parser(cmd, help="Capture inputs" if cmd == "begin" else "Capture inputs and execute registered argv")
        p.add_argument("kind")
        p.add_argument("--inputs", nargs="+", required=True)
        p.add_argument("--tool", required=True)
        p.add_argument("--corner", required=True)
        if cmd == "run":
            p.add_argument("--report", required=True)
            p.add_argument("--format", choices=["json", "junit", "klayout-rdb", "csv", "yosys-sat"], default="json")
            p.add_argument("--timeout", type=float, default=3600)
    p = sub.add_parser("finish", help="Import a report for a previously captured run (unmanaged mode)")
    p.add_argument("run_id")
    p.add_argument("--report", required=True)
    p.add_argument("--exit-code", required=True, type=int)
    p.add_argument("--format", choices=["json", "junit", "klayout-rdb", "csv", "yosys-sat"], default="json")
    p = sub.add_parser("candidate", help="Freeze evidence and delivery scope")
    p.add_argument("name")
    p.add_argument("--notes", required=True, help="Release notes, or @UTF8-file")
    p.add_argument("--delivery", action="append", default=[], help="Delivery filename=layout-resource-id")
    p = sub.add_parser("gate", help="Check integrity, freshness, policy and signed approvals")
    p.add_argument("name")
    p.add_argument("--markdown", action="store_true", help="CI-friendly Markdown summary")
    p = sub.add_parser("approve", help="Sign exact candidate content for one authorized role")
    p.add_argument("name")
    p.add_argument("--role", required=True)
    p.add_argument("--key", required=True, type=Path)
    p = sub.add_parser("waive", help="Sign an expiring, evidence-bound individual violation waiver")
    p.add_argument("run_id")
    p.add_argument("fingerprint")
    p.add_argument("--reason", required=True)
    p.add_argument("--owner", required=True)
    p.add_argument("--expires", required=True)
    p.add_argument("--key", required=True, type=Path)
    p.add_argument("--attachment", action="append", default=[], help="Workspace-relative supporting evidence")
    p = sub.add_parser("revoke-waiver")
    p.add_argument("waiver_sha256")
    p.add_argument("--reason", required=True)
    p.add_argument("--key", required=True, type=Path)
    p = sub.add_parser("seal", help="Export FULL private evidence, signed manifest and GDS/OASIS deliveries")
    p.add_argument("name")
    p.add_argument("output", type=Path)
    p.add_argument("--key", required=True, type=Path)
    p = sub.add_parser("verify", help="Verify an archive offline against external policy and keys")
    p.add_argument("archive", type=Path)
    p.add_argument("--status", type=Path, help="Fresh externally supplied signed release-status statement")
    p.add_argument("--min-status-seq", type=int, default=0, help="Externally retained anti-replay high-water sequence")
    p = sub.add_parser("receipt", help="Compare an operator-supplied foundry upload checksum")
    p.add_argument("release")
    p.add_argument("--sha256", required=True)
    p.add_argument("--reference", required=True)
    p = sub.add_parser("impact", help="Explain downstream dependency impact and affected runs")
    p.add_argument("resource")
    p = sub.add_parser("diff", help="Compare two immutable candidates")
    p.add_argument("before")
    p.add_argument("after")
    p = sub.add_parser("audit", help="Verify hash chain, optionally against an external signed checkpoint")
    p.add_argument("--checkpoint", type=Path)
    p = sub.add_parser("checkpoint", help="Sign a checkpoint; retain externally to detect truncation")
    p.add_argument("--key", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    sub.add_parser("status", help="Inspect current project and evidence")
    p = sub.add_parser("demo", help="Create a synthetic, six-check example and real signature workflow")
    p.add_argument("destination", type=Path)
    p.add_argument("--stale", action="store_true", help="Apply a netlist ECO after successful approval")
    p = sub.add_parser("serve", help="Read-only dashboard/API; never exposes signing operations")
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8080)
    register_commands(sub)
    return root


def markdown_gate(report: dict) -> str:
    from html import escape
    lines = ["## OpenTapeout — " + ("READY" if report["ready"] else "BLOCKED"), "",
             f"Candidate digest: `{report['candidate_sha256']}`", "", "| Check | State |", "|---|---|"]
    for check in report["checks"]:
        lines.append(f"| {escape(check['check']).replace('|', '&#124;')} | {check['status']} |")
    if report["blockers"]:
        lines.extend(["", "### Release blockers"])
        for blocker in report["blockers"]:
            text = escape(blocker["message"]).replace("\n", " ")
            lines.append(f"- **{blocker['code']}**: {text}")
    return "\n".join(lines) + "\n"


def dispatch(args: argparse.Namespace) -> tuple[object, int]:
    policy_path = args.policy or args.root / "policy.json"
    trust_path = args.trust or args.root / "trust.json"
    def policy() -> dict:
        return read_json(policy_path)
    def trust() -> Trust:
        return Trust.from_file(trust_path)
    def key():
        password = os.environ.get("OT_KEY_PASSWORD")
        return load_key(args.key, password.encode() if password else None)
    cmd = args.command
    extended = dispatch_commands(args, policy, trust, key)
    if extended is not None:
        return extended
    if cmd == "keygen":
        password = os.environ.get("OT_KEY_PASSWORD")
        return generate_key(args.output, password=password.encode() if password else None), 0
    if cmd == "trust-key":
        public = read_json(args.public)
        data = read_json(trust_path) if trust_path.exists() else {"schema": "opentapeout.trust/v1", "keys": {}}
        ensure(public["key_id"] not in data["keys"], "Key already exists; edit trust deliberately for changes/revocation")
        data["keys"][public["key_id"]] = {"principal": args.principal, "roles": args.roles,
                                            "public_key": public["public_key"]}
        Trust(data)
        write_json(trust_path, data, overwrite=trust_path.exists())
        return {"trust_store": str(trust_path), "added": public["key_id"]}, 0
    if cmd == "demo":
        from .demo import build_demo
        return build_demo(args.destination, stale=args.stale), 0
    if cmd == "init":
        engine = Engine.init(args.root, args.name, args.actor)
        if not policy_path.exists():
            write_json(policy_path, default_policy())
        return {"project": engine.state()["project"], "policy": str(policy_path),
                "next": "Generate reviewer keys, add their public keys to trust.json, and register inputs."}, 0
    if cmd == "verify":
        return verify_bundle(args.archive, policy(), trust(),
            status=read_json(args.status) if args.status else None, minimum_status_sequence=args.min_status_seq), 0
    engine = Engine(args.root)
    if cmd == "register":
        metadata = read_json(args.metadata[1:]) if args.metadata.startswith("@") else loads(args.metadata)
        return engine.register(args.id, args.kind, path=args.file, metadata=metadata,
                               depends_on=args.depends, actor=args.actor), 0
    if cmd == "capture-tree":
        return engine.register_tree(args.id, args.kind, args.directory, version=args.revision,
                                    depends_on=args.depends, actor=args.actor), 0
    if cmd == "capture-git":
        metadata = inspect_git(engine.root, args.repository)
        ensure(not metadata["dirty"], "Cannot capture a dirty Git worktree")
        return engine.register(args.id, "git", metadata=metadata, actor=args.actor), 0
    if cmd == "begin":
        return {"run_id": engine.begin(args.kind, args.inputs, args.tool, args.corner, args.actor)}, 0
    if cmd == "run":
        result = engine.run(args.kind, args.inputs, args.tool, args.corner, args.report, format_name=args.format,
                            timeout=args.timeout, actor=args.actor)
        successful = result["exit_code"] == 0 and result["result"]["status"] == "pass" and not result["input_drift"]
        return result, 0 if successful else 2
    if cmd == "finish":
        result = engine.finish(args.run_id, args.report, exit_code=args.exit_code,
                               format_name=args.format, actor=args.actor)
        return result, 0 if result["result"]["status"] == "pass" and args.exit_code == 0 and not result["input_drift"] else 2
    if cmd == "candidate":
        deliveries = {}
        for assignment in args.delivery:
            ensure("=" in assignment, "Delivery syntax is filename=resource-id")
            filename, rid = assignment.split("=", 1)
            ensure(filename not in deliveries, "Duplicate delivery name")
            deliveries[filename] = rid
        notes = Path(args.notes[1:]).read_text() if args.notes.startswith("@") else args.notes
        return {"candidate_sha256": engine.candidate(args.name, notes, deliveries, policy(), trust(), args.actor)}, 0
    if cmd == "gate":
        result = engine.gate(args.name, policy(), trust())
        return markdown_gate(result) if args.markdown else result, 0 if result["ready"] else 2
    if cmd == "approve":
        return engine.approve(args.name, args.role, key(), policy(), trust()), 0
    if cmd == "waive":
        attachments = [engine.attach(path) for path in args.attachment]
        return {"waiver_sha256": engine.waive(args.run_id, args.fingerprint, args.reason, args.owner,
                args.expires, key(), trust(), attachments=attachments)}, 0
    if cmd == "revoke-waiver":
        engine.revoke_waiver(args.waiver_sha256, args.reason, key(), trust())
        return {"revoked": args.waiver_sha256}, 0
    if cmd == "seal":
        print("WARNING: Full evidence archives may contain confidential source, PDK material and tool logs.", file=sys.stderr)
        return seal(engine, args.name, args.output, key(), policy(), trust()), 0
    if cmd == "receipt":
        return engine.receipt(args.release, args.sha256, args.reference, args.actor), 0
    if cmd == "impact":
        return engine.impact(args.resource), 0
    if cmd == "diff":
        return engine.diff(args.before, args.after), 0
    if cmd == "audit":
        expected = None
        if args.checkpoint:
            body, _ = trust().verify(read_json(args.checkpoint), role="release", statement_type="opentapeout.checkpoint/v1")
            ensure(body["project_id"] == engine.state()["project"]["id"], "Checkpoint project mismatch")
            expected = body["checkpoint"]
        return engine.store.verify_checkpoint(expected), 0
    if cmd == "checkpoint":
        body = {"type": "opentapeout.checkpoint/v1", "project_id": engine.state()["project"]["id"],
                "checkpoint": engine.store.verify_checkpoint(), "created_at": now()}
        envelope = sign(body, key())
        trust().verify(envelope, role="release", statement_type="opentapeout.checkpoint/v1")
        write_json(args.output, envelope)
        return {"checkpoint": str(args.output)}, 0
    if cmd == "status":
        from .web import summary
        return summary(engine, policy(), trust()), 0
    if cmd == "serve":
        try:
            import uvicorn
            from .web import create_app
        except ImportError as exc:
            raise TapeoutError("Install the web extra: python -m pip install 'opentapeout[web]'") from exc
        token = os.environ.get("OPENTAPEOUT_API_TOKEN")
        ensure(args.host in {"127.0.0.1", "localhost", "::1"} or (token is not None and len(token) >= 32),
               "Non-loopback binding requires OPENTAPEOUT_API_TOKEN (32+ characters) and a TLS reverse proxy")
        uvicorn.run(create_app(engine.root, policy_path, trust_path, token=token), host=args.host, port=args.port)
        return None, 0
    raise TapeoutError("Unknown command")


def main(argv: list[str] | None = None) -> int:
    args = parser().parse_args(argv)
    try:
        result, code = dispatch(args)
        if isinstance(result, str):
            print(result, end="" if result.endswith("\n") else "\n")
        elif result is not None:
            print(json.dumps(result, indent=2, sort_keys=True, ensure_ascii=False))
        return code
    except (TapeoutError, OSError, KeyError) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
