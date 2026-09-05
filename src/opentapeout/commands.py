"""Extended CLI commands. Offline verifiers never require a local workspace."""
from pathlib import Path

from .delivery import (disclosure_template, record_receipt, seal_delivery, sign_receipt, verify_delivery)
from .engine import Engine
from .lifecycle import export_status, revoke_approval, withdraw_release
from .planning import compare, plan
from .util import read_json, write_json

COMMANDS = {"plan", "compare", "revoke-approval", "withdraw", "release-status", "disclosure",
            "deliver", "verify-delivery", "sign-receipt", "record-receipt", "pin-policy"}


def register(sub) -> None:
    p = sub.add_parser("pin-policy", help="Write an exact-input policy v2 for review; never authorizes release")
    p.add_argument("--output", required=True, type=Path)
    p = sub.add_parser("plan", help="Explain rebuild order and reusable checks; never executes or authorizes")
    p.add_argument("name", nargs="?")
    p.add_argument("--changed", nargs="*", default=[], help="Read-only hypothetical resource changes")
    p = sub.add_parser("compare", help="Compare immutable candidates, checks and numerical metric deltas")
    p.add_argument("before")
    p.add_argument("after")
    for cmd, help_text in (("revoke-approval", "Revoke one exact approval as its reviewer or release-admin"),
                           ("withdraw", "Irreversibly withdraw a sealed release; preserve historical evidence")):
        p = sub.add_parser(cmd, help=help_text)
        p.add_argument("target")
        p.add_argument("--reason", required=True)
        p.add_argument("--key", required=True, type=Path)
    p = sub.add_parser("release-status", help="Sign a short-lived status snapshot for offline revocation checking")
    p.add_argument("--key", required=True, type=Path)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--valid-hours", type=float, default=1)
    p = sub.add_parser("disclosure", help="Generate an explicit delivery allowlist for operator review")
    p.add_argument("name")
    p.add_argument("--recipient", required=True)
    p.add_argument("--output", required=True, type=Path)
    p = sub.add_parser("deliver", help="Export only explicitly allowlisted GDS/OASIS delivery bytes")
    p.add_argument("release")
    p.add_argument("delivery_id")
    p.add_argument("output", type=Path)
    p.add_argument("--disclosure", required=True, type=Path)
    p.add_argument("--key", required=True, type=Path)
    p = sub.add_parser("verify-delivery", help="Verify recipient, signature and allowlisted bytes; NOT withheld signoff")
    p.add_argument("archive", type=Path)
    p.add_argument("--disclosure", required=True, type=Path)
    p = sub.add_parser("sign-receipt", help="Designated recipient verifies bytes and signs an acknowledgment")
    p.add_argument("archive", type=Path)
    p.add_argument("--disclosure", required=True, type=Path)
    p.add_argument("--key", required=True, type=Path)
    p.add_argument("--reference", required=True)
    p.add_argument("--output", required=True, type=Path)
    p = sub.add_parser("record-receipt", help="Verify and record a designated recipient's signed acknowledgment")
    p.add_argument("receipt", type=Path)


def dispatch(args, policy, trust, key):
    cmd = args.command
    if cmd not in COMMANDS:
        return None
    if cmd == "verify-delivery":
        return verify_delivery(args.archive, read_json(args.disclosure), trust()), 0
    if cmd == "sign-receipt":
        envelope = sign_receipt(args.archive, read_json(args.disclosure), trust(), key(), args.reference)
        write_json(args.output, envelope)
        return {"receipt": str(args.output), "signature": envelope}, 0
    engine = Engine(args.root)
    if cmd == "pin-policy":
        from .pinning import pin_policy
        value = pin_policy(engine, policy())
        write_json(args.output, value)
        return {"policy": str(args.output), "review_required": True,
                "warning": "Review every input, tool, rule and corner. Pinning does not infer missing dependencies or authorize release."}, 0
    if cmd == "plan":
        return plan(engine, policy(), trust(), candidate_name=args.name, changed=args.changed), 0
    if cmd == "compare":
        return compare(engine, args.before, args.after), 0
    if cmd == "revoke-approval":
        return revoke_approval(engine, args.target, args.reason, key(), trust()), 0
    if cmd == "withdraw":
        return withdraw_release(engine, args.target, args.reason, key(), trust()), 0
    if cmd == "release-status":
        envelope = export_status(engine, key(), trust(), valid_hours=args.valid_hours)
        write_json(args.output, envelope)
        return {"status": str(args.output), "checkpoint": envelope["payload"]["checkpoint"]}, 0
    if cmd == "disclosure":
        value = disclosure_template(engine, args.name, args.recipient)
        write_json(args.output, value)
        return {"disclosure": str(args.output), "review_required": True,
                "warning": "Review recipient, aliases, exact hashes, content and license obligations before delivery."}, 0
    if cmd == "deliver":
        return seal_delivery(engine, args.release, args.delivery_id, args.output, read_json(args.disclosure),
                             key(), policy(), trust()), 0
    if cmd == "record-receipt":
        return record_receipt(engine, read_json(args.receipt), trust()), 0
    raise AssertionError("Unhandled extended command")
