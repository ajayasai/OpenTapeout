"""Offline command signing and explicit HTTPS transport; tokens are read from env only."""
from __future__ import annotations

import os
from pathlib import Path
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener
import ipaddress

from .signing import load_key, sign
from .team import ACTIONS, make_command
from .util import MAX_JSON_BYTES, TapeoutError, canonical, digest, ensure, loads, now, read_json, write_json

COMMANDS = {"serve-team", "team-sign", "team-approve", "team-get", "team-submit"}


def register(sub) -> None:
    p = sub.add_parser("serve-team", help="Project-scoped team API; requires external configuration and access tokens")
    p.add_argument("--config", type=Path, required=True)
    p.add_argument("--host", default="127.0.0.1")
    p.add_argument("--port", type=int, default=8081)
    p.add_argument("--ssl-keyfile", type=Path)
    p.add_argument("--ssl-certfile", type=Path)
    p.add_argument("--allow-insecure-loopback", action="store_true", help="Local development only, rejects non-loopback peers")
    for name in ("team-sign", "team-approve"):
        p = sub.add_parser(name, help="Sign an exact command locally; never upload a private reviewer key")
        p.add_argument("--context", type=Path, required=True)
        p.add_argument("--key", type=Path, required=True)
        p.add_argument("--output", type=Path, required=True)
        if name == "team-sign":
            p.add_argument("--action", choices=sorted(ACTIONS), required=True)
            source = p.add_mutually_exclusive_group(required=True)
            source.add_argument("--parameters", type=Path, help="Exact command parameters JSON")
            source.add_argument("--statement", type=Path, help="Unsigned decision JSON to sign with the same key")
        else:
            p.add_argument("--candidate", type=Path, required=True, help="Downloaded candidate-details JSON")
            p.add_argument("--role", required=True)
    for name in ("team-get", "team-submit"):
        p = sub.add_parser(name, help="Explicit authenticated request; HTTPS, no redirects, no tokens in arguments")
        p.add_argument("--url", required=True)
        p.add_argument("--output", type=Path, required=True)
        p.add_argument("--token-env", default="OT_ACCESS_TOKEN")
        p.add_argument("--allow-http-loopback", action="store_true", help="Development on a literal loopback IP only")
        if name == "team-submit":
            p.add_argument("--command-file", type=Path, required=True)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise TapeoutError("Redirect refused; use the exact trusted API address")


def request_json(url: str, token: str, command: dict | None = None, *, allow_http_loopback: bool = False) -> dict:
    parsed = urlsplit(url)
    local = False
    try:
        local = ipaddress.ip_address(parsed.hostname or "").is_loopback
    except ValueError:
        pass
    ensure(parsed.scheme == "https" or (parsed.scheme == "http" and local and allow_http_loopback), "HTTPS API URL required")
    ensure(parsed.hostname and not parsed.username and not parsed.password and not parsed.fragment
           and not set(parse_qs(parsed.query)) & {"token", "access_token", "authorization"}, "Unsafe API URL")
    ensure(isinstance(token, str) and 0 < len(token) <= 16384 and not any(c.isspace() for c in token),
           "Access token missing or malformed; supply it through the selected environment variable")
    headers = {"Authorization": "Bearer " + token, "Accept": "application/json"}
    data = None
    if command is not None:
        data = canonical(command)
        headers["Content-Type"] = "application/json"
    try:
        with build_opener(NoRedirect).open(Request(url, data=data, headers=headers), timeout=20) as response:
            result = loads(response.read(MAX_JSON_BYTES+1))
            ensure(isinstance(result, dict), "API response must be an object")
            return result
    except HTTPError as exc:
        # Do not echo server-controlled error text or potentially credential-bearing URLs.
        raise TapeoutError(f"Team API rejected request (HTTP {exc.code}); no automatic retry or re-signing") from exc
    except OSError as exc:
        raise TapeoutError("Team API connection failed; verify the trusted address and TLS configuration") from exc


def dispatch(args):
    if args.command not in COMMANDS:
        return None
    if args.command == "serve-team":
        import uvicorn
        from .team_web import create_team_app
        ensure(bool(args.ssl_certfile) == bool(args.ssl_keyfile), "TLS certificate and key must be supplied together")
        if args.allow_insecure_loopback:
            ensure(args.host in {"127.0.0.1", "::1"}, "Development HTTP may bind only a literal loopback address")
        ensure(args.ssl_certfile or args.allow_insecure_loopback,
               "Supply TLS certificate/key or explicitly enable local development HTTP")
        app = create_team_app(args.config, allow_insecure_loopback=args.allow_insecure_loopback)
        # No untrusted Forwarded/X-Forwarded-* identity/scheme headers; no query-bearing access logs.
        uvicorn.run(app, host=args.host, port=args.port, proxy_headers=False, access_log=False,
                    ssl_certfile=str(args.ssl_certfile) if args.ssl_certfile else None,
                    ssl_keyfile=str(args.ssl_keyfile) if args.ssl_keyfile else None,
                    timeout_keep_alive=5, limit_concurrency=32)
        return None, 0
    if args.command in {"team-get", "team-submit"}:
        command = read_json(args.command_file) if args.command == "team-submit" else None
        ensure(not args.output.exists(), "Refusing to overwrite response file")
        result = request_json(args.url, os.environ.get(args.token_env, ""), command,
                              allow_http_loopback=args.allow_http_loopback)
        write_json(args.output, result)
        return {"response_file": str(args.output)}, 0
    password = os.environ.get("OT_KEY_PASSWORD")
    key = load_key(args.key, password.encode() if password else None)
    context = read_json(args.context)
    if args.command == "team-approve":
        details = read_json(args.candidate)
        candidate = details["candidate"]
        ensure(digest(candidate) == details["candidate_sha256"], "Candidate content/digest mismatch")
        ensure(candidate["project_id"] == context["project_id"], "Candidate/context project mismatch")
        statement = sign({"type": "opentapeout.approval/v1", "project_id": context["project_id"],
            "candidate_sha256": digest(candidate), "role": args.role, "decision": "approve", "created_at": now()}, key)
        envelope = make_command(context, "approval.submit", {"statement": statement}, key)
    else:
        if args.statement:
            body = read_json(args.statement)
            ensure(isinstance(body, dict), "Unsigned statement must be an object")
            statement = sign({"created_at": now(), **body}, key)
            parameters = {"statement": statement}
        else:
            parameters = read_json(args.parameters)
        envelope = make_command(context, args.action, parameters, key)
    write_json(args.output, envelope)
    return {"command_file": str(args.output), "request_id": envelope["payload"]["request_id"],
            "review_required": "Review exact candidate, policy, permissions and statement before submission"}, 0
