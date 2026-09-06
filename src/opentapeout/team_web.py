"""Optional multi-project API: access-token identity plus detached signed commands."""
from __future__ import annotations

import ipaddress
import logging
import sqlite3
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from . import __version__
from .engine import Engine, state_from
from .team import Gateway, MAX_COMMAND
from .team_auth import TeamError, require
from .util import TapeoutError, digest, ensure, loads

LOG = logging.getLogger("opentapeout.team")


def bearer(request: Request) -> str:
    values = request.headers.getlist("authorization")
    require(len(values) == 1 and values[0].startswith("Bearer "), "AUTHENTICATION",
            "Bearer access token required", 401)
    return values[0][7:]


def create_team_app(config_file: Path, *, allow_insecure_loopback: bool = False) -> FastAPI:
    gateway = Gateway(config_file)
    app = FastAPI(title="OpenTapeout team API", version=__version__, docs_url=None, redoc_url=None,
                  openapi_url=None)

    @app.middleware("http")
    async def protection(request: Request, call_next):
        insecure_local = False
        if allow_insecure_loopback and request.client:
            try:
                insecure_local = ipaddress.ip_address(request.client.host).is_loopback
            except ValueError:
                pass
        if request.url.scheme != "https" and not insecure_local:
            response = JSONResponse({"error": "TLS_REQUIRED", "message": "HTTPS is required"}, status_code=400)
        elif request.headers.get("origin") is not None:
            # No cookie authentication, browser cross-origin writes, or permissive CORS.
            response = JSONResponse({"error": "ORIGIN_NOT_ALLOWED"}, status_code=403)
        elif request.url.query and any(k in request.query_params for k in ("token", "access_token", "authorization")):
            response = JSONResponse({"error": "TOKEN_IN_URL_FORBIDDEN"}, status_code=400)
        else:
            response = await call_next(request)
        response.headers.update({"Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY", "Referrer-Policy": "no-referrer",
            "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
            "Strict-Transport-Security": "max-age=31536000"})
        return response

    @app.exception_handler(TeamError)
    async def team_error(request: Request, exc: TeamError):
        LOG.warning("team_request_rejected code=%s status=%s", exc.code, exc.status)
        headers = {"WWW-Authenticate": "Bearer"} if exc.status == 401 else {}
        return JSONResponse({"error": exc.code, "message": str(exc)}, status_code=exc.status, headers=headers)

    @app.exception_handler(TapeoutError)
    async def invalid(request: Request, exc: TapeoutError):
        # Detailed local exceptions may contain paths or project names; do not return them remotely.
        LOG.warning("team_request_rejected code=INVALID_OPERATION")
        return JSONResponse({"error": "INVALID_OPERATION", "message": "Operation failed validation or integrity checks"},
                            status_code=422)

    @app.exception_handler(OSError)
    async def unavailable(request: Request, exc: OSError):
        LOG.error("team_request_rejected code=GOVERNANCE_UNAVAILABLE")
        return JSONResponse({"error": "GOVERNANCE_UNAVAILABLE"}, status_code=503)

    @app.exception_handler(sqlite3.OperationalError)
    async def database_busy(request: Request, exc: sqlite3.OperationalError):
        LOG.error("team_request_rejected code=LEDGER_UNAVAILABLE")
        return JSONResponse({"error": "LEDGER_UNAVAILABLE"}, status_code=503, headers={"Retry-After": "1"})

    @app.get("/health")
    def health():
        return {"status": "ok", "mode": "team", "version": __version__}

    @app.get("/v1/projects")
    def projects(request: Request):
        identity = gateway.tokens.verify(bearer(request))
        result = []
        for slug, project in gateway.projects.items():
            _, _, access, _ = project.governance()
            try:
                project.member(identity, access, "read")
            except TeamError:
                continue
            result.append({"slug": slug, "project_id": project.project_id})
        return {"projects": result}

    @app.get("/v1/projects/{slug}/context")
    def context(slug: str, request: Request):
        return gateway.context(slug, bearer(request))

    def read(slug, request, mode, *, name=None, after=0, after_hash=None, limit=50, until=None, until_hash=None):
        identity = gateway.tokens.verify(bearer(request))
        project = gateway.project(slug)
        policy, trust, access, _ = project.governance()
        project.member(identity, access, "audit" if mode == "audit" else "read")
        ensure(0 <= after and 1 <= limit <= 100, "Invalid pagination bounds")
        engine = Engine(project.workspace)
        with engine.store.transaction() as tx:
            state = state_from(tx.events)
            ensure(state["project"]["id"] == project.project_id, "Workspace project ID mismatch")
            if mode == "receipt":
                record = state["team_commands"].get(name)
                require(record is not None, "NOT_FOUND", "Command receipt not found", 404)
                return {**record["response"], "checkpoint": record["checkpoint"], "historical": True}
            if mode == "gate":
                return engine._gate(tx, name, policy, trust)
            if mode == "candidate":
                require(name in state["candidates"], "NOT_FOUND", "Candidate not found", 404)
                candidate = state["candidates"][name]
                return {"candidate": candidate, "candidate_sha256": digest(candidate),
                        "approvals": [a for a in state["approvals"] if a["payload"]["candidate_sha256"] == digest(candidate)],
                        "revoked_approvals": sorted(state["revoked_approvals"]), "checkpoint": tx.checkpoint}
            if mode == "candidates":
                entries = list(state["candidates"].items())
                return {"candidates": [{"name": n, "candidate_sha256": digest(c), "created_by": c["created_by"],
                    "created_at": c["created_at"]} for n, c in entries[after:after+limit]],
                    "next_offset": after+limit if after+limit < len(entries) else None, "checkpoint": tx.checkpoint}
            # Cursor is pinned to a verified chain prefix and fixed end checkpoint, not an opaque offset.
            end = len(tx.events) if until is None else until
            ensure(after <= end <= len(tx.events), "Audit cursor out of range")
            if after:
                require(tx.events[after-1]["hash"] == after_hash, "CURSOR_MISMATCH", "Audit cursor hash mismatch", 409)
            if until is not None:
                ensure(end >= 1, "Audit end must include project genesis")
                require(tx.events[end-1]["hash"] == until_hash, "CURSOR_MISMATCH", "Audit end hash mismatch", 409)
            page = tx.events[after:min(end, after+limit)]
            last = page[-1] if page else (tx.events[after-1] if after else None)
            return {"events": page, "after": {"seq": last["seq"], "hash": last["hash"]} if last else None,
                    "until": {"seq": end, "hash": tx.events[end-1]["hash"]},
                    "complete": after+len(page) == end}

    @app.get("/v1/projects/{slug}/commands/{request_id}")
    def receipt(slug: str, request_id: str, request: Request):
        return read(slug, request, "receipt", name=request_id)

    @app.get("/v1/projects/{slug}/candidates")
    def candidates(slug: str, request: Request, offset: int = 0, limit: int = 50):
        return read(slug, request, "candidates", after=offset, limit=limit)

    @app.get("/v1/projects/{slug}/candidates/{name}")
    def candidate(slug: str, name: str, request: Request):
        return read(slug, request, "candidate", name=name)

    @app.get("/v1/projects/{slug}/gate/{name}")
    def gate(slug: str, name: str, request: Request):
        return read(slug, request, "gate", name=name)

    @app.get("/v1/projects/{slug}/audit")
    def audit(slug: str, request: Request, after: int = 0, after_hash: str | None = None,
              limit: int = 50, until: int | None = None, until_hash: str | None = None):
        return read(slug, request, "audit", after=after, after_hash=after_hash, limit=limit,
                    until=until, until_hash=until_hash)

    @app.post("/v1/projects/{slug}/commands")
    async def command(slug: str, request: Request):
        token = bearer(request)
        await run_in_threadpool(gateway.tokens.verify, token)
        # Authorize project visibility before accepting potentially expensive input.
        await run_in_threadpool(gateway.context, slug, token)
        require(request.headers.get("content-type", "").split(";")[0].strip() == "application/json",
                "CONTENT_TYPE", "application/json required", 415)
        require("content-encoding" not in request.headers, "CONTENT_ENCODING", "Encoded bodies not accepted", 415)
        raw = bytearray()
        async for chunk in request.stream():
            require(len(raw) + len(chunk) <= MAX_COMMAND, "BODY_TOO_LARGE", "Command exceeds 128 KiB", 413)
            raw.extend(chunk)
        envelope = loads(bytes(raw), limit=MAX_COMMAND)
        return await run_in_threadpool(gateway.execute, slug, token, envelope)

    return app
