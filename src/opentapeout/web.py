"""Read-only local dashboard/API. All mutation and signing stay in the CLI/Python API."""
from __future__ import annotations

import secrets
from pathlib import Path

from . import __version__
from .engine import Engine
from .planning import plan, compare
from .graph import Graph
from .signing import Trust
from .util import TapeoutError, digest, read_json

STATIC = Path(__file__).parent / "static"


def summary(engine: Engine, policy: dict, trust: Trust) -> dict:
    state = engine.state()
    graph = Graph(state["resources"])
    drift = graph.drift(engine.root)
    candidates = []
    for name, candidate in state["candidates"].items():
        gate = engine.gate(name, policy, trust)
        candidates.append({"name": name, "sha256": digest(candidate), "notes": candidate["notes"],
                           "created_by": candidate["created_by"], "created_at": candidate["created_at"],
                           "deliveries": candidate["deliveries"], "gate": gate})
    resources = [{"id": key, **value, "fingerprint": graph.fingerprints[key],
                  "stale_reasons": graph.stale[key], "workspace_drift": drift.get(key)}
                 for key, value in state["resources"].items()]
    return {"project": state["project"], "resources": resources, "candidates": candidates,
            "runs": list(state["runs"].values()), "waivers": list(state["waivers"].values()),
            "approvals": state["approvals"], "releases": list(state["releases"].values()),
            "receipts": state["receipts"], "checkpoint": engine.store.verify_checkpoint(),
            "approval_states": [{"sha256": digest(a), "revoked": digest(a) in state["revoked_approvals"]} for a in state["approvals"]],
            "withdrawals": list(state["withdrawals"].values()), "delivery_capsules": list(state["deliveries"].values()),
            "signed_receipts": state["delivery_receipts"],
            "mode": "read-only", "synthetic": "SYNTHETIC" in state["project"]["name"]}


def create_app(root: Path, policy_file: Path | None = None, trust_file: Path | None = None,
               *, token: str | None = None):
    from fastapi import FastAPI, Request
    from fastapi.responses import FileResponse, JSONResponse
    from starlette.middleware.trustedhost import TrustedHostMiddleware

    engine = Engine(root)
    policy_file = policy_file or engine.root / "policy.json"
    trust_file = trust_file or engine.root / "trust.json"
    app = FastAPI(title="OpenTapeout read-only API", version=__version__, docs_url=None, redoc_url=None,
                  openapi_url=None)
    if not token:
        app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1", "[::1]", "testserver"])

    @app.middleware("http")
    async def protection(request: Request, call_next):
        if request.url.path.startswith("/api/") and token:
            header = request.headers.get("authorization", "")
            if not secrets.compare_digest(header, "Bearer " + token):
                return JSONResponse({"error": "Authentication required"}, status_code=401,
                                    headers={"Cache-Control": "no-store", "WWW-Authenticate": "Bearer"})
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Cache-Control"] = "no-store"
        response.headers["Content-Security-Policy"] = ("default-src 'self'; script-src 'self'; style-src 'self'; "
            "img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
        return response

    @app.exception_handler(TapeoutError)
    async def validation_error(request: Request, exc: TapeoutError):
        return JSONResponse({"error": str(exc)}, status_code=422)

    @app.exception_handler(OSError)
    async def io_error(request: Request, exc: OSError):
        return JSONResponse({"error": "Workspace or policy/trust file is unavailable"}, status_code=422)

    @app.get("/")
    def index():
        return FileResponse(STATIC / "index.html", media_type="text/html")

    @app.get("/static/{name}")
    def static(name: str):
        if name not in {"app.js", "control.js", "style.css"}:
            return JSONResponse({"error": "Not found"}, status_code=404)
        return FileResponse(STATIC / name)

    @app.get("/health")
    def health():
        return {"status": "ok", "mode": "read-only"}

    @app.get("/api/summary")
    def overview():
        return summary(engine, read_json(policy_file), Trust.from_file(trust_file))

    @app.get("/api/gate/{name}")
    def gate(name: str):
        return engine.gate(name, read_json(policy_file), Trust.from_file(trust_file))

    @app.get("/api/impact/{resource_id}")
    def impact(resource_id: str):
        return engine.impact(resource_id)

    @app.get("/api/diff/{before}/{after}")
    def diff(before: str, after: str):
        return engine.diff(before, after)

    @app.get("/api/plan")
    def rebuild_plan(name: str | None = None, changed: str = ""):
        return plan(engine, read_json(policy_file), Trust.from_file(trust_file),
                    candidate_name=name, changed=changed.split(",") if changed else [])

    @app.get("/api/compare/{before}/{after}")
    def compare_candidates(before: str, after: str):
        return compare(engine, before, after)

    @app.get("/api/audit")
    def audit():
        with engine.store.transaction() as tx:
            return {"checkpoint": tx.checkpoint, "events": tx.events}

    return app
