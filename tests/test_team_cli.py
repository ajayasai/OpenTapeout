from __future__ import annotations

import os
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from threading import Thread
import json
from types import SimpleNamespace
from urllib.error import HTTPError

import pytest
from cryptography.hazmat.primitives import serialization

from opentapeout.cli import dispatch, parser
from opentapeout.team_cli import request_json, NoRedirect
from opentapeout.team import make_command
from opentapeout.util import TapeoutError, read_json, write_json, digest, now
from test_team import team, rsa_key  # shared real-key fixtures


def invoke(arguments):
    return dispatch(parser().parse_args(arguments))


def keyfile(team, principal):
    path=team.folder/(principal+".pem")
    path.write_bytes(team.ctx.keys[principal].private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    return str(path)


def test_cli_signed_creation(team):
    context=team.gateway.context("chip",team.token())
    write_json(team.folder/"context.json",context)
    write_json(team.folder/"params.json",{"name":"CLI-RC", "notes":"CLI synthetic release", "deliveries":{}})
    result,code=invoke(["team-sign","--context",str(team.folder/"context.json"),"--key",keyfile(team,"author"),
        "--action","candidate.create","--parameters",str(team.folder/"params.json"),"--output",str(team.folder/"command.json")])
    assert code==0 and result["request_id"]
    response=team.gateway.execute("chip",team.token(),read_json(team.folder/"command.json"))
    assert response["result"]["name"]=="CLI-RC"


def test_cli_approve(team):
    team.ctx.run();team.ctx.candidate()
    candidate=team.ctx.engine.state()["candidates"]["RC1"]
    write_json(team.folder/"context.json",team.gateway.context("chip",team.token("alice")))
    write_json(team.folder/"candidate.json",{"candidate":candidate,"candidate_sha256":digest(candidate)})
    result,code=invoke(["team-approve","--context",str(team.folder/"context.json"),"--key",keyfile(team,"alice"),
        "--candidate",str(team.folder/"candidate.json"),"--role","physical","--output",str(team.folder/"approve.json")])
    assert code==0
    team.gateway.execute("chip",team.token("alice"),read_json(team.folder/"approve.json"))
    assert len(team.ctx.engine.state()["approvals"])==1


def test_cli_sign_statement(team):
    team.ctx.ready()
    original=team.ctx.engine.state()["approvals"][0]
    write_json(team.folder/"context.json",team.gateway.context("chip",team.token("alice")))
    write_json(team.folder/"statement.json",{"type":"opentapeout.approval-revocation/v1", "project_id":team.project_id,
        "approval_sha256":digest(original),"candidate_sha256":original["payload"]["candidate_sha256"],
        "reason":"Revoked through signed team CLI command"})
    result,code=invoke(["team-sign","--context",str(team.folder/"context.json"),"--key",keyfile(team,"alice"),
        "--action","approval.revoke","--statement",str(team.folder/"statement.json"),"--output",str(team.folder/"revoke.json")])
    assert code==0
    assert team.gateway.execute("chip",team.token("alice"),read_json(team.folder/"revoke.json"))["result"]["revoked_approval"]


@pytest.mark.parametrize("url",["http://example.com/x","ftp://example.com","https://user:pass@example.com", 
    "https://example.com/#fragment","https://example.com/?access_token=x","http://localhost/test"])
def test_client_unsafe_urls(url):
    with pytest.raises(TapeoutError):request_json(url,"token",allow_http_loopback=True)


@pytest.mark.parametrize("token",["","bad token","x\ny","x"*16385])
def test_client_unsafe_token(token):
    with pytest.raises(TapeoutError):request_json("https://example.test",token)


def test_client_redirect_rejected():
    with pytest.raises(TapeoutError,match="Redirect refused"):
        NoRedirect().redirect_request(None,None,302,"",{},"https://evil.example")


def test_client_and_cli_real_http_transport(team,monkeypatch):
    seen=[]
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.headers.get("Authorization"))
            if self.path=="/reject":self.send_error(403);return
            if self.path=="/redirect":
                self.send_response(302);self.send_header("Location","https://evil.example");self.end_headers();return
            self.send_response(200);self.end_headers();self.wfile.write(b'{"ok":true}')
        def do_POST(self):
            seen.append(json.loads(self.rfile.read(int(self.headers["Content-Length"]))))
            self.do_GET()
        def log_message(self,*args):pass
    server=ThreadingHTTPServer(("127.0.0.1",0),Handler)
    thread=Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        url=f"http://127.0.0.1:{server.server_port}"
        monkeypatch.setenv("OT_ACCESS_TOKEN","test-token")
        output=team.folder/"response.json"
        assert invoke(["team-get","--url",url,"--output",str(output),"--allow-http-loopback"])[1]==0
        assert read_json(output)=={"ok":True} and seen==["Bearer test-token"]
        write_json(team.folder/"command.json",team.command())
        assert invoke(["team-submit","--url",url,"--output",str(team.folder/"post.json"),
            "--command-file",str(team.folder/"command.json"),"--allow-http-loopback"])[1]==0
        assert isinstance(seen[1],dict)
        with pytest.raises(TapeoutError,match="HTTP 403"):request_json(url+"/reject","t",allow_http_loopback=True)
        with pytest.raises(TapeoutError,match="Redirect refused"):request_json(url+"/redirect","t",allow_http_loopback=True)
    finally:
        server.shutdown();server.server_close();thread.join(timeout=5)
    with pytest.raises(TapeoutError,match="connection failed"):
        request_json(url,"t",allow_http_loopback=True)


def test_serve_team_safe_defaults(team,monkeypatch):
    import uvicorn
    calls=[];monkeypatch.setattr(uvicorn,"run",lambda *a,**kw:calls.append(kw))
    with pytest.raises(TapeoutError):invoke(["serve-team","--config",str(team.path)])
    with pytest.raises(TapeoutError):invoke(["serve-team","--config",str(team.path),"--allow-insecure-loopback","--host","0.0.0.0"])
    with pytest.raises(TapeoutError):invoke(["serve-team","--config",str(team.path),"--ssl-certfile","cert.pem"])
    assert invoke(["serve-team","--config",str(team.path),"--allow-insecure-loopback"])[1]==0
    assert not calls[-1]["proxy_headers"] and not calls[-1]["access_log"]
    assert invoke(["serve-team","--config",str(team.path),"--ssl-certfile","cert.pem","--ssl-keyfile","tls.pem"])[1]==0
    assert calls[-1]["ssl_keyfile"]=="tls.pem"


@pytest.mark.parametrize("seconds",[0,True,301])
def test_signing_limits(team,seconds):
    with pytest.raises(TapeoutError):team.command(valid_seconds=seconds)
