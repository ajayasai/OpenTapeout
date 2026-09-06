#!/usr/bin/env python3
"""Execute a real HTTP team-review workflow with ephemeral keys and SYNTHETIC EDA.

No IdP account, production design, network service, or private key is published.
The server uses a temporary loopback TLS certificate, not a production IdP deployment.
"""
from __future__ import annotations

import argparse
import json
import os
import ipaddress
from datetime import datetime, timedelta, timezone
import socket
import subprocess
import sys
import tempfile
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography import x509
from cryptography.x509.oid import NameOID

from opentapeout import __version__
from opentapeout.bundle import seal, verify_bundle
from opentapeout.demo import build_demo
from opentapeout.engine import Engine
from opentapeout.signing import Trust, generate_key, load_key, sign
from opentapeout.team import make_command
from opentapeout.team_cli import request_json
from opentapeout.util import TapeoutError, digest, ensure, now, read_json, write_json


def qualify(root: Path) -> dict:
    workspace, config = root/"workspace", root/"config"
    config.mkdir(parents=True)
    build_demo(workspace)
    engine = Engine(workspace)
    project_id = engine.state()["project"]["id"]
    policy = read_json(workspace/"policy.json")
    trust = read_json(workspace/"trust.json")
    for entry in trust["keys"].values():
        entry["roles"].append("team")
    author = generate_key(config/"author.pem")
    trust["keys"][author["key_id"]] = {"principal":"release-author", "public_key":author["public_key"], "roles":["team"]}
    keys = {"release-author":load_key(config/"author.pem")}
    for principal in ("physical-reviewer","verification-reviewer","release-engineer"):
        keys[principal] = load_key(workspace/"keys"/(principal+".pem"))
    write_json(config/"policy.json",policy)
    write_json(config/"trust.json",trust)
    access={"schema":"opentapeout.team-access/v1","project_id":project_id,"members":{}}
    for principal, permissions in [("release-author",["candidate.create"]), ("physical-reviewer",["approval.submit","approval.revoke"]),
            ("verification-reviewer",["approval.submit"]), ("release-engineer",["release.withdraw"]), ("reader",[])]:
        access["members"]["sub:"+principal]={"principal":principal,"permissions":["read",*permissions]}
    write_json(config/"access.json",access)
    issuer_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    jwk=jwt.algorithms.RSAAlgorithm.to_jwk(issuer_key.public_key(),as_dict=True)
    jwk.update(kid="ephemeral-test-issuer",use="sig",alg="RS256")
    write_json(config/"jwks.json",{"keys":[jwk]})
    write_json(config/"team.json",{"schema":"opentapeout.team/v1","identity":{
        "issuer":"https://synthetic-issuer.example.invalid","audience":"opentapeout-qualification",
        "jwks_file":str(config/"jwks.json"),"client_ids":["qualification"],"max_lifetime_seconds":600},"projects":{
        "synthetic":{"project_id":project_id,"workspace":str(workspace),"policy":str(config/"policy.json"),
            "trust":str(config/"trust.json"),"access":str(config/"access.json")}}})
    def token(principal):
        at=int(time.time())
        return jwt.encode({"iss":"https://synthetic-issuer.example.invalid","aud":"opentapeout-qualification",
            "sub":"sub:"+principal,"iat":at,"exp":at+300,"jti":str(uuid.uuid4()),"client_id":"qualification",
            "scope":"opentapeout:read opentapeout:write"},issuer_key,algorithm="RS256",
            headers={"kid":"ephemeral-test-issuer","typ":"at+jwt"})
    with socket.socket() as sock:
        sock.bind(("127.0.0.1",0));port=sock.getsockname()[1]
    tls_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,"OpenTapeout ephemeral TLS test")])
    at=datetime.now(timezone.utc)
    cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(tls_key.public_key())
        .serial_number(x509.random_serial_number()).not_valid_before(at-timedelta(minutes=1))
        .not_valid_after(at+timedelta(hours=1))
        .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]),critical=False)
        .add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True).sign(tls_key,hashes.SHA256()))
    (config/"tls.pem").write_bytes(tls_key.private_bytes(serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    (config/"tls.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    previous_ca=os.environ.get("SSL_CERT_FILE")
    url=f"https://127.0.0.1:{port}/v1/projects/synthetic"
    def request(path,principal="release-author",body=None):
        return request_json(url+path,token(principal),body)
    with (config/"server.log").open("wb") as log:
        server=subprocess.Popen([sys.executable,"-m","opentapeout","serve-team","--config",str(config/"team.json"),
            "--port",str(port),"--ssl-certfile",str(config/"tls.crt"),"--ssl-keyfile",str(config/"tls.pem")],stdout=log,stderr=log)
        try:
            deadline=time.monotonic()+20
            while True:
                try:
                    with socket.create_connection(("127.0.0.1",port),timeout=0.2):
                        pass
                    break
                except OSError:
                    ensure(server.poll() is None and time.monotonic()<deadline,"Local qualification server did not start")
                    time.sleep(0.1)
            try:
                request("/context")
            except TapeoutError:
                untrusted_tls_rejected=True
            else:
                raise TapeoutError("An untrusted TLS certificate was accepted")
            os.environ["SSL_CERT_FILE"]=str(config/"tls.crt")
            context=request("/context")
            create=make_command(context,"candidate.create",{"name":"RC-TEAM","notes":"SYNTHETIC team qualification",
                "deliveries":{"synthetic.gds":"layout"}},keys["release-author"])
            first=request("/commands",body=create)
            repeat=request("/commands",body=create)
            ensure(repeat["replayed"] and repeat["checkpoint"]==first["checkpoint"],"Duplicate retry changed ledger")
            try:
                request("/commands","physical-reviewer",create)
            except TapeoutError:
                spoof_blocked=True
            else:
                raise TapeoutError("Mismatched bearer and signing identity was accepted")
            details=request("/candidates/RC-TEAM")
            for principal,role in [("physical-reviewer","physical"),("verification-reviewer","verification")]:
                decision=sign({"type":"opentapeout.approval/v1","project_id":project_id,
                    "candidate_sha256":details["candidate_sha256"],"role":role,"decision":"approve","created_at":now()},keys[principal])
                command=make_command(request("/context",principal),"approval.submit",{"statement":decision},keys[principal])
                request("/commands",principal,command)
            ensure(request("/gate/RC-TEAM","reader")["ready"],"Two-reviewer API release did not pass")
            trust_object=Trust(trust)
            seal(engine,"RC-TEAM",config/"private-evidence.zip",keys["release-engineer"],policy,trust_object)
            verified=verify_bundle(config/"private-evidence.zip",policy,trust_object)["verified"]
            concurrent_context=request("/context")
            commands=[make_command(concurrent_context,"candidate.create",{"name":f"RACE-{i}","notes":"SYNTHETIC race",
                "deliveries":{}},keys["release-author"]) for i in range(8)]
            def race(command):
                try:
                    request("/commands",body=command);return "committed"
                except TapeoutError as exc:
                    ensure("HTTP 409" in str(exc),"Unexpected concurrency failure")
                    return "conflict"
            with ThreadPoolExecutor(max_workers=8) as pool:
                races=list(pool.map(race,commands))
            ensure(races.count("committed")==1 and races.count("conflict")==7,"Concurrent writes lost updates")
            original=next(a for a in engine.state()["approvals"] if a["payload"]["candidate_sha256"]==details["candidate_sha256"])
            revoke=sign({"type":"opentapeout.approval-revocation/v1","project_id":project_id,
                "approval_sha256":digest(original),"candidate_sha256":details["candidate_sha256"],
                "reason":"Synthetic reviewer withdrew this exact decision","created_at":now()},keys["physical-reviewer"])
            request("/commands","physical-reviewer",make_command(request("/context","physical-reviewer"),
                "approval.revoke",{"statement":revoke},keys["physical-reviewer"]))
            ensure(not request("/gate/RC-TEAM","reader")["ready"],"Revoked review did not block live authorization")
            return {"qualified":True,"version":__version__,"scope":"synthetic EDA; real loopback HTTPS, RSA tokens, Ed25519 reviews and SQLite transactions",
                "transport":"verified loopback HTTPS with ephemeral certificate; NOT an external-IdP deployment",
                "untrusted_TLS_certificate_rejected":untrusted_tls_rejected,
                "signed_candidate_created":True,"independent_reviewers":2,"offline_archive_verified":verified,
                "duplicate_retry_idempotent":True,"identity_spoof_blocked":spoof_blocked,
                "concurrent_requests":8,"concurrent_commits":races.count("committed"),"explicit_conflicts":races.count("conflict"),
                "revocation_blocks_live_gate":True,"reviewer_private_keys_received_by_API":False}
        finally:
            if previous_ca is None:os.environ.pop("SSL_CERT_FILE",None)
            else:os.environ["SSL_CERT_FILE"]=previous_ca
            server.terminate()
            try:server.wait(timeout=10)
            except subprocess.TimeoutExpired:server.kill();server.wait()


def main():
    p=argparse.ArgumentParser();p.add_argument("--output",type=Path,required=True);args=p.parse_args()
    with tempfile.TemporaryDirectory(prefix="opentapeout-team-") as temp:
        result=qualify(Path(temp))
    write_json(args.output,result)
    print(json.dumps(result,indent=2))


if __name__=="__main__":main()
