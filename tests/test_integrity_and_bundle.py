import copy
import json
import sqlite3
from contextlib import closing
import warnings
import zipfile

import pytest

from opentapeout.bundle import _entry, seal, verify_bundle, write_archive
from opentapeout.signing import Trust
from opentapeout.util import TapeoutError, canonical, digest


def test_append_only_sql_triggers(ctx):
    with closing(sqlite3.connect(ctx.engine.store.db_path)) as db, db:
        with pytest.raises(sqlite3.IntegrityError,match="append-only"):
            db.execute("UPDATE events SET hash='changed' WHERE seq=1")
        with pytest.raises(sqlite3.IntegrityError,match="append-only"):
            db.execute("DELETE FROM events WHERE seq=1")


def test_chain_detects_admin_edit_without_rehash(ctx):
    with closing(sqlite3.connect(ctx.engine.store.db_path)) as db, db:
        db.execute("DROP TRIGGER events_no_update")
        body=json.loads(db.execute("SELECT body FROM events WHERE seq=1").fetchone()[0])
        body["actor"]="tampered"
        db.execute("UPDATE events SET body=? WHERE seq=1",(json.dumps(body),))
    with pytest.raises(TapeoutError,match="integrity"):
        ctx.engine.store.verify_checkpoint()


def test_external_checkpoint_detects_suffix_truncation(ctx):
    expected=ctx.engine.store.verify_checkpoint()
    with closing(sqlite3.connect(ctx.engine.store.db_path)) as db, db:
        db.execute("DROP TRIGGER events_no_delete")
        db.execute("DELETE FROM events WHERE seq=?",(expected["seq"],))
    # An unanchored valid prefix is indistinguishable from an older ledger.
    assert ctx.engine.store.verify_checkpoint()["seq"]==expected["seq"]-1
    with pytest.raises(TapeoutError,match="truncated"):
        ctx.engine.store.verify_checkpoint(expected)


def test_external_checkpoint_allows_valid_append(ctx):
    expected=ctx.engine.store.verify_checkpoint()
    ctx.engine.register("note","config",metadata={"note":"after checkpoint"})
    assert ctx.engine.store.verify_checkpoint(expected)["seq"]==expected["seq"]+1


def test_cas_corruption_blocks_gate_and_reingest(ctx):
    ctx.ready()
    checksum=ctx.engine.state()["resources"]["rtl"]["sha256"]
    obj=ctx.engine.store.object_path(checksum)
    obj.chmod(0o600);obj.write_bytes(b"corrupt")
    assert any(b["code"]=="OBJECT_INTEGRITY" for b in ctx.gate()["blockers"])
    with pytest.raises(TapeoutError,match="corrupted"):
        ctx.engine.register("rtl","rtl",path="rtl.v")


def test_missing_report_object_blocks_gate(ctx):
    ctx.ready()
    run=next(iter(ctx.engine.state()["runs"].values()))
    ctx.engine.store.object_path(run["report_sha256"]).unlink()
    assert any(b["code"]=="OBJECT_INTEGRITY" for b in ctx.gate()["blockers"])


def package(ctx):
    ctx.ready()
    archive=ctx.root/"release.zip"
    record=seal(ctx.engine,"RC1",archive,ctx.keys["release"],ctx.policy,ctx.trust)
    return archive,record


def test_full_archive_offline_verified_and_receipt_checked(ctx):
    archive,record=package(ctx)
    verified=verify_bundle(archive,ctx.policy,ctx.trust)
    assert verified["verified"] and verified["signer"]=="release"
    assert verified["candidate_sha256"]==record["candidate_sha256"]
    receipt=ctx.engine.receipt("RC1",record["archive_sha256"],"SYNTHETIC receipt-1")
    assert receipt["archive_sha256"]==record["archive_sha256"]
    with pytest.raises(TapeoutError,match="does not match"):
        ctx.engine.receipt("RC1","0"*64,"wrong upload")


def test_release_requires_all_gates(ctx):
    ctx.run();ctx.candidate()
    with pytest.raises(TapeoutError,match="Release blocked"):
        seal(ctx.engine,"RC1",ctx.root/"blocked.zip",ctx.keys["release"],ctx.policy,ctx.trust)
    assert not ctx.engine.state()["releases"] and not (ctx.root/"blocked.zip").exists()


def test_release_signing_role_enforced(ctx):
    ctx.ready()
    with pytest.raises(TapeoutError,match="not authorized"):
        seal(ctx.engine,"RC1",ctx.root/"bad.zip",ctx.keys["alice"],ctx.policy,ctx.trust)


def test_sealed_release_cannot_be_overwritten(ctx):
    archive,_=package(ctx)
    with pytest.raises(TapeoutError,match="overwrite"):
        seal(ctx.engine,"RC1",archive,ctx.keys["release"],ctx.policy,ctx.trust)
    with pytest.raises(TapeoutError,match="already sealed"):
        seal(ctx.engine,"RC1",ctx.root/"second.zip",ctx.keys["release"],ctx.policy,ctx.trust)


def rewrite(archive,target,change):
    with zipfile.ZipFile(archive) as reader:
        entries=[(item,reader.read(item.filename)) for item in reader.infolist()]
    with zipfile.ZipFile(target,"w") as writer:
        change(writer,entries)


@pytest.mark.parametrize("attack",["manifest","signature","object","missing","unexpected","duplicate","traversal","symlink","compressed"])
def test_archive_tampering_and_unsafe_members_rejected(ctx,attack):
    archive,_=package(ctx)
    target=ctx.root/(attack+".zip")
    def change(writer,entries):
        mutated=False
        for info,data in entries:
            if attack=="manifest" and info.filename=="manifest.json":
                value=json.loads(data);value["candidate"]["notes"]="altered";data=canonical(value)
            if attack=="signature" and info.filename=="signature.json":
                value=json.loads(data);value["signature"]="A"*88;data=canonical(value)
            if attack in {"object","missing"} and info.filename.startswith("objects/") and not mutated:
                mutated=True
                if attack=="missing":continue
                data=b"tampered"
            if attack=="compressed":info.compress_type=zipfile.ZIP_DEFLATED
            writer.writestr(info,data)
        if attack=="unexpected":writer.writestr(_entry("unexpected.txt"),b"x")
        if attack=="duplicate":
            with warnings.catch_warnings():
                warnings.simplefilter("ignore")
                writer.writestr(_entry("manifest.json"),entries[0][1])
        if attack=="traversal":writer.writestr(_entry("../outside.txt"),b"x")
        if attack=="symlink":
            info=_entry("symlink");info.external_attr=0o120777<<16;writer.writestr(info,b"/etc/passwd")
    rewrite(archive,target,change)
    with pytest.raises(TapeoutError):verify_bundle(target,ctx.policy,ctx.trust)


def test_bundle_requires_external_matching_policy(ctx):
    archive,_=package(ctx)
    policy=copy.deepcopy(ctx.policy);policy["required_checks"][0]["max_age_hours"]=10
    with pytest.raises(TapeoutError,match="External policy"):
        verify_bundle(archive,policy,ctx.trust)


def test_bundle_current_key_revocation_rejects_historical_signature(ctx):
    archive,_=package(ctx)
    data=copy.deepcopy(ctx.trust.data)
    for entry in data["keys"].values():
        if entry["principal"]=="release":entry["revoked"]=True
    with pytest.raises(TapeoutError,match="revoked"):
        verify_bundle(archive,ctx.policy,Trust(data))


def test_bundle_resource_budget(ctx):
    archive,_=package(ctx)
    with pytest.raises(TapeoutError,match="budget"):
        verify_bundle(archive,ctx.policy,ctx.trust,max_total=1)


def test_package_member_metadata_is_reproducible(ctx):
    archive,_=package(ctx)
    with zipfile.ZipFile(archive) as reader:
        manifest=json.loads(reader.read("manifest.json"));signature=json.loads(reader.read("signature.json"))
    sources={name:ctx.engine.store.verify_object(entry["sha256"]) for name,entry in manifest["files"].items()}
    rebuilt=ctx.root/"rebuilt.zip"
    write_archive(rebuilt,manifest,signature,sources)
    assert archive.read_bytes()==rebuilt.read_bytes()


def test_initialization_explicitly_closes_sqlite_connection(tmp_path, monkeypatch):
    """SQLite's connection context only commits; it does not close the connection."""
    from opentapeout.store import Store
    from unittest.mock import MagicMock
    real_connect = Store.connect
    connections = []

    def tracked_connect(store):
        actual = real_connect(store)
        wrapper = MagicMock(wraps=actual)
        connections.append(wrapper)
        return wrapper

    monkeypatch.setattr(Store, "connect", tracked_connect)
    Store(tmp_path, create=True)
    assert len(connections) == 1
    connections[0].close.assert_called_once_with()
