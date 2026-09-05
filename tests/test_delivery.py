import copy
import warnings
import zipfile

import pytest

from opentapeout.bundle import _entry, seal
from opentapeout.delivery import (disclosure_template, record_receipt, seal_delivery, sign_receipt,
                                  validate_disclosure, verify_delivery)
from opentapeout.lifecycle import withdraw_release
from opentapeout.signing import sign
from opentapeout.util import TapeoutError, canonical, digest, loads


def package(ctx):
    for entry in ctx.trust.keys.values():
        if entry["principal"] in {"flexible", "bob"}:
            entry["roles"].append("delivery-receiver")
    ctx.run()
    ctx.candidate(notes="DO-NOT-DISCLOSE-INTERNAL-RELEASE-NOTES")
    ctx.approve()
    seal(ctx.engine, "RC1", ctx.root / "private.zip", ctx.keys["release"], ctx.policy, ctx.trust)
    policy = disclosure_template(ctx.engine, "RC1", "flexible")
    output = ctx.root / "recipient.zip"
    record = seal_delivery(ctx.engine, "RC1", "D001", output, policy, ctx.keys["release"], ctx.policy, ctx.trust)
    return output, policy, record


def test_minimal_delivery_excludes_private_evidence(ctx):
    output, policy, record = package(ctx)
    result = verify_delivery(output, policy, ctx.trust)
    assert result["verified"] and "not full signoff" in result["scope"]
    with zipfile.ZipFile(output) as z:
        assert set(z.namelist()) == {"manifest.json", "signature.json", "delivery/chip.gds"}
        content = b"".join(z.read(n) for n in z.namelist())
        for secret in (b"DO-NOT-DISCLOSE", b"rtl.v", b"netlist.v", b"pdk.lock", b"tool_spec", b"result/v1"):
            assert secret not in content
    assert record["manifest_sha256"] == result["manifest_sha256"]
    assert ctx.engine.state()["deliveries"]["D001"] == record


def test_designated_receiver_signs_exact_bytes_and_receipt_is_idempotent(ctx):
    output, policy, record = package(ctx)
    receipt = sign_receipt(output, policy, ctx.trust, ctx.keys["flexible"], "TEST-RECEIVER-001")
    assert receipt["payload"]["archive_sha256"] == record["archive_sha256"]
    assert record_receipt(ctx.engine, receipt, ctx.trust)["recorded"]
    checkpoint = ctx.engine.store.verify_checkpoint()
    record_receipt(ctx.engine, receipt, ctx.trust)
    assert ctx.engine.store.verify_checkpoint() == checkpoint
    assert len(ctx.engine.state()["delivery_receipts"]) == 1


@pytest.mark.parametrize("principal", ["bob", "alice", "release"])
def test_wrong_recipient_cannot_acknowledge(ctx, principal):
    output, policy, _ = package(ctx)
    with pytest.raises(TapeoutError):
        sign_receipt(output, policy, ctx.trust, ctx.keys[principal], "Wrong recipient")


@pytest.mark.parametrize("field,value", [("archive_sha256", "a"*64), ("manifest_sha256", "b"*64),
    ("project_id", "wrong-project"), ("recipient", "other"), ("delivery_id", "unknown"), ("reference", ""),
    ("created_at", "2099-01-01T00:00:00Z")])
def test_signed_receipt_scope_is_checked(ctx, field, value):
    output, policy, _ = package(ctx)
    body = sign_receipt(output, policy, ctx.trust, ctx.keys["flexible"], "RECEIVED")["payload"]
    body[field] = value
    with pytest.raises(TapeoutError):
        record_receipt(ctx.engine, sign(body, ctx.keys["flexible"]), ctx.trust)


def test_withdrawn_release_cannot_deliver_or_record_receipt(ctx):
    output, policy, _ = package(ctx)
    receipt = sign_receipt(output, policy, ctx.trust, ctx.keys["flexible"], "RECEIVED")
    withdraw_release(ctx.engine, "RC1", "A newly discovered design flaw", ctx.keys["release"], ctx.trust)
    with pytest.raises(TapeoutError, match="withdrawn"):
        record_receipt(ctx.engine, receipt, ctx.trust)
    with pytest.raises(TapeoutError, match="Delivery blocked"):
        seal_delivery(ctx.engine, "RC1", "D002", ctx.root/"next.zip", policy, ctx.keys["release"], ctx.policy, ctx.trust)


def test_disclosure_is_exact_not_extension_based(ctx):
    _, policy, _ = package(ctx)
    policy["files"][0]["delivery"] = "pdk.lock"
    with pytest.raises(TapeoutError, match="declared"):
        seal_delivery(ctx.engine, "RC1", "D002", ctx.root/"next.zip", policy, ctx.keys["release"], ctx.policy, ctx.trust)
    assert not (ctx.root/"next.zip").exists()
    assert "D002" not in ctx.engine.state()["deliveries"]


def test_relabeling_delivery_changes_only_the_allowlisted_name(ctx):
    _, policy, _ = package(ctx)
    policy["files"][0]["name"] = "anonymous-die.gdsii"
    output = ctx.root/"renamed.zip"
    seal_delivery(ctx.engine, "RC1", "D002", output, policy, ctx.keys["release"], ctx.policy, ctx.trust)
    assert verify_delivery(output, policy, ctx.trust)["verified"]
    with zipfile.ZipFile(output) as z:
        assert "delivery/anonymous-die.gdsii" in z.namelist()
    # The alias is not a format converter or geometry validator.


@pytest.mark.parametrize("name", ["../chip.gds", "/chip.gds", "x/chip.gds", "chip.gds/", "CON.gds", "x.txt", "x\\chip.gds", "x\x00.gds"])
def test_disclosure_rejects_unsafe_names(ctx, name):
    ctx.ready()
    policy = disclosure_template(ctx.engine, "RC1", "flexible")
    policy["files"][0]["name"] = name
    with pytest.raises(TapeoutError):
        validate_disclosure(policy)


@pytest.mark.parametrize("mutation", [{"files": []}, {"max_bytes": True}, {"max_bytes": 0},
                                      {"recipient": ""}, {"unexpected": True}])
def test_strict_disclosure_schema(ctx, mutation):
    ctx.ready()
    policy = {**disclosure_template(ctx.engine, "RC1", "flexible"), **mutation}
    with pytest.raises(TapeoutError):
        validate_disclosure(policy)


def test_wrong_hash_budget_duplicate_and_changed_policy(ctx):
    output, policy, _ = package(ctx)
    for change in ("hash", "budget", "duplicate", "recipient"):
        altered = copy.deepcopy(policy)
        if change == "hash": altered["files"][0]["sha256"] = "0"*64
        if change == "budget": altered["max_bytes"] = 1
        if change == "duplicate": altered["files"].append(copy.deepcopy(altered["files"][0]))
        if change == "recipient": altered["recipient"] = "bob"
        with pytest.raises(TapeoutError):
            verify_delivery(output, altered, ctx.trust)


def rewrite(src, output, change):
    with zipfile.ZipFile(src) as z:
        entries = [(i.filename, z.read(i.filename)) for i in z.infolist()]
    entries = change(entries)
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", UserWarning)
        with zipfile.ZipFile(output, "w") as z:
            for name, data in entries:
                z.writestr(_entry(name), data)


@pytest.mark.parametrize("attack", ["extra", "missing", "duplicate", "bytes", "manifest", "signature", "private-field"])
def test_adversarial_capsules(ctx, attack):
    output, policy, _ = package(ctx)
    def change(entries):
        if attack == "extra": return entries + [("objects/private", b"confidential")]
        if attack == "missing": return entries[:-1]
        if attack == "duplicate": return entries + [entries[-1]]
        updated = []
        for name, data in entries:
            if attack == "bytes" and name.startswith("delivery/"): data = b"corrupt"
            if name == "manifest.json" and attack in {"manifest", "private-field"}:
                m = loads(data)
                if attack == "manifest": m["recipient"] = "other"
                else: m["private_notes"] = "should never disclose"
                data = canonical(m)
            if name == "signature.json" and attack == "signature": data = b"{}"
            updated.append((name, data))
        return updated
    bad = ctx.root/"bad.zip"
    rewrite(output, bad, change)
    with pytest.raises(TapeoutError):
        verify_delivery(bad, policy, ctx.trust)


def test_sealed_only_and_no_overwrite(ctx):
    ctx.ready()
    policy = disclosure_template(ctx.engine, "RC1", "flexible")
    output = ctx.root/"out.zip"
    with pytest.raises(TapeoutError, match="full evidence"):
        seal_delivery(ctx.engine, "RC1", "D1", output, policy, ctx.keys["release"], ctx.policy, ctx.trust)
    output.write_bytes(b"existing")
    with pytest.raises(TapeoutError, match="overwrite"):
        seal_delivery(ctx.engine, "RC1", "D1", output, policy, ctx.keys["release"], ctx.policy, ctx.trust)
    assert output.read_bytes() == b"existing"


def test_format_conversion_by_renaming_is_rejected(ctx):
    _, policy, _ = package(ctx)
    policy["files"][0]["name"] = "chip.oas"
    with pytest.raises(TapeoutError, match="cannot convert"):
        seal_delivery(ctx.engine, "RC1", "D2", ctx.root/"wrong-format.zip", policy, ctx.keys["release"], ctx.policy, ctx.trust)
