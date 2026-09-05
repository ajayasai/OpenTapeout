"""Allowlisted, recipient-bound delivery capsules; no private evidence export.

The recipient verifies transport integrity and sender authorization, NOT the
withheld signoff evidence. Keep the full evidence release under appropriate access
control. No network upload or foundry acceptance is implied by these functions.
"""
from __future__ import annotations

import os
import re
import tempfile
import zipfile
from pathlib import Path

from .bundle import METADATA, write_archive
from .engine import Engine, state_from
from .signing import Trust, sign
from .util import (HEX, MAX_JSON_BYTES, TapeoutError, digest, ensure, file_digest, hash_stream,
                   identifier, loads, now, safe_relative, timestamp)

DISCLOSURE = "opentapeout.disclosure/v1"
DELIVERY = "opentapeout.delivery/v1"
SIGNATURE = "opentapeout.delivery-signature/v1"
RECEIPT = "opentapeout.delivery-receipt/v1"
PUBLIC_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,120}\.(?:gds|gdsii|oas|oasis)\Z", re.IGNORECASE)


def validate_disclosure(policy: dict) -> dict:
    ensure(isinstance(policy, dict) and set(policy) == {"schema", "recipient", "files", "max_bytes"}
           and policy["schema"] == DISCLOSURE, "Invalid disclosure policy; unknown fields are forbidden")
    identifier(policy["recipient"])
    ensure(type(policy["max_bytes"]) is int and 0 < policy["max_bytes"] <= 1024**4,
           "Disclosure byte budget must be positive and at most 1 TiB")
    ensure(isinstance(policy["files"], list) and 0 < len(policy["files"]) <= 1000,
           "Explicit, nonempty disclosure file allowlist is required")
    names, sources = set(), set()
    for item in policy["files"]:
        ensure(isinstance(item, dict) and set(item) == {"delivery", "name", "sha256"}, "Invalid disclosure file")
        source = safe_relative(item["delivery"])
        name = item["name"]
        ensure(isinstance(name, str) and PUBLIC_NAME.fullmatch(name), "Delivery alias must be a portable GDS/OASIS filename")
        ensure(name.split('.')[0].upper() not in {"CON", "PRN", "AUX", "NUL", *[f"COM{i}" for i in range(10)],
                *[f"LPT{i}" for i in range(10)]}, "Reserved delivery filename")
        ensure(name.casefold() not in names and source not in sources, "Duplicate delivery name or source")
        ensure(isinstance(item["sha256"], str) and HEX.fullmatch(item["sha256"]), "Disclosure requires exact artifact SHA-256")
        names.add(name.casefold())
        sources.add(source)
    return policy


def disclosure_template(engine: Engine, name: str, recipient: str) -> dict:
    state = engine.state()
    ensure(name in state["candidates"], "Unknown candidate")
    entries = state["candidates"][name]["deliveries"]
    policy = {"schema": DISCLOSURE, "recipient": recipient,
              "max_bytes": sum(e["size"] for e in entries),
              "files": [{"delivery": e["name"], "name": Path(e["name"]).name, "sha256": e["sha256"]} for e in entries]}
    return validate_disclosure(policy)


def seal_delivery(engine: Engine, release_id: str, delivery_id: str, output: Path, disclosure: dict,
                  key, policy: dict, trust: Trust) -> dict:
    validate_disclosure(disclosure)
    identifier(delivery_id)
    output = output.resolve()
    ensure(not output.exists(), "Refusing to overwrite a delivery capsule")
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, temp_name = tempfile.mkstemp(prefix=".delivery-", suffix=".zip", dir=output.parent)
    os.close(fd)
    temporary, recorded = Path(temp_name), False
    try:
        with engine.store.transaction(write=True) as tx:
            state = state_from(tx.events)
            ensure(delivery_id not in state["deliveries"], "Delivery ID already used")
            release = state["releases"].get(release_id)
            ensure(release is not None, "Seal a full evidence release before creating a delivery capsule")
            gate = engine._gate(tx, release_id, policy, trust)
            ensure(gate["ready"], f"Delivery blocked: {gate['blockers']}")
            candidate = state["candidates"][release_id]
            declared = {e["name"]: e for e in candidate["deliveries"]}
            files, sources = {}, {}
            for item in disclosure["files"]:
                entry = declared.get(item["delivery"])
                ensure(entry is not None, "Disclosure may only select declared candidate deliveries, not raw evidence")
                source_format = "gds" if Path(entry["name"]).suffix.lower() in {".gds", ".gdsii"} else "oas"
                alias_format = "gds" if Path(item["name"]).suffix.lower() in {".gds", ".gdsii"} else "oas"
                ensure(source_format == alias_format, "Renaming cannot convert GDS to OASIS or vice versa")
                ensure(entry["sha256"] == item["sha256"], "Disclosure is pinned to different artifact bytes")
                member = "delivery/" + item["name"]
                files[member] = {"sha256": entry["sha256"], "size": entry["size"]}
                sources[member] = engine.store.verify_object(entry["sha256"])
            ensure(sum(f["size"] for f in files.values()) <= disclosure["max_bytes"], "Disclosure exceeds byte budget")
            manifest = {"schema": DELIVERY, "delivery_id": delivery_id, "project_id": candidate["project_id"],
                        "created_at": now(), "recipient": disclosure["recipient"],
                        "candidate_sha256": digest(candidate), "source_archive_sha256": release["archive_sha256"],
                        "source_manifest_sha256": release["manifest_sha256"],
                        "disclosure_sha256": digest(disclosure), "files": files}
            signature = sign({"type": SIGNATURE, "project_id": candidate["project_id"],
                              "created_at": manifest["created_at"], "manifest_sha256": digest(manifest)}, key)
            _, principal = trust.verify(signature, role="release", statement_type=SIGNATURE)
            write_archive(temporary, manifest, signature, sources)
            verify_delivery(temporary, disclosure, trust)
            ensure(engine._gate(tx, release_id, policy, trust)["ready"], "Release changed during delivery packaging")
            checksum, size = file_digest(temporary)
            record = {"id": delivery_id, "release_id": release_id, "project_id": candidate["project_id"],
                      "candidate_sha256": digest(candidate), "archive_sha256": checksum, "archive_size": size,
                      "manifest_sha256": digest(manifest), "recipient": disclosure["recipient"],
                      "disclosure_sha256": digest(disclosure), "sealed_at": manifest["created_at"],
                      "signature": signature}
            tx.append("delivery.sealed", record, principal)
        recorded = True
        try:
            os.link(temporary, output)
        except FileExistsError as exc:
            raise TapeoutError("Delivery recorded; output appeared concurrently. Recover the temporary file by ledger checksum") from exc
        return record
    finally:
        if temporary.exists() and (not recorded or output.exists()):
            temporary.unlink()


def verify_delivery(path: Path, disclosure: dict, trust: Trust) -> dict:
    validate_disclosure(disclosure)
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            ensure(2 < len(infos) <= 1002, "Invalid delivery archive member count")
            names = [i.filename for i in infos]
            ensure(len(names) == len(set(names)), "Duplicate ZIP members")
            expected = {"delivery/" + item["name"]: item["sha256"] for item in disclosure["files"]}
            ensure(set(names) == METADATA | set(expected), "Unexpected or missing members: disclosure is an exact allowlist")
            for info in infos:
                safe_relative(info.filename)
                ensure(not info.is_dir() and not (info.flag_bits & 1)
                       and (info.external_attr >> 16 & 0o170000) in (0, 0o100000)
                       and info.compress_type == zipfile.ZIP_STORED, "Unsafe delivery ZIP member")
                ensure(info.file_size <= (MAX_JSON_BYTES if info.filename in METADATA else disclosure["max_bytes"]),
                       "Delivery member exceeds size budget")
            ensure(sum(i.file_size for i in infos if i.filename not in METADATA) <= disclosure["max_bytes"],
                   "Delivery exceeds disclosure byte budget")
            manifest, signature = loads(archive.read("manifest.json")), loads(archive.read("signature.json"))
            ensure(isinstance(manifest, dict) and set(manifest) == {"schema", "delivery_id", "project_id", "created_at",
                   "recipient", "candidate_sha256", "source_archive_sha256", "source_manifest_sha256",
                   "disclosure_sha256", "files"} and manifest["schema"] == DELIVERY, "Invalid delivery manifest")
            statement, signer = trust.verify(signature, role="release", statement_type=SIGNATURE)
            ensure(set(statement) == {"type", "project_id", "created_at", "manifest_sha256"}, "Unexpected signature fields")
            ensure(statement["manifest_sha256"] == digest(manifest), "Delivery manifest signature mismatch")
            ensure(statement["project_id"] == manifest["project_id"] and statement["created_at"] == manifest["created_at"],
                   "Delivery signature scope mismatch")
            ensure(timestamp(manifest["created_at"]) <= timestamp(now()), "Future-dated delivery")
            identifier(manifest["delivery_id"])
            identifier(manifest["project_id"])
            for field in ("candidate_sha256", "source_archive_sha256", "source_manifest_sha256", "disclosure_sha256"):
                ensure(isinstance(manifest[field], str) and HEX.fullmatch(manifest[field]), "Invalid delivery digest")
            ensure(manifest["disclosure_sha256"] == digest(disclosure) and manifest["recipient"] == disclosure["recipient"],
                   "Delivery recipient or external disclosure policy mismatch")
            ensure(isinstance(manifest["files"], dict) and set(manifest["files"]) == set(expected), "Delivery file index mismatch")
            for name, checksum in expected.items():
                entry = manifest["files"][name]
                ensure(isinstance(entry, dict) and set(entry) == {"sha256", "size"}
                       and type(entry["size"]) is int and 0 <= entry["size"] <= disclosure["max_bytes"]
                       and entry["size"] == archive.getinfo(name).file_size and entry["sha256"] == checksum,
                       "Delivery file entry mismatch")
                with archive.open(name) as member:
                    observed, size = hash_stream(member, entry["size"])
                ensure(observed == checksum and size == entry["size"], "Delivery artifact digest mismatch")
            return {"verified": True, "scope": "sender-authorized delivery bytes only; not full signoff or foundry acceptance",
                    "signer": signer, "manifest_sha256": digest(manifest), "manifest": manifest}
    except (OSError, zipfile.BadZipFile, KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, TapeoutError):
            raise
        raise TapeoutError(f"Invalid delivery package: {exc}") from exc


def sign_receipt(archive: Path, disclosure: dict, trust: Trust, key, reference: str) -> dict:
    ensure(isinstance(reference, str) and 0 < len(reference.strip()) <= 512, "Recipient reference required (max 512 characters)")
    checksum, _ = file_digest(archive)
    verified = verify_delivery(archive, disclosure, trust)
    ensure(file_digest(archive)[0] == checksum, "Delivery archive changed during receipt verification")
    manifest = verified["manifest"]
    envelope = sign({"type": RECEIPT, "project_id": manifest["project_id"], "delivery_id": manifest["delivery_id"],
                     "archive_sha256": checksum, "manifest_sha256": verified["manifest_sha256"],
                     "recipient": manifest["recipient"], "reference": reference, "created_at": now()}, key)
    _, principal = trust.verify(envelope, role="delivery-receiver", statement_type=RECEIPT)
    ensure(principal == manifest["recipient"], "Receipt signer is not the designated recipient")
    return envelope


def record_receipt(engine: Engine, envelope: dict, trust: Trust) -> dict:
    body, principal = trust.verify(envelope, role="delivery-receiver", statement_type=RECEIPT)
    ensure(set(body) == {"type", "project_id", "delivery_id", "archive_sha256", "manifest_sha256", "recipient",
                         "reference", "created_at"}, "Invalid receipt fields")
    with engine.store.transaction(write=True) as tx:
        state = state_from(tx.events)
        delivery = state["deliveries"].get(body["delivery_id"])
        ensure(delivery is not None, "Unknown delivery")
        ensure(body["project_id"] == state["project"]["id"], "Receipt belongs to a different project")
        ensure(principal == body["recipient"] == delivery["recipient"], "Receipt recipient mismatch")
        for field in ("archive_sha256", "manifest_sha256"):
            ensure(body[field] == delivery[field], "Receipt does not match the exact sealed delivery")
        ensure(timestamp(delivery["sealed_at"]) <= timestamp(body["created_at"]) <= timestamp(now()), "Invalid receipt time")
        ensure(isinstance(body["reference"], str) and 0 < len(body["reference"].strip()) <= 512, "Invalid receipt reference")
        ensure(delivery["candidate_sha256"] not in state["withdrawals"], "Cannot accept receipt for a withdrawn release")
        if envelope not in state["delivery_receipts"]:
            tx.append("delivery.received", envelope, principal)
        return {"recorded": True, "receipt_sha256": digest(envelope), "recipient": principal,
                "scope": "designated recipient's signed acknowledgment; not an independent foundry API attestation"}
