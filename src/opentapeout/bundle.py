"""Signed, deterministic-member ZIP64 evidence packages and strict offline verification."""
from __future__ import annotations

import os
import shutil
import tempfile
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .engine import Engine, object_refs, state_from
from .policy import evaluate, validate_policy
from .lifecycle import active_approvals, check_candidate_status
from .signing import Trust, sign
from .util import (CHUNK, MAX_JSON_BYTES, TapeoutError, canonical, digest, ensure, file_digest,
                   hash_stream, identifier, loads, now, safe_relative, timestamp)

METADATA = {"manifest.json", "signature.json"}
MAX_MEMBERS = 100_000
MAX_TOTAL = 1024 ** 4  # explicit 1 TiB verification cap; configurable by the Python API


def _entry(name: str) -> zipfile.ZipInfo:
    entry = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
    entry.compress_type = zipfile.ZIP_STORED
    entry.create_system = 3
    entry.external_attr = 0o100444 << 16
    return entry


def write_archive(path: Path, manifest: dict, signature: dict, sources: dict[str, Path]) -> None:
    """Identical manifests, signatures and bytes produce identical archive bytes."""
    with zipfile.ZipFile(path, "w", allowZip64=True) as archive:
        archive.writestr(_entry("manifest.json"), canonical(manifest))
        archive.writestr(_entry("signature.json"), canonical(signature))
        for name, source in sorted(sources.items()):
            with source.open("rb") as input_file, archive.open(_entry(name), "w", force_zip64=True) as output:
                shutil.copyfileobj(input_file, output, CHUNK)


def seal(engine: Engine, name: str, output: Path, key: Ed25519PrivateKey, policy: dict, trust: Trust) -> dict:
    identifier(name)
    output = output.resolve()
    ensure(not output.exists(), "Refusing to overwrite an existing release archive")
    output.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".release-", suffix=".zip", dir=output.parent)
    os.close(fd)
    recorded = False
    try:
        with engine.store.transaction(write=True) as tx:
            state = state_from(tx.events)
            ensure(name not in state["releases"], "Release already sealed; use a new candidate name")
            gate = engine._gate(tx, name, policy, trust)
            ensure(gate["ready"], f"Release blocked: {gate['blockers']}")
            candidate = state["candidates"][name]
            approvals = [a for a in active_approvals(state) if a["payload"]["candidate_sha256"] == digest(candidate)]
            sources, files, object_index = {}, {}, {}
            for checksum in sorted(object_refs(candidate)):
                source = engine.store.verify_object(checksum)
                member = "objects/sha256/" + checksum
                sources[member] = source
                files[member] = {"sha256": checksum, "size": source.stat().st_size}
                object_index[checksum] = member
            # Delivery aliases intentionally duplicate bytes for direct foundry handoff; see docs.
            for delivery in candidate["deliveries"]:
                member = "delivery/" + delivery["name"]
                sources[member] = engine.store.verify_object(delivery["sha256"])
                files[member] = {"sha256": delivery["sha256"], "size": delivery["size"]}
            manifest = {"schema": "opentapeout.release/v1", "created_at": now(), "candidate": candidate,
                "candidate_sha256": digest(candidate), "approvals": sorted(approvals, key=digest),
                "checkpoint": tx.checkpoint, "files": files, "object_index": object_index,
                "policy": policy, "disclosure": "full evidence: may include confidential design/PDK material"}
            envelope = sign({"type": "opentapeout.release-signature/v1", "manifest_sha256": digest(manifest),
                "project_id": candidate["project_id"], "created_at": manifest["created_at"]}, key)
            _, principal = trust.verify(envelope, role="release", statement_type="opentapeout.release-signature/v1")
            write_archive(Path(temporary), manifest, envelope, sources)
            verify_bundle(Path(temporary), policy, trust)
            # Detect observable input changes while the archive was being assembled.
            final_gate = engine._gate(tx, name, policy, trust)
            ensure(final_gate["ready"], "Workspace/evidence changed while sealing the archive")
            checksum, size = file_digest(Path(temporary))
            record = {"id": name, "archive_sha256": checksum, "archive_size": size,
                      "manifest_sha256": digest(manifest), "candidate_sha256": digest(candidate),
                      "sealed_at": manifest["created_at"], "signature": envelope}
            # Durable release event is the authority. A crash after commit but before publication
            # may leave a .release- file; checksum permits safe recovery, never an unsafe release.
            tx.append("release.sealed", record, principal)
        recorded = True
        try:
            os.link(temporary, output)
        except FileExistsError as exc:
            raise TapeoutError("Release recorded but output appeared concurrently; recover using archive checksum") from exc
        return record
    finally:
        # Preserve a completed temporary archive only if the release was committed but its
        # output could not be published. Its ledger checksum permits a controlled recovery.
        if os.path.exists(temporary) and (not recorded or output.exists()):
            os.unlink(temporary)


def verify_bundle(path: Path, policy: dict, trust: Trust, *, max_total: int = MAX_TOTAL,
                  status: dict | None = None, minimum_status_sequence: int = 0) -> dict:
    """Never extracts files. Trust/policy come from the caller, not the archive."""
    validate_policy(policy)
    ensure(status is not None or minimum_status_sequence == 0, "A status statement is required for anti-replay verification")
    try:
        with zipfile.ZipFile(path) as archive:
            infos = archive.infolist()
            ensure(2 <= len(infos) <= MAX_MEMBERS, "Invalid archive member count")
            names = [item.filename for item in infos]
            ensure(len(names) == len(set(names)), "Duplicate ZIP members")
            ensure(sum(item.file_size for item in infos) <= max_total, "Archive exceeds uncompressed-size budget")
            for item in infos:
                safe_relative(item.filename)
                ensure(not item.is_dir() and not (item.flag_bits & 1), "Directories/encrypted members are forbidden")
                mode = item.external_attr >> 16
                ensure((mode & 0o170000) in (0, 0o100000), "ZIP symlinks/special files are forbidden")
                ensure(item.compress_type == zipfile.ZIP_STORED, "Only uncompressed release archives are supported")
            ensure(METADATA <= set(names), "Release metadata is missing")
            for name in METADATA:
                ensure(archive.getinfo(name).file_size <= MAX_JSON_BYTES, "Oversized release metadata")
            manifest = loads(archive.read("manifest.json"))
            envelope = loads(archive.read("signature.json"))
            ensure(manifest.get("schema") == "opentapeout.release/v1", "Unsupported release schema")
            statement, signer = trust.verify(envelope, role="release", statement_type="opentapeout.release-signature/v1")
            ensure(statement["manifest_sha256"] == digest(manifest), "Manifest signature digest mismatch")
            candidate = manifest["candidate"]
            ensure(statement["project_id"] == candidate["project_id"], "Release signature project mismatch")
            ensure(statement["created_at"] == manifest["created_at"], "Release timestamp mismatch")
            ensure(timestamp(manifest["created_at"]) <= timestamp(now()), "Release is future-dated")
            ensure(digest(candidate) == manifest["candidate_sha256"], "Candidate digest mismatch")
            ensure(digest(manifest["policy"]) == digest(policy) == candidate["policy_sha256"],
                   "External policy does not match signed candidate")
            approvals, status_result = manifest["approvals"], None
            if status is not None:
                approvals, status_result = check_candidate_status(candidate, approvals, status, trust,
                    minimum_sequence=minimum_status_sequence)
            gate = evaluate(candidate, policy, trust, approvals, at=manifest["created_at"])
            ensure(gate["ready"], f"Signed release fails historical gate: {gate['blockers']}")
            files = manifest["files"]
            ensure(set(names) == set(files) | METADATA, "Missing or unexpected archive members")
            for name, entry in files.items():
                safe_relative(name)
                ensure(archive.getinfo(name).file_size == entry["size"], f"Size mismatch: {name}")
                with archive.open(name) as member:
                    checksum, size = hash_stream(member, entry["size"])
                ensure(checksum == entry["sha256"] and size == entry["size"], f"Artifact digest mismatch: {name}")
            ensure(set(manifest["object_index"]) == object_refs(candidate), "Evidence object set mismatch")
            for checksum, member in manifest["object_index"].items():
                ensure(member in files and files[member]["sha256"] == checksum, "Evidence object index mismatch")
            for delivery in candidate["deliveries"]:
                info = files.get("delivery/" + safe_relative(delivery["name"]))
                ensure(info == {"sha256": delivery["sha256"], "size": delivery["size"]}, "Delivery manifest mismatch")
            return {"verified": True, "verification_scope": "historical signed evidence, not current design or foundry acceptance",
                    "candidate_sha256": digest(candidate), "manifest_sha256": digest(manifest),
                    "signer": signer, "objects": len(manifest["object_index"]),
                    "files": len(files), "gate": gate, "release_status": status_result}
    except (OSError, zipfile.BadZipFile, KeyError, TypeError, ValueError) as exc:
        if isinstance(exc, TapeoutError):
            raise
        raise TapeoutError(f"Invalid release package: {exc}") from exc
