"""Transactional append-only event ledger and streaming content-addressed objects.

The SQL triggers prevent accidental mutation, not a hostile database administrator.
An externally retained signed checkpoint detects rewriting/truncation of its prefix.
"""
from __future__ import annotations

import hashlib
import os
import sqlite3
import stat
import tempfile
from contextlib import closing, contextmanager
from pathlib import Path
from typing import Iterator

from .util import CHUNK, HEX, TapeoutError, canonical, digest, ensure, file_digest, loads, now

ZERO = "0" * 64
DDL = """
CREATE TABLE IF NOT EXISTS events (
  seq INTEGER PRIMARY KEY, body TEXT NOT NULL, hash TEXT NOT NULL UNIQUE
);
CREATE TRIGGER IF NOT EXISTS events_no_update BEFORE UPDATE ON events
BEGIN SELECT RAISE(ABORT, 'append-only ledger'); END;
CREATE TRIGGER IF NOT EXISTS events_no_delete BEFORE DELETE ON events
BEGIN SELECT RAISE(ABORT, 'append-only ledger'); END;
"""


class Transaction:
    def __init__(self, connection: sqlite3.Connection, events: list[dict]):
        self.connection, self.events = connection, events

    def append(self, event_type: str, payload: dict, actor: str) -> dict:
        ensure(isinstance(actor, str) and 0 < len(actor.strip()) <= 128, "Actor is required")
        body = {"seq": len(self.events) + 1, "previous": self.events[-1]["hash"] if self.events else ZERO,
                "type": event_type, "actor": actor, "at": now(), "payload": payload}
        event = {**body, "hash": digest(body)}
        self.connection.execute("INSERT INTO events(seq,body,hash) VALUES(?,?,?)",
                                (body["seq"], canonical(body).decode(), event["hash"]))
        self.events.append(event)
        return event

    @property
    def checkpoint(self) -> dict:
        return {"seq": len(self.events), "hash": self.events[-1]["hash"] if self.events else ZERO}


class Store:
    def __init__(self, root: str | Path, *, create: bool = False):
        self.root = Path(root).resolve()
        self.directory = self.root / ".opentapeout"
        self.db_path = self.directory / "ledger.sqlite3"
        self.objects = self.directory / "objects" / "sha256"
        ensure(not self.directory.is_symlink(), "Ledger directory must not be a symlink")
        if create:
            self.objects.mkdir(parents=True, exist_ok=True, mode=0o700)
            with closing(self.connect()) as connection:
                connection.executescript(DDL)
                connection.execute("PRAGMA journal_mode=WAL")
        ensure(self.db_path.is_file(), "No OpenTapeout workspace. Run 'opentapeout init'.")

    def connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.db_path, timeout=30, isolation_level=None)
        connection.execute("PRAGMA busy_timeout=30000")
        connection.execute("PRAGMA synchronous=FULL")
        return connection

    @staticmethod
    def read_events(connection: sqlite3.Connection) -> list[dict]:
        events, previous = [], ZERO
        for index, (seq, data, recorded_hash) in enumerate(
                connection.execute("SELECT seq,body,hash FROM events ORDER BY seq"), 1):
            body = loads(data)
            ensure(isinstance(body, dict) and body.get("seq") == seq == index,
                   "Ledger sequence gap or invalid event")
            ensure(body.get("previous") == previous and digest(body) == recorded_hash,
                   f"Ledger integrity failure at event {index}")
            previous = recorded_hash
            events.append({**body, "hash": recorded_hash})
        return events

    @contextmanager
    def transaction(self, *, write: bool = False) -> Iterator[Transaction]:
        connection = self.connect()
        try:
            connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
            tx = Transaction(connection, self.read_events(connection))
            yield tx
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    def object_path(self, checksum: str) -> Path:
        ensure(isinstance(checksum, str) and HEX.fullmatch(checksum) is not None, "Invalid object digest")
        target = self.objects / checksum[:2] / checksum[2:]
        ensure(not self.objects.is_symlink() and not target.parent.is_symlink()
               and not target.is_symlink(), "Symlink in object store")
        return target

    def put_file(self, source: Path) -> tuple[str, int]:
        """Copy and hash one stable file in bounded memory; never trust existing CAS bytes."""
        self.objects.mkdir(parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(dir=self.objects, prefix=".incoming-")
        try:
            with os.fdopen(fd, "wb") as output:
                source_fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
                with os.fdopen(source_fd, "rb") as handle:
                    before = os.fstat(handle.fileno())
                    ensure(stat.S_ISREG(before.st_mode), "Only regular files can be stored")
                    h, size = hashlib.sha256(), 0
                    while chunk := handle.read(CHUNK):
                        h.update(chunk)
                        output.write(chunk)
                        size += len(chunk)
                    after = os.fstat(handle.fileno())
                    ensure((before.st_mtime_ns, before.st_size, before.st_ino) ==
                           (after.st_mtime_ns, after.st_size, after.st_ino), "File changed during ingest")
                    ensure(source.stat(follow_symlinks=False).st_ino == before.st_ino,
                           "File replaced during ingest")
                output.flush()
                os.fsync(output.fileno())
            checksum = h.hexdigest()
            target = self.object_path(checksum)
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.link(temporary, target)
                os.chmod(target, 0o400)
            except FileExistsError:
                self.verify_object(checksum)
            return checksum, size
        except OSError as exc:
            raise TapeoutError(f"Object storage error: {exc.strerror}") from exc
        finally:
            if os.path.exists(temporary):
                os.unlink(temporary)

    def put_bytes(self, data: bytes) -> tuple[str, int]:
        fd, temporary = tempfile.mkstemp(dir=self.directory)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(data)
            return self.put_file(Path(temporary))
        finally:
            os.unlink(temporary)

    def verify_object(self, checksum: str) -> Path:
        path = self.object_path(checksum)
        ensure(path.is_file(), f"Missing evidence object: {checksum}")
        actual, _ = file_digest(path)
        ensure(actual == checksum, f"Evidence object corrupted: {checksum}")
        return path

    def verify_checkpoint(self, expected: dict | None = None) -> dict:
        with self.transaction() as tx:
            if expected is not None:
                seq = expected.get("seq")
                ensure(type(seq) is int and seq >= 0, "Invalid checkpoint sequence")
                ensure(seq <= len(tx.events), "Ledger truncated below checkpoint")
                found = tx.events[seq - 1]["hash"] if seq else ZERO
                ensure(found == expected.get("hash"), "Ledger disagrees with external checkpoint")
            return tx.checkpoint
