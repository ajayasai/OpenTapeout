"""Strict encoding, hashing, time and filesystem primitives."""
from __future__ import annotations

import hashlib
import json
import math
import os
import re
import stat
import tempfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, BinaryIO

CHUNK = 1024 * 1024
MAX_JSON_BYTES = 16 * 1024 * 1024
HEX = re.compile(r"^[a-f0-9]{64}$")
IDENTIFIER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")


class TapeoutError(ValueError):
    """An expected validation, integrity or policy error."""


def ensure(condition: bool, message: str) -> None:
    if not condition:
        raise TapeoutError(message)


def identifier(value: str) -> str:
    ensure(isinstance(value, str) and IDENTIFIER.fullmatch(value) is not None, "Invalid identifier")
    return value


def sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def canonical(value: Any) -> bytes:
    """Project canonical JSON v1, NOT RFC 8785. See docs/SECURITY.md."""
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                          allow_nan=False).encode("ascii")
    except (ValueError, TypeError, RecursionError) as exc:
        raise TapeoutError(f"Not canonical JSON: {exc}") from exc


def digest(value: Any) -> str:
    return sha256(canonical(value))


def _unique_pairs(pairs: list[tuple[str, Any]]) -> dict:
    result = {}
    for key, value in pairs:
        ensure(key not in result, f"Duplicate JSON key: {key}")
        result[key] = value
    return result


def loads(data: bytes | str, limit: int = MAX_JSON_BYTES) -> Any:
    ensure(len(data) <= limit, "JSON exceeds size limit")
    def reject_constant(value: str) -> None:
        raise TapeoutError(f"Nonfinite JSON number: {value}")
    def strict_float(value: str) -> float:
        number = float(value)
        ensure(math.isfinite(number), "Nonfinite JSON number")
        return number
    try:
        return json.loads(data, object_pairs_hook=_unique_pairs, parse_constant=reject_constant, parse_float=strict_float)
    except (ValueError, UnicodeDecodeError, RecursionError) as exc:
        raise TapeoutError(f"Invalid JSON: {exc}") from exc


def read_json(path: str | Path) -> Any:
    with Path(path).open("rb") as handle:
        return loads(handle.read(MAX_JSON_BYTES + 1))


def write_json(path: str | Path, value: Any, *, overwrite: bool = False) -> None:
    atomic_write(Path(path), json.dumps(value, indent=2, sort_keys=True, allow_nan=False).encode() + b"\n",
                 overwrite=overwrite)


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def timestamp(value: str) -> datetime:
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, AttributeError, TypeError) as exc:
        raise TapeoutError("Timestamp must be ISO 8601 with a timezone") from exc
    ensure(result.tzinfo is not None, "Timestamp must include a timezone")
    return result.astimezone(timezone.utc)


def finite_number(value: Any) -> bool:
    return type(value) in (int, float) and math.isfinite(value)


def safe_relative(value: str) -> str:
    ensure(isinstance(value, str) and bool(value) and "\\" not in value and "\x00" not in value,
           "Unsafe relative path")
    p = PurePosixPath(value)
    ensure(not p.is_absolute() and all(x not in ("", ".", "..") for x in value.split("/"))
           and ":" not in value, "Unsafe relative path")
    return p.as_posix()


def workspace_file(root: Path, relative: str) -> Path:
    safe_relative(relative)
    root = root.resolve()
    target = root / relative
    current = root
    for part in PurePosixPath(relative).parts:
        current = current / part
        ensure(not current.is_symlink(), "Symlinked workspace paths are rejected")
    ensure(target.resolve().is_relative_to(root), "Path escapes workspace")
    ensure(target.is_file(), f"Missing workspace file: {relative}")
    return target


def file_digest(path: Path) -> tuple[str, int]:
    """Stream regular files; reject observable changes during hashing."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
        with os.fdopen(fd, "rb") as handle:
            before = os.fstat(handle.fileno())
            ensure(stat.S_ISREG(before.st_mode), "Only regular files can be hashed")
            h, size = hashlib.sha256(), 0
            while chunk := handle.read(CHUNK):
                h.update(chunk)
                size += len(chunk)
            after = os.fstat(handle.fileno())
            current = path.stat(follow_symlinks=False)
            ensure((before.st_size, before.st_mtime_ns, before.st_ino, before.st_dev) ==
                   (after.st_size, after.st_mtime_ns, after.st_ino, after.st_dev),
                   "File changed while hashing")
            ensure((current.st_ino, current.st_dev, current.st_mtime_ns, current.st_size) ==
                   (after.st_ino, after.st_dev, after.st_mtime_ns, after.st_size),
                   "File replaced while hashing")
            return h.hexdigest(), size
    except OSError as exc:
        raise TapeoutError(f"Cannot hash {path.name}: {exc.strerror}") from exc


def hash_stream(handle: BinaryIO, limit: int | None = None) -> tuple[str, int]:
    h, size = hashlib.sha256(), 0
    while chunk := handle.read(CHUNK):
        size += len(chunk)
        ensure(limit is None or size <= limit, "Stream exceeds size limit")
        h.update(chunk)
    return h.hexdigest(), size


def atomic_write(path: Path, content: bytes, *, overwrite: bool = False, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".ot-", dir=path.parent)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if overwrite:
            ensure(not path.is_symlink(), "Refusing to overwrite a symlink")
            os.replace(temporary, path)
        else:
            try:
                os.link(temporary, path)
            except FileExistsError as exc:
                raise TapeoutError(f"Refusing to overwrite: {path}") from exc
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
