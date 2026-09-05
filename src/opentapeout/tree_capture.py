"""Byte-level directory snapshots for PDKs and unpacked IP; no timestamp shortcuts."""
from pathlib import Path

from .util import ensure, file_digest, safe_relative, workspace_file


def capture_tree(root: Path, relative: str, store=None) -> list[dict]:
    safe_relative(relative)
    ensure(not relative.startswith('.opentapeout'), 'Cannot snapshot the ledger into itself')
    directory = root / relative
    ensure(directory.is_dir() and not directory.is_symlink(), 'Tree must be a nonsymlink directory')
    ensure(directory.resolve().is_relative_to(root.resolve()), 'Tree escapes workspace')
    manifest = []
    for path in sorted(directory.rglob('*')):
        ensure(not path.is_symlink(), 'Symlinks are not allowed in directory snapshots')
        if path.is_dir():
            continue
        ensure(path.is_file(), 'Only regular files are allowed in directory snapshots')
        relative_file = path.relative_to(root).as_posix()
        verified = workspace_file(root, relative_file)
        checksum, size = store.put_file(verified) if store else file_digest(verified)
        manifest.append({'path': path.relative_to(directory).as_posix(), 'sha256': checksum, 'size': size})
        ensure(len(manifest) <= 100_000, 'Directory snapshot exceeds 100,000 files; partition the PDK/IP tree')
    ensure(bool(manifest), 'Empty directory snapshots are not accepted as evidence')
    return manifest
