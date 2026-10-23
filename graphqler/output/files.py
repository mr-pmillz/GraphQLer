"""Atomic private output files with no predictable temporary-file symlinks."""

from contextlib import contextmanager
import os
from pathlib import Path
import stat
import tempfile


def ensure_directory(path: Path, root: Path) -> Path:
    """Reject nested symlinks and paths outside the selected output root."""
    path, root = Path(os.path.abspath(path)), Path(os.path.abspath(root))
    relative = path.relative_to(root)
    current = root
    for part in relative.parts:
        current = current / part
        if current.is_symlink():
            raise ValueError(f"Output directory contains a symlink: {current}")
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    return path


@contextmanager
def atomic_writer(path: Path, root: Path):
    """Publish a UTF-8 file only after its writer succeeds; new files are private."""
    path = Path(os.path.abspath(path))
    ensure_directory(path.parent, root)
    descriptor, name = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    temporary = Path(name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            yield stream
            stream.flush()
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def prepare_database(path: Path) -> None:
    """Never follow a database symlink or open a device/FIFO as a catalog."""
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        metadata = path.lstat()
        if stat.S_ISLNK(metadata.st_mode):
            raise ValueError("Results database must not be a symlink")
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1:
            raise ValueError("Results database must be a regular file with a single link")
    else:
        os.close(descriptor)


def remove_output(path: Path, root: Path) -> None:
    """Remove an obsolete export without traversing a symlinked subdirectory."""
    path, root = Path(os.path.abspath(path)), Path(os.path.abspath(root))
    current = root
    for part in path.parent.relative_to(root).parts:
        current = current / part
        if current.is_symlink():
            return
    if path.is_file() or path.is_symlink():
        path.unlink()
