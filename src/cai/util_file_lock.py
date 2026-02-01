"""Cross-platform file locking utilities."""

from __future__ import annotations

from contextlib import contextmanager
import os
import time
from typing import IO, Iterator


LOCK_RETRY_INTERVAL = 0.1


def _lock_file(handle: IO[str]) -> None:
    """Acquire an exclusive lock on the file handle."""
    if os.name == "nt":
        import msvcrt  # pylint: disable=import-outside-toplevel

        msvcrt.locking(handle.fileno(), msvcrt.LK_LOCK, 1)
    else:
        import fcntl  # pylint: disable=import-outside-toplevel

        fcntl.flock(handle.fileno(), fcntl.LOCK_EX)


def _unlock_file(handle: IO[str]) -> None:
    """Release the exclusive lock on the file handle."""
    if os.name == "nt":
        import msvcrt  # pylint: disable=import-outside-toplevel

        msvcrt.locking(handle.fileno(), msvcrt.LK_UNLCK, 1)
    else:
        import fcntl  # pylint: disable=import-outside-toplevel

        fcntl.flock(handle.fileno(), fcntl.LOCK_UN)


@contextmanager
def locked_open(
    path: str,
    mode: str = "a",
    *,
    timeout_sec: float = 5.0,
    **open_kwargs,
) -> Iterator[IO[str]]:
    """Open a file and hold an exclusive lock for the duration."""
    start = time.time()
    handle = open(path, mode, **open_kwargs)  # noqa: PTH123
    try:
        while True:
            try:
                _lock_file(handle)
                break
            except OSError:
                if time.time() - start >= timeout_sec:
                    raise TimeoutError(f"Timed out waiting for file lock: {path}") from None
                time.sleep(LOCK_RETRY_INTERVAL)

        yield handle
    finally:
        try:
            _unlock_file(handle)
        finally:
            handle.close()
