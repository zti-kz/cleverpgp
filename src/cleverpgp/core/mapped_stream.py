from __future__ import annotations

import mmap
from pathlib import Path


class MappedFileStream:
    """Seekable ciphertext stream backed by the operating-system page cache.

    WinSpd often forwards small sector writes. Mapping the already allocated
    container avoids a separate buffered file operation for every request while
    preserving explicit flush semantics. Only ciphertext is mapped; plaintext
    exists solely in the short-lived block buffers owned by the crypto layer.
    """

    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self._file = self.path.open("r+b", buffering=0)
        try:
            self._mapping = mmap.mmap(
                self._file.fileno(),
                length=0,
                access=mmap.ACCESS_WRITE,
            )
        except Exception:
            self._file.close()
            raise
        self._dirty_start: int | None = None
        self._dirty_end = 0
        self._closed = False

    def seek(self, offset: int, whence: int = 0) -> int:
        return self._mapping.seek(offset, whence)

    def tell(self) -> int:
        return self._mapping.tell()

    def read(self, size: int = -1) -> bytes:
        return self._mapping.read(size)

    def write(self, data: bytes | bytearray) -> int:
        start = self._mapping.tell()
        written = self._mapping.write(data)
        if written:
            end = start + written
            self._dirty_start = (
                start
                if self._dirty_start is None
                else min(self._dirty_start, start)
            )
            self._dirty_end = max(self._dirty_end, end)
        return written

    def flush(self) -> None:
        if self._closed:
            raise ValueError("Mapped ciphertext stream is closed.")
        if self._dirty_start is None:
            return
        granularity = mmap.ALLOCATIONGRANULARITY
        aligned_start = self._dirty_start - self._dirty_start % granularity
        self._mapping.flush(
            aligned_start,
            self._dirty_end - aligned_start,
        )
        self._dirty_start = None
        self._dirty_end = 0

    def fileno(self) -> int:
        return self._file.fileno()

    def close(self) -> None:
        if self._closed:
            return
        try:
            self.flush()
        finally:
            try:
                self._mapping.close()
            finally:
                self._file.close()
                self._closed = True


__all__ = ["MappedFileStream"]
