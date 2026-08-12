"""Safely extract a small, password-protected benchmark ZIP into a fresh directory."""

from __future__ import annotations

import stat
import sys
from pathlib import Path, PurePosixPath
from zipfile import ZipFile

MAX_ENTRIES = 1_000
MAX_FILE_BYTES = 32 * 1024 * 1024
MAX_TOTAL_BYTES = 64 * 1024 * 1024
PASSWORD = b"infected"


def main() -> None:
    if len(sys.argv) != 3:
        raise SystemExit("usage: extract-dataset-zip.py ARCHIVE DESTINATION")
    archive = Path(sys.argv[1]).resolve(strict=True)
    destination = Path(sys.argv[2]).resolve(strict=True)
    total = 0
    with ZipFile(archive) as bundle:
        entries = bundle.infolist()
        if len(entries) > MAX_ENTRIES:
            raise ValueError(f"dataset ZIP contains more than {MAX_ENTRIES} entries")
        for entry in entries:
            relative = safe_path(entry.filename)
            mode = entry.external_attr >> 16
            if stat.S_ISLNK(mode) or (mode and not (stat.S_ISREG(mode) or stat.S_ISDIR(mode))):
                raise ValueError(f"dataset ZIP contains unsupported entry type: {entry.filename}")
            if entry.file_size > MAX_FILE_BYTES:
                raise ValueError(f"dataset ZIP entry exceeds {MAX_FILE_BYTES} bytes: {entry.filename}")
            total += entry.file_size
            if total > MAX_TOTAL_BYTES:
                raise ValueError(f"dataset ZIP exceeds {MAX_TOTAL_BYTES} unpacked bytes")
            target = destination.joinpath(*relative.parts)
            if entry.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(entry, pwd=PASSWORD) as source, target.open("xb") as output:
                written = 0
                while chunk := source.read(64 * 1024):
                    written += len(chunk)
                    if written > entry.file_size or written > MAX_FILE_BYTES:
                        raise ValueError(f"dataset ZIP entry exceeded its declared size: {entry.filename}")
                    output.write(chunk)
            if written != entry.file_size or target.stat().st_size != entry.file_size:
                raise ValueError(f"dataset ZIP entry changed size while extracting: {entry.filename}")


def safe_path(name: str) -> PurePosixPath:
    if "\\" in name or "\0" in name:
        raise ValueError(f"dataset ZIP contains an unsafe path: {name!r}")
    relative = PurePosixPath(name)
    if relative.is_absolute() or ".." in relative.parts or not relative.parts:
        raise ValueError(f"dataset ZIP contains an unsafe path: {name!r}")
    if relative.parts[0].endswith(":"):
        raise ValueError(f"dataset ZIP contains a drive path: {name!r}")
    return relative


if __name__ == "__main__":
    main()
