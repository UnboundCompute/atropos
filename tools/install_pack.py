#!/usr/bin/env python3
"""Install and validate an Atropos model-pack archive for local consumers."""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
import tempfile
import zipfile
from pathlib import Path, PurePosixPath

import validate_pack


def _digest(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _safe_member(name: str) -> PurePosixPath:
    path = PurePosixPath(name)
    if path.is_absolute() or ".." in path.parts or not path.parts:
        raise ValueError(f"unsafe archive member: {name!r}")
    return path


def _extract(archive: Path, staging: Path) -> None:
    with zipfile.ZipFile(archive) as bundle:
        for member in bundle.infolist():
            relative = _safe_member(member.filename)
            # Refuse symlinks and other special files; model packs are data only.
            mode = (member.external_attr >> 16) & 0o170000
            if mode and mode != 0o100000:
                raise ValueError(f"archive member is not a regular file: {member.filename!r}")
            target = staging.joinpath(*relative.parts)
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(bundle.read(member))


def install(archive: Path, destination: Path, expected_sha256: str | None = None) -> Path:
    archive = archive.resolve()
    if not archive.is_file():
        raise ValueError(f"archive does not exist: {archive}")
    actual = _digest(archive)
    if expected_sha256 and actual != expected_sha256.lower():
        raise ValueError(f"sha256 mismatch: expected {expected_sha256}, got {actual}")

    destination = destination.expanduser().resolve()
    destination.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=".atropos-pack-", dir=destination))
    try:
        _extract(archive, staging)
        pack, _, errors = validate_pack.validate(staging)
        if errors:
            raise ValueError("invalid pack: " + "; ".join(errors))
        pack_id = str(pack["id"])
        version = str(pack["version"])
        final = destination / pack_id / version
        if final.exists():
            raise ValueError(f"pack is already installed: {final}")
        final.parent.mkdir(parents=True, exist_ok=True)
        staging.replace(final)
        metadata = {
            "archive": archive.name,
            "sha256": actual,
            "pack": {"id": pack_id, "version": version},
            "root": str(final),
        }
        (final / "install.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
        return final
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Install and validate an Atropos model-pack archive.")
    parser.add_argument("archive", type=Path, help="model-pack .zip archive")
    parser.add_argument("--destination", type=Path, default=Path("~/.atropos/packs"),
                        help="pack store root (default: ~/.atropos/packs)")
    parser.add_argument("--sha256", help="expected archive SHA-256 digest")
    args = parser.parse_args([] if argv is None else argv)
    if args.sha256 and (len(args.sha256) != 64 or any(c not in "0123456789abcdefABCDEF" for c in args.sha256)):
        parser.error("--sha256 must be a 64-character hexadecimal digest")
    try:
        root = install(args.archive, args.destination, args.sha256)
    except (OSError, ValueError, zipfile.BadZipFile) as error:
        print(f"install_pack.py: {error}", file=sys.stderr)
        return 1
    print(f"installed {root}")
    print(f"set ATROPOS_ROOT={root} for Lachesis or another consumer")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
