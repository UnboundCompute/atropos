#!/usr/bin/env python3
"""Build a deterministic zip archive from an Atropos pack directory."""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
import sys
import zipfile
from pathlib import Path

import validate_pack


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description="Build a deterministic Atropos model-pack archive.")
    parser.add_argument("--root", type=Path, default=validate_pack.ROOT, help="pack directory")
    parser.add_argument("--output", type=Path, required=True, help="output .zip path")
    parser.add_argument("--checksums", type=Path, help="optional sha256sum-format sidecar")
    parser.add_argument("--provenance", type=Path, help="optional JSON provenance sidecar")
    args = parser.parse_args([] if argv is None else argv)
    root = args.root.resolve()
    output = args.output.resolve()
    pack, model_files, errors = validate_pack.validate(root)
    if errors:
        for error in errors:
            print(f"build_pack.py: {error}", file=sys.stderr)
        return 1
    runtime_files = [
        path for pattern in pack.get("runtime_globs", [])
        for path in root.glob(pattern) if path.is_file()
    ]
    package_files = [root / "pack.json", root / pack["license_file"], *model_files, *runtime_files]
    for optional in ("README.md", "CHANGELOG.md"):
        candidate = root / optional
        if candidate.is_file():
            package_files.append(candidate)
    files = list(dict.fromkeys(package_files))
    if output in {path.resolve() for path in files}:
        print("build_pack.py: output must be outside the pack files", file=sys.stderr)
        return 2
    output.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(output, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as archive:
        for path in sorted(files, key=lambda item: item.relative_to(root).as_posix()):
            relative = path.relative_to(root).as_posix()
            info = zipfile.ZipInfo(relative, date_time=(1980, 1, 1, 0, 0, 0))
            info.compress_type = zipfile.ZIP_DEFLATED
            info.create_system = 3
            info.external_attr = 0o644 << 16
            archive.writestr(info, path.read_bytes())
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    if args.checksums:
        args.checksums.parent.mkdir(parents=True, exist_ok=True)
        args.checksums.write_text(f"{digest}  {output.name}\n", encoding="utf-8")
    if args.provenance:
        try:
            source_revision = subprocess.check_output(
                ["git", "-C", str(root), "rev-parse", "HEAD"],
                text=True,
                stderr=subprocess.DEVNULL,
            ).strip()
        except (OSError, subprocess.CalledProcessError):
            source_revision = None
        provenance = {
            "schema_version": 1,
            "artifact": output.name,
            "sha256": digest,
            "pack": {"id": pack.get("id"), "version": pack.get("version")},
            "source_revision": source_revision,
            "files": [path.relative_to(root).as_posix() for path in sorted(files, key=lambda item: item.relative_to(root).as_posix())],
        }
        args.provenance.parent.mkdir(parents=True, exist_ok=True)
        args.provenance.write_text(json.dumps(provenance, indent=2) + "\n", encoding="utf-8")
    print(f"built {output} for {pack.get('id')} v{pack.get('version')}")
    print(f"sha256 {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
