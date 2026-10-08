#!/usr/bin/env python3
"""Pin the release archive contract for workspace-agent.

The guest image recipe, install.ps1 and the MSI all consume these archives,
so the layout is a contract, not an implementation detail: one stage directory
per target, the agent binary and docs at its root, enrollment scripts beside
the Windows binary, and SHA256SUMS covering exactly the archives (plus the
MSI when it exists — MSI creation/signing changes bytes, so checksums are
always recomputed afterwards).
"""
import argparse
import hashlib
from pathlib import Path, PurePosixPath
import tarfile
import zipfile

# (os, arch) pairs that must exist. Windows is amd64-only for now (no ARM64
# guest runners); Linux covers both server arches.
TARGETS = (("linux", "amd64"), ("linux", "arm64"), ("windows", "amd64"))


def members_of(archive: Path, os_name: str) -> list[str]:
    if archive.suffix == ".zip":
        with zipfile.ZipFile(archive) as z:
            return [f.filename for f in z.infolist() if not f.is_dir()]
    with tarfile.open(archive, "r:gz") as t:
        entries = t.getmembers()
        assert all(e.isfile() or e.isdir() for e in entries), archive.name
        return [e.name for e in entries if e.isfile()]


def assert_binary_runnable(archive: Path, os_name: str) -> None:
    # Artifact upload/download drops the executable bit, so `make package`
    # must restore it; a tar member that cannot exec is not a usable agent.
    if os_name == "windows" or archive.suffix == ".zip":
        return
    with tarfile.open(archive, "r:gz") as t:
        member = next((m for m in t.getmembers() if m.name.endswith("/kw-agent")), None)
        assert member is not None, f"{archive.name}: kw-agent missing"
        assert member.mode & 0o111, f"{archive.name}: kw-agent is not executable"


def verify(directory: Path, version: str, require_msi: bool = False) -> None:
    sums = {}
    for line in (directory / "SHA256SUMS").read_text().splitlines():
        digest, name = line.split(maxsplit=1)
        name = name.removeprefix("*").removeprefix("./")
        assert name not in sums, f"duplicate checksum: {name}"
        sums[name] = digest

    expected = set()
    for os_name, arch in TARGETS:
        ext = "zip" if os_name == "windows" else "tar.gz"
        name = f"workspace-agent-{version}-{os_name}-{arch}.{ext}"
        expected.add(name)
        archive = directory / name
        with archive.open("rb") as f:
            assert hashlib.file_digest(f, "sha256").hexdigest() == sums[name], name

        members = members_of(archive, os_name)
        root = f"workspace-agent-{os_name}-{arch}"
        assert len(members) == len(set(members)), f"duplicate member: {name}"
        for member in members:
            p = PurePosixPath(member)
            assert not p.is_absolute() and ".." not in p.parts, member
            assert p.parts[0] == root and "\\" not in member, member

        exe = "kw-agent.exe" if os_name == "windows" else "kw-agent"
        required = {f"{root}/{exe}", f"{root}/README.md", f"{root}/LICENSE"}
        if os_name == "windows":
            required |= {f"{root}/install.ps1", f"{root}/uninstall.ps1"}
        missing = required - set(members)
        assert not missing, f"{name}: missing members {sorted(missing)}"
        assert_binary_runnable(archive, os_name)
        print(f"{name}: contract OK")

    # The unsigned Windows MSI ships alongside the archives (same release,
    # SHA256 covered) but is not one of them: enrollment stays with
    # install.ps1. Any extra checksum entry must be that MSI, hash verified.
    extra = set(sums) - expected
    installer = f"workspace-agent-{version}-windows-amd64.msi"
    assert extra <= {installer}, f"unexpected checksum entries: {extra - {installer}}"
    if require_msi:
        assert extra == {installer}, "the Windows MSI is required"
    for name in sorted(extra):
        assert name.endswith(".msi"), f"unexpected checksum entry: {name}"
        with (directory / name).open("rb") as f:
            assert hashlib.file_digest(f, "sha256").hexdigest() == sums[name], name
        print(f"{name}: checksum OK (msi, outside archive contract)")

    actual = {p.name for p in directory.iterdir() if p.name.endswith((".tar.gz", ".zip", ".msi"))}
    assert set(sums) == actual, f"checksum inventory differs from artifacts: {set(sums) ^ actual}"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("version")
    parser.add_argument("--require-msi", action="store_true")
    args = parser.parse_args()
    verify(args.directory, args.version, args.require_msi)
