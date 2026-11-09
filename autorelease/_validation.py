"""Primitive rejections shared by every deterministic control.

Digests, canonical JSON, path containment, and the regular expressions that fix
the shape of every identifier live here so that one definition is asserted at
every boundary. Nothing in this module reads state or reaches the network; it is
the bottom of the package and imports no sibling.
"""

from __future__ import annotations

import datetime as dt
import fnmatch
import hashlib
import json
import pathlib
import re
import tarfile
from typing import Any, Iterable


ROOT = pathlib.Path(__file__).resolve().parents[1]
SHA256_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
COMMIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")
ACTION_KEY_RE = re.compile(
    r"^(no_change:[0-9a-f]{16}|new_patch:\d+\.\d+\.\d+|new_branch:\d+\.\d+|"
    r"branch_eol:\d+\.\d+:\d{4}-\d{2}-\d{2}|"
    r"recipe_rebuild:\d+\.\d+\.\d+:[1-9]\d*|"
    r"(?:source_unhealthy|health_failed|policy_failure):[0-9a-f]{8,64})$"
)
STABLE_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+(?:-[1-9]\d*)?$")
PROTECTED_PATHS = pathlib.Path(__file__).with_name("protected-paths.json")
try:
    PROTECTED_PATTERNS = tuple(json.loads(PROTECTED_PATHS.read_text())["patterns"])
except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
    raise RuntimeError(f"cannot load protected paths: {error}") from error
if not all(isinstance(pattern, str) and pattern for pattern in PROTECTED_PATTERNS):
    raise RuntimeError("protected paths must be non-empty strings")
SECRET_PATTERNS = (
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"github_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bgh[opusr]_[A-Za-z0-9]{30,}\b"),
    re.compile(r"\bsk-[A-Za-z0-9_-]{20,}\b"),
)


class ControlError(RuntimeError):
    """A fail-closed deterministic-control rejection."""


def utc_now() -> str:
    return dt.datetime.now(dt.UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def sha256_bytes(value: bytes) -> str:
    return "sha256:" + hashlib.sha256(value).hexdigest()


def sha256_file(path: pathlib.Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return "sha256:" + digest.hexdigest()


def load_json(path: pathlib.Path) -> Any:
    # Bytes that are not UTF-8 are as unreadable as malformed JSON, and must reach
    # callers as the same fail-closed rejection rather than an uncaught decode error.
    try:
        return json.loads(path.read_text())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ControlError(f"cannot load JSON {path}: {error}") from error


def write_json(path: pathlib.Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(canonical_json(value))
    temporary.replace(path)


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ControlError(message)


def contained_path(root: pathlib.Path, value: Any, label: str) -> pathlib.Path:
    require(isinstance(value, str) and bool(value), f"{label} is missing")
    relative = pathlib.PurePosixPath(value)
    require(not relative.is_absolute() and ".." not in relative.parts, f"unsafe {label}: {value}")
    resolved_root = root.resolve()
    resolved = (resolved_root / pathlib.Path(*relative.parts)).resolve()
    require(resolved.is_relative_to(resolved_root), f"unsafe {label}: {value}")
    return resolved


def resolve_json_pointer(document: Any, pointer: str) -> Any:
    if pointer == "":
        return document
    require(pointer.startswith("/"), f"invalid JSON pointer: {pointer}")
    current = document
    for token in pointer[1:].split("/"):
        key = token.replace("~1", "/").replace("~0", "~")
        if isinstance(current, list):
            require(key.isdigit(), f"non-numeric array index in pointer: {pointer}")
            index = int(key)
            require(index < len(current), f"array index does not resolve: {pointer}")
            current = current[index]
        else:
            require(isinstance(current, dict) and key in current, f"pointer does not resolve: {pointer}")
            current = current[key]
    return current


def path_is_protected(path: str) -> bool:
    normalized = pathlib.PurePosixPath(path).as_posix()
    return any(fnmatch.fnmatch(normalized, pattern) for pattern in PROTECTED_PATTERNS)


def path_is_allowed(path: str, patterns: Iterable[str]) -> bool:
    normalized = pathlib.PurePosixPath(path).as_posix()
    return any(fnmatch.fnmatch(normalized, pattern) for pattern in patterns)


def _archive_member_name(name: str) -> str:
    return name[2:] if name.startswith("./") else name


# Every release publishes one archive per platform, named as `scripts/lib.sh`
# `build_platform` spells the platform, and mise-php selects its archive by that
# name. Each platform maps to the leading bytes its `bin/php` must start with: a
# 64-bit little-endian Mach-O for arm64, or a 64-bit little-endian ELF and its
# e_machine (offset 18) for Linux.
RELEASE_PLATFORMS = ("macos-aarch64", "linux-x86_64", "linux-aarch64")
_PLATFORM_EXECUTABLE_HEADERS = {
    "macos-aarch64": ((0, b"\xcf\xfa\xed\xfe"), (4, b"\x0c\x00\x00\x01")),
    "linux-x86_64": ((0, b"\x7fELF\x02\x01"), (18, b"\x3e\x00")),
    "linux-aarch64": ((0, b"\x7fELF\x02\x01"), (18, b"\xb7\x00")),
}
# Releases published before Linux builds carry only the macOS archive. They stay
# immutable, so the code that reads a published release back accepts this set too;
# nothing that creates a release does.
LEGACY_RELEASE_PLATFORMS = ("macos-aarch64",)


def release_archive_name(version: str, platform: str) -> str:
    require(platform in RELEASE_PLATFORMS, f"unknown release platform: {platform}")
    return f"php-{version}-cli-{platform}.tar.gz"


def _archive_platform(archive: pathlib.Path, version: str) -> str:
    for platform in RELEASE_PLATFORMS:
        if archive.name == release_archive_name(version, platform):
            return platform
    raise ControlError("unexpected archive name")


def _archive_members(archive: pathlib.Path) -> dict[str, tarfile.TarInfo]:
    try:
        with tarfile.open(archive, "r:gz") as handle:
            members = handle.getmembers()
    except tarfile.TarError as error:
        raise ControlError(f"cannot read archive {archive}: {error}") from error
    names: dict[str, tarfile.TarInfo] = {}
    for member in members:
        normalized = pathlib.PurePosixPath(_archive_member_name(member.name))
        require(
            ".." not in normalized.parts
            and not normalized.is_absolute()
            and not member.name.startswith("/"),
            f"unsafe archive path: {member.name}",
        )
        require(not member.issym() and not member.islnk(), "archive contains a link")
        names[normalized.as_posix()] = member
    return names


def _read_member(archive: pathlib.Path, member: tarfile.TarInfo, limit: int | None = None) -> bytes:
    try:
        with tarfile.open(archive, "r:gz") as handle:
            stream = handle.extractfile(member)
            require(stream is not None, f"archive member is not a file: {member.name}")
            return stream.read() if limit is None else stream.read(limit)
    except tarfile.TarError as error:
        raise ControlError(f"cannot read archive {archive}: {error}") from error


def validate_archive(archive: pathlib.Path, version: str) -> None:
    """Reject an archive that is not one safe release archive of `version`.

    The name must be one platform's archive name, every member must stay inside the
    archive without links, and `bin/php` must be an executable for that platform, so
    an archive can never be published under another platform's name.
    """
    platform = _archive_platform(archive, version)
    members = _archive_members(archive)
    require("bin/php" in members, "archive does not contain bin/php")
    header = _read_member(archive, members["bin/php"], 32)
    require(
        all(header[offset : offset + len(expected)] == expected for offset, expected in _PLATFORM_EXECUTABLE_HEADERS[platform]),
        f"bin/php is not a {platform} executable",
    )


def _archive_manifest(archive: pathlib.Path, version: str) -> bytes:
    members = _archive_members(archive)
    require("share/php-bin/manifest.json" in members, f"{archive.name} has no share/php-bin/manifest.json")
    body = _read_member(archive, members["share/php-bin/manifest.json"])
    try:
        manifest = json.loads(body)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ControlError(f"{archive.name} has an unreadable manifest: {error}") from error
    require(
        isinstance(manifest, dict)
        and manifest.get("schemaVersion") == 1
        and manifest.get("release") == version
        and manifest.get("phpVersion") == version.split("-", 1)[0]
        and isinstance(manifest.get("extensions"), list),
        f"{archive.name} has a manifest for another release or schema",
    )
    return body


def release_checksums(directory: pathlib.Path, names: Iterable[str]) -> bytes:
    """Return the canonical SHA256SUMS for `names`: one `<hex>  <name>` line each, sorted by name."""
    lines = [f"{sha256_file(directory / name).removeprefix('sha256:')}  {name}\n" for name in sorted(names)]
    return "".join(lines).encode()


def validate_release_assets(directory: pathlib.Path, version: str, allow_legacy: bool = False) -> dict[str, str]:
    """Return the digest of every asset of one release staged in `directory`.

    A release is exactly one archive per platform plus SHA256SUMS, nothing else. Every
    archive passes `validate_archive`, carries the same `share/php-bin/manifest.json`,
    and SHA256SUMS is byte for byte the canonical listing of the archives. With
    `allow_legacy`, a published macOS-only release from before Linux builds is accepted
    too, checked as it was published: its archive and its one checksum line.
    """
    require(bool(STABLE_VERSION_RE.fullmatch(version or "")), f"release version is invalid: {version}")
    require(directory.is_dir(), f"release assets directory is missing: {directory}")
    present = sorted(path.name for path in directory.iterdir())
    full = [release_archive_name(version, platform) for platform in RELEASE_PLATFORMS]
    legacy = [release_archive_name(version, platform) for platform in LEGACY_RELEASE_PLATFORMS]
    if present == sorted([*full, "SHA256SUMS"]):
        archives = full
    elif allow_legacy and present == sorted([*legacy, "SHA256SUMS"]):
        archives = legacy
    else:
        raise ControlError(f"release {version} assets are not exactly the expected set: {', '.join(present) or 'none'}")
    for name in archives:
        require((directory / name).is_file(), f"release asset is not a file: {name}")
        validate_archive(directory / name, version)
    if archives == full:
        manifests = {_archive_manifest(directory / name, version) for name in archives}
        require(len(manifests) == 1, "the release archives carry different manifests")
    checksums = directory / "SHA256SUMS"
    require(checksums.is_file(), "SHA256SUMS is not a file")
    require(checksums.read_bytes() == release_checksums(directory, archives), "SHA256SUMS does not bind exactly the release archives")
    return {name: sha256_file(directory / name) for name in sorted([*archives, "SHA256SUMS"])}
