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
    r"repair:\d+\.\d+\.\d+:[0-9a-f]{8,64}|"
    r"(?:source_unhealthy|health_failed|policy_failure|auth_failure):[0-9a-f]{8,64})$"
)
COMPLETION_EVIDENCE_REF_RE = re.compile(
    r"^(evidence\[\d+\]|preconditions\.(?:phpBinHead|misePhpHead|supportPolicyDigest)|"
    r"researchSources\[\d+\])$"
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
    try:
        return json.loads(path.read_text())
    except (OSError, json.JSONDecodeError) as error:
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


def instruction_digest(path: pathlib.Path) -> str:
    require(path.is_file(), f"instruction file does not exist: {path}")
    return sha256_file(path)


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


def validate_archive(archive: pathlib.Path, version: str) -> None:
    require(archive.name == f"php-{version}-cli-macos-aarch64.tar.gz", "unexpected archive name")
    try:
        with tarfile.open(archive, "r:gz") as handle:
            members = handle.getmembers()
    except tarfile.TarError as error:
        raise ControlError(f"cannot read archive {archive}: {error}") from error
    names = set()
    for member in members:
        normalized = pathlib.PurePosixPath(_archive_member_name(member.name))
        require(
            ".." not in normalized.parts
            and not normalized.is_absolute()
            and not member.name.startswith("/"),
            f"unsafe archive path: {member.name}",
        )
        require(not member.issym() and not member.islnk(), "archive contains a link")
        names.add(normalized.as_posix())
    require("bin/php" in names, "archive does not contain bin/php")
