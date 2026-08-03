"""Evidence capture and the readers that re-derive its identity.

Captured bodies are opaque bytes: this module fetches them, digests them, and
proves a cited capture still resolves to the same bytes. It deliberately does
not interpret a body, so no source-format parser belongs here.
"""

from __future__ import annotations

import pathlib
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Iterable

from ._validation import (
    ACTION_KEY_RE,
    COMMIT_SHA_RE,
    SHA256_RE,
    ControlError,
    canonical_json,
    contained_path,
    load_json,
    require,
    sha256_bytes,
    utc_now,
    write_json,
)


EVIDENCE_CAPTURE_IDS = {
    "php_supported_versions",
    "php_release_feed",
    "php_source_tags",
    "php_bin_releases",
    "php_bin_state",
    "mise_php_releases",
    "mise_php_state",
}
RUNTIME_PLAN_EVIDENCE_IDS = {"evidence_manifest", "watch_decision"}


def manifest_digest(captures: Iterable[dict[str, Any]]) -> str:
    """Digest the identity of an evidence capture set.

    The writer (capture_evidence) and every reader (validate_recaptured_evidence,
    the attestation predicate) must agree byte for byte, so the projected fields
    and their order live here once. Only captureId, status, and digest are
    covered: timestamps and body paths differ between runs that captured
    identical evidence.
    """
    comparable = [
        {"captureId": item["captureId"], "status": item["status"], "digest": item["digest"]}
        for item in captures
    ]
    return sha256_bytes(canonical_json(comparable))


def validate_recaptured_evidence(
    plan: dict[str, Any],
    admitted_manifest: dict[str, Any],
    current_manifest: dict[str, Any],
) -> dict[str, Any]:
    """Verify cited authoritative captures while allowing runtime-only evidence."""

    def indexed_captures(manifest: dict[str, Any], label: str) -> dict[str, dict[str, Any]]:
        require(isinstance(manifest, dict), f"{label} evidence manifest must be an object")
        require(manifest.get("schemaVersion") == 1, f"{label} evidence manifest version is invalid")
        captures = manifest.get("captures")
        require(isinstance(captures, list), f"{label} evidence captures must be an array")
        indexed: dict[str, dict[str, Any]] = {}
        for capture in captures:
            require(isinstance(capture, dict), f"{label} evidence capture must be an object")
            capture_id = capture.get("captureId")
            digest = capture.get("digest")
            require(capture_id in EVIDENCE_CAPTURE_IDS, f"{label} evidence capture is unknown")
            require(capture_id not in indexed, f"{label} evidence capture is duplicated: {capture_id}")
            require(capture.get("status") == 200, f"{label} evidence capture is not healthy: {capture_id}")
            require(bool(SHA256_RE.fullmatch(digest or "")), f"{label} evidence digest is invalid: {capture_id}")
            indexed[capture_id] = capture
        require(set(indexed) == EVIDENCE_CAPTURE_IDS, f"{label} evidence capture set changed")
        require(
            manifest.get("manifestDigest") == manifest_digest(captures),
            f"{label} evidence manifest digest mismatch",
        )
        return indexed

    admitted = indexed_captures(admitted_manifest, "admitted")
    current = indexed_captures(current_manifest, "current")
    evidence = plan.get("evidence")
    require(isinstance(evidence, list) and bool(evidence), "autorelease plan has no evidence")
    verified = []
    for item in evidence:
        require(isinstance(item, dict), "plan evidence entry must be an object")
        capture_id = item.get("captureId")
        digest = item.get("digest")
        require(bool(SHA256_RE.fullmatch(digest or "")), f"plan evidence digest is invalid: {capture_id}")
        if capture_id in RUNTIME_PLAN_EVIDENCE_IDS:
            continue
        require(capture_id in admitted, f"plan evidence capture is unknown: {capture_id}")
        require(admitted[capture_id]["digest"] == digest, f"admitted evidence digest mismatch: {capture_id}")
        require(current[capture_id]["digest"] == digest, f"recaptured evidence changed: {capture_id}")
        verified.append(capture_id)
    require(bool(verified), "autorelease plan cites no authoritative captured evidence")
    return {"valid": True, "verifiedCaptureIds": sorted(verified)}


def validate_evidence_state_record(record: dict[str, Any]) -> None:
    require(isinstance(record, dict), "evidence state must be an object")
    require(
        set(record) == {"schemaVersion", "manifestDigest", "planDigest", "captures"},
        "evidence state fields changed",
    )
    require(record.get("schemaVersion") == 1, "invalid evidence state version")
    require(bool(SHA256_RE.fullmatch(record.get("manifestDigest", ""))), "invalid evidence manifest digest")
    require(bool(SHA256_RE.fullmatch(record.get("planDigest", ""))), "invalid evidence plan digest")
    captures = record.get("captures")
    require(isinstance(captures, list), "evidence captures must be an array")
    capture_ids = []
    for capture in captures:
        require(isinstance(capture, dict), "evidence capture must be an object")
        require(set(capture) == {"captureId", "digest", "status"}, "evidence capture fields changed")
        capture_ids.append(capture.get("captureId"))
        require(bool(SHA256_RE.fullmatch(capture.get("digest", ""))), "invalid evidence capture digest")
        require(capture.get("status") == 200, "evidence capture status is not healthy")
    require(len(capture_ids) == len(set(capture_ids)), "duplicate evidence capture")
    require(set(capture_ids) == EVIDENCE_CAPTURE_IDS, "evidence capture set changed")


def validate_evidence_attestation_predicate(
    predicate: dict[str, Any],
    *,
    run_id: str,
    source_sha: str,
    action_key: str,
    manifest_digest: str,
) -> None:
    require(isinstance(predicate, dict), "evidence attestation predicate must be an object")
    require(
        set(predicate) == {"schemaVersion", "runId", "sourceSha", "actionKey", "manifestDigest"},
        "evidence attestation predicate fields changed",
    )
    require(predicate.get("schemaVersion") == 1, "invalid evidence attestation predicate version")
    require(bool(re.fullmatch(r"[1-9][0-9]*", run_id)), "invalid expected watcher run")
    require(bool(COMMIT_SHA_RE.fullmatch(source_sha)), "invalid expected watcher source")
    require(bool(ACTION_KEY_RE.fullmatch(action_key)), "invalid expected watcher action")
    require(bool(SHA256_RE.fullmatch(manifest_digest)), "invalid expected evidence manifest")
    require(predicate.get("runId") == run_id, "evidence attestation run mismatch")
    require(predicate.get("sourceSha") == source_sha, "evidence attestation source mismatch")
    require(predicate.get("actionKey") == action_key, "evidence attestation action mismatch")
    require(
        predicate.get("manifestDigest") == manifest_digest,
        "evidence attestation manifest mismatch",
    )


def load_capture(manifest_path: pathlib.Path, capture_id: str) -> tuple[dict[str, Any], bytes]:
    manifest = load_json(manifest_path)
    require(isinstance(manifest, dict), "capture manifest must be an object")
    captures = manifest.get("captures", [])
    require(isinstance(captures, list), "capture manifest captures must be an array")
    matches = [item for item in captures if isinstance(item, dict) and item.get("captureId") == capture_id]
    require(len(matches) == 1, f"capture {capture_id} does not resolve exactly once")
    capture = matches[0]
    body_path = contained_path(manifest_path.parent, capture.get("bodyPath"), "capture body path")
    require(body_path.is_file(), f"capture body is missing: {body_path}")
    body = body_path.read_bytes()
    require(sha256_bytes(body) == capture.get("digest"), f"capture digest mismatch: {capture_id}")
    return capture, body


def load_plan_evidence(manifest_path: pathlib.Path, capture_id: str) -> tuple[dict[str, Any], bytes]:
    if capture_id not in RUNTIME_PLAN_EVIDENCE_IDS:
        return load_capture(manifest_path, capture_id)
    runtime_root = manifest_path.parent.parent
    path = {
        "evidence_manifest": manifest_path,
        "watch_decision": runtime_root / "watch-decision.json",
    }[capture_id]
    require(path.is_file(), f"runtime plan evidence is unavailable: {capture_id}")
    body = path.read_bytes()
    return {"captureId": capture_id, "digest": sha256_bytes(body)}, body


class RestrictedRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req: Any, fp: Any, code: int, msg: str, headers: Any, newurl: str) -> Any:
        old = urllib.parse.urlparse(req.full_url)
        new = urllib.parse.urlparse(newurl)
        if new.scheme != "https" or new.hostname != old.hostname:
            raise urllib.error.HTTPError(newurl, code, "cross-host redirect rejected", headers, fp)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


@dataclass(frozen=True)
class EvidenceSource:
    capture_id: str
    url: str
    max_bytes: int


def capture_evidence(
    output_dir: pathlib.Path,
    sources: Iterable[EvidenceSource],
    token: str | None = None,
) -> dict[str, Any]:
    """Fetch each source once and record what came back, healthy or not.

    The source set is supplied rather than defaulted: which sources are
    authoritative is a reviewed decision that stays in `control`, so this client
    holds no opinion about where evidence comes from.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    opener = urllib.request.build_opener(RestrictedRedirect)
    captures = []
    for source in sources:
        headers = {
            "Accept": "application/vnd.github+json, application/json, text/html",
            "User-Agent": "bigpixelrocket-autorelease/1",
        }
        if token and urllib.parse.urlparse(source.url).hostname == "api.github.com":
            headers["Authorization"] = f"Bearer {token}"
        request = urllib.request.Request(
            source.url,
            headers=headers,
        )
        last_error: Exception | None = None
        for attempt in range(3):
            if attempt:
                time.sleep(2**attempt)
            try:
                with opener.open(request, timeout=30) as response:
                    body = response.read(source.max_bytes + 1)
                    require(len(body) <= source.max_bytes, f"capture too large: {source.capture_id}")
                    body_path = pathlib.Path("raw") / f"{source.capture_id}.body"
                    destination = output_dir / body_path
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(body)
                    captures.append(
                        {
                            "captureId": source.capture_id,
                            "url": source.url,
                            "retrievedAt": utc_now(),
                            "status": response.status,
                            "contentType": response.headers.get("Content-Type"),
                            "etag": response.headers.get("ETag"),
                            "lastModified": response.headers.get("Last-Modified"),
                            "digest": sha256_bytes(body),
                            "bodyPath": body_path.as_posix(),
                        }
                    )
                    last_error = None
                    break
            except ControlError as error:
                last_error = error
                break
            except urllib.error.HTTPError as error:
                last_error = error
                if error.code not in {408, 429} and not 500 <= error.code < 600:
                    break
            except (OSError, urllib.error.URLError) as error:
                last_error = error
        if last_error is not None:
            body_path = pathlib.Path("raw") / f"{source.capture_id}.body"
            destination = output_dir / body_path
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(b"")
            captures.append(
                {
                    "captureId": source.capture_id,
                    "url": source.url,
                    "retrievedAt": utc_now(),
                    "status": 0,
                    "contentType": None,
                    "etag": None,
                    "lastModified": None,
                    "digest": sha256_bytes(b""),
                    "bodyPath": body_path.as_posix(),
                    "error": type(last_error).__name__,
                }
            )
    manifest = {
        "schemaVersion": 1,
        "capturedAt": utc_now(),
        "captures": captures,
        "manifestDigest": "",
    }
    manifest["manifestDigest"] = manifest_digest(captures)
    write_json(output_dir / "evidence-manifest.json", manifest)
    return manifest
