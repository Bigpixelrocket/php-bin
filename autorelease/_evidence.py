"""Evidence capture and the readers that re-derive its identity.

Captured bodies are opaque bytes: this module fetches them, digests them, and
proves a cited capture still resolves to the same bytes. It deliberately does
not interpret a body, so no source-format parser belongs here. A source may
carry a reviewed identity projection supplied by the registry in `control`;
this module applies it blindly before digesting and retains the unprojected
bytes beside the digested body, so which fields count toward evidence identity
stays a reviewed decision rather than a client detail.
"""

from __future__ import annotations

import pathlib
import re
import secrets
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any, Callable, Iterable

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
# The aggregate release feed names only the newest release of each major, so every
# maintained branch also has its own feed capture. The set follows the accepted
# support policy, so it is validated by shape rather than listed.
BRANCH_FEED_CAPTURE_PREFIX = "php_release_feed_"
BRANCH_FEED_CAPTURE_RE = re.compile(r"^php_release_feed_(\d+\.\d+)$")


def branch_feed_capture_id(branch: str) -> str:
    """Return the capture ID of one maintained branch's release feed."""
    capture_id = f"{BRANCH_FEED_CAPTURE_PREFIX}{branch}"
    require(bool(BRANCH_FEED_CAPTURE_RE.fullmatch(capture_id)), f"invalid release branch: {branch}")
    return capture_id


STABLE_RELEASE_ACTIONS = {"new_patch", "new_branch"}
# php.net sits behind a CDN that caches every URL, query string included, for
# hours to 30 days per edge and ignores request cache headers, so two runners can
# read different snapshots of the same feed. A fresh value for this parameter on
# every request is a key no edge has cached; a fixed value would only become one
# more cached key. The manifest records the canonical URL without it.
EDGE_CACHE_BYPASS_PARAMETER = "autorelease_fetch"
# The CDN names the cache result of every response in this header. A key no request
# has used before cannot be a genuine hit, so a HIT on a bypassing fetch means the
# CDN has started to ignore the parameter and the bypass no longer works.
EDGE_CACHE_STATUS_HEADER = "CDN-Cache"


class EdgeCacheHit(ControlError):
    """A cache-bypassing fetch was answered from an edge cache anyway."""


def release_feed_capture_ids(version: str) -> set[str]:
    """Return the captures that can prove one stable PHP version is released.

    Those are the aggregate feed and the version's own branch feed; another branch's
    feed never proves it. Admission accepts the version only from one of these, and
    the publish recapture requires the plan to cite one of them, so the two agree
    on what proves a release.
    """
    match = re.fullmatch(r"(\d+\.\d+)\.\d+", version) if isinstance(version, str) else None
    require(bool(match), f"stable release version is invalid: {version}")
    return {"php_release_feed", branch_feed_capture_id(match.group(1))}


def is_release_feed(capture_id: Any) -> bool:
    """Return whether a capture ID names the aggregate or one branch's release feed."""
    return capture_id == "php_release_feed" or (
        isinstance(capture_id, str) and bool(BRANCH_FEED_CAPTURE_RE.fullmatch(capture_id))
    )


def validate_capture_id_set(capture_ids: Iterable[Any], label: str) -> None:
    """Require exactly the fixed sources plus any number of per-branch feeds.

    Which branches are captured is decided by the support policy at capture time, so
    a stored record written before a branch was added or retired stays valid; only
    an unknown ID, a duplicate, or a missing fixed source is rejected.
    """
    capture_ids = list(capture_ids)
    require(len(capture_ids) == len(set(capture_ids)), f"duplicate {label}evidence capture")
    branch_feeds = {
        item for item in capture_ids if isinstance(item, str) and BRANCH_FEED_CAPTURE_RE.fullmatch(item)
    }
    require(set(capture_ids) - branch_feeds == EVIDENCE_CAPTURE_IDS, f"{label}evidence capture set changed")


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
    """Verify that the upstream truth a plan was admitted on still holds at publication.

    Every cited authoritative capture must match the admitted manifest and, with
    one exception, recapture byte-identically. The exception is a stable release
    (`new_patch`, `new_branch`) and release feeds that say nothing about its
    version: another branch's feed, and the aggregate feed when the version's own
    branch feed is the cited proof. A release on another branch moves those feeds
    without changing anything about this one, so they do not stop the
    publication. The own branch feed is bound whenever it was captured, cited or
    not, because admission reads it to prove no newer patch on the branch
    supersedes the version. Every other cited capture, repository state included,
    stays bound for every action. Runtime-only evidence is never recaptured. The
    publish command also reruns the supersession check on the recaptured feeds, so
    an exempt feed that names a later patch on the branch still stops the release.
    """

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
            require(
                capture_id in EVIDENCE_CAPTURE_IDS
                or (isinstance(capture_id, str) and bool(BRANCH_FEED_CAPTURE_RE.fullmatch(capture_id))),
                f"{label} evidence capture is unknown",
            )
            require(capture_id not in indexed, f"{label} evidence capture is duplicated: {capture_id}")
            require(capture.get("status") == 200, f"{label} evidence capture is not healthy: {capture_id}")
            require(bool(SHA256_RE.fullmatch(digest or "")), f"{label} evidence digest is invalid: {capture_id}")
            indexed[capture_id] = capture
        validate_capture_id_set(indexed, f"{label} ")
        require(
            manifest.get("manifestDigest") == manifest_digest(captures),
            f"{label} evidence manifest digest mismatch",
        )
        return indexed

    admitted = indexed_captures(admitted_manifest, "admitted")
    current = indexed_captures(current_manifest, "current")
    # Both captures run against the same accepted support policy, so a differing
    # branch-feed set means the policy moved under the admitted plan.
    require(set(admitted) == set(current), "recaptured evidence capture set changed")
    evidence = plan.get("evidence")
    require(isinstance(evidence, list) and bool(evidence), "autorelease plan has no evidence")
    proof_feeds: set[str] | None = None
    if plan.get("action") in STABLE_RELEASE_ACTIONS:
        release_intent = plan.get("releaseIntent")
        require(isinstance(release_intent, dict), "stable release action has no release intent")
        proof_feeds = release_feed_capture_ids(release_intent.get("version"))
    cited = set()
    for item in evidence:
        require(isinstance(item, dict), "plan evidence entry must be an object")
        capture_id = item.get("captureId")
        digest = item.get("digest")
        require(bool(SHA256_RE.fullmatch(digest or "")), f"plan evidence digest is invalid: {capture_id}")
        if capture_id in RUNTIME_PLAN_EVIDENCE_IDS:
            continue
        require(capture_id in admitted, f"plan evidence capture is unknown: {capture_id}")
        require(admitted[capture_id]["digest"] == digest, f"admitted evidence digest mismatch: {capture_id}")
        cited.add(capture_id)
    require(bool(cited), "autorelease plan cites no authoritative captured evidence")
    verified = cited
    if proof_feeds is not None:
        require(bool(cited & proof_feeds), "stable release cites no release feed that proves its version")
        own_branch_feed = proof_feeds - {"php_release_feed"}
        release_feeds = {capture_id for capture_id in admitted if is_release_feed(capture_id)}
        # The aggregate feed stays bound only while it is the proof: once the own
        # branch feed is cited, the aggregate adds nothing but other branches' news.
        unrelated = release_feeds - own_branch_feed
        if not cited & own_branch_feed:
            unrelated -= {"php_release_feed"}
        # The own branch feed is bound even when uncited: the aggregate feed is not
        # branch-scoped, so it alone cannot show that the branch has moved on.
        verified = (cited - unrelated) | (own_branch_feed & set(admitted))
    for capture_id in sorted(verified):
        require(
            current[capture_id]["digest"] == admitted[capture_id]["digest"],
            f"recaptured evidence changed: {capture_id}",
        )
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
    validate_capture_id_set(capture_ids, "")


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
    # A reviewed identity projection: the digested body is normalize(raw bytes),
    # so volatile fields with no autorelease consequence stay out of evidence
    # identity. None digests the raw bytes unchanged.
    normalize: Callable[[bytes], bytes] | None = None
    # Fetch past a shared edge cache that could serve a stale snapshot; see
    # EDGE_CACHE_BYPASS_PARAMETER. Only the fetch changes: `url` stays the
    # canonical address the manifest records.
    bypass_edge_cache: bool = False


def fetch_url(source: EvidenceSource) -> str:
    """Return the address to request for one fetch of a source.

    A cache-bypassing source gets a new random parameter value on every call, so
    each attempt, including a retry, reaches the origin rather than an edge copy.
    """
    if not source.bypass_edge_cache:
        return source.url
    separator = "&" if urllib.parse.urlparse(source.url).query else "?"
    return f"{source.url}{separator}{EDGE_CACHE_BYPASS_PARAMETER}={secrets.token_hex(16)}"


def require_edge_cache_miss(source: EvidenceSource, headers: Any) -> None:
    """Reject a bypassing fetch the edge says it served from its cache.

    The capture then fails like any unreachable source (status 0): the watcher
    raises `source_unhealthy` and the publish recapture refuses it, instead of
    evidence silently going stale again. A response without the header is
    accepted: only a positive hit proves the bypass failed.
    """
    if not source.bypass_edge_cache:
        return
    status = str(headers.get(EDGE_CACHE_STATUS_HEADER) or "").strip().upper()
    if status == "HIT":
        raise EdgeCacheHit(f"edge cache served a bypassing fetch: {source.capture_id}")


def capture_evidence(
    output_dir: pathlib.Path,
    sources: Iterable[EvidenceSource],
    token: str | None = None,
) -> dict[str, Any]:
    """Fetch each source once and record what came back, healthy or not.

    The source set is supplied rather than defaulted: which sources are
    authoritative is a reviewed decision that stays in `control`, so this client
    holds no opinion about where evidence comes from. Each capture records the
    source's canonical `url`, never the cache-bypassing address actually fetched,
    and evidence identity (`manifest_digest`) covers no URL at all.
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
        last_error: Exception | None = None
        for attempt in range(3):
            if attempt:
                time.sleep(2**attempt)
            try:
                request = urllib.request.Request(fetch_url(source), headers=headers)
                with opener.open(request, timeout=30) as response:
                    require_edge_cache_miss(source, response.headers)
                    body = response.read(source.max_bytes + 1)
                    require(len(body) <= source.max_bytes, f"capture too large: {source.capture_id}")
                    stored = source.normalize(body) if source.normalize else body
                    body_path = pathlib.Path("raw") / f"{source.capture_id}.body"
                    destination = output_dir / body_path
                    destination.parent.mkdir(parents=True, exist_ok=True)
                    destination.write_bytes(stored)
                    raw_path = destination.parent / f"{source.capture_id}.body.raw"
                    if stored != body:
                        # The projection is what admission and recapture verify, so
                        # the digest covers the stored body; the unprojected bytes
                        # stay retrievable for audit but carry no identity.
                        raw_path.write_bytes(body)
                    else:
                        # A reused output directory must not retain a raw artifact
                        # from an earlier capture the manifest no longer describes.
                        raw_path.unlink(missing_ok=True)
                    captures.append(
                        {
                            "captureId": source.capture_id,
                            "url": source.url,
                            "retrievedAt": utc_now(),
                            "status": response.status,
                            "contentType": response.headers.get("Content-Type"),
                            "etag": response.headers.get("ETag"),
                            "lastModified": response.headers.get("Last-Modified"),
                            # Diagnostic only, outside evidence identity: shows which
                            # edge answered when a feed later looks stale.
                            "edgeCache": response.headers.get(EDGE_CACHE_STATUS_HEADER),
                            "digest": sha256_bytes(stored),
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
            (destination.parent / f"{source.capture_id}.body.raw").unlink(missing_ok=True)
            captures.append(
                {
                    "captureId": source.capture_id,
                    "url": source.url,
                    "retrievedAt": utc_now(),
                    "status": 0,
                    "contentType": None,
                    "etag": None,
                    "lastModified": None,
                    "edgeCache": None,
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
