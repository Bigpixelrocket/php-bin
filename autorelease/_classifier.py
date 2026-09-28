"""Deterministic classification of one watcher capture into exactly one plan.

The classifier reads only what the watcher already retained: the evidence manifest and
its captured bodies, the watch decision, the exact preconditions, the durable event
records, and the accepted support policy. It applies the reviewed priority rules in a
fixed order and returns one plan in `schemas/autorelease-plan.schema.json`, with every
evidence digest computed from the bytes it cites:

1. Unhealthy evidence stops the run as `blocked`: nothing else can be proven from it.
2. An incomplete event record is resumed under its own action key. A lifecycle record
   that is only waiting for mise-php readiness lets a due patch go first.
3. A `new_patch` per maintained branch, oldest branch first, for the newest stable
   version that branch's own feed names when it is neither published nor superseded.
   A maintained branch that never shipped a release needs a human instead: its first
   release belongs to `new_branch`, behind the cross-repository readiness gate.
4. Lifecycle evidence on the supported-versions page: a `new_branch`, then a
   `branch_eol`. Patches never read that page, so an unreadable page blocks only a run
   with no patch due.
5. The one `recipe_rebuild` the watch decision selected.
6. `no_change`, keyed on the manifest's embedded `manifestDigest`.

It never admits its own output. `_admission.validate_plan` re-checks every plan
independently, so a defect here is rejected rather than trusted. The two share only
small pure helpers (capture loading, pointer resolution, feed capture names).

Every outcome is explicit. A body that does not have its reviewed shape, a lifecycle
contradiction, or a record that cannot be resumed produces a `blocked` or
`needs_human` plan, which the watcher turns into one deduplicated owner issue. Nothing
is guessed.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import json
import pathlib
import re
from typing import Any, Iterable

from ._admission import REQUIRED_PLAN_CHECKS
from ._evidence import branch_feed_capture_id, load_capture, load_plan_evidence
from ._state import PUBLISHED_RELEASE_TAG_RE
from ._validation import (
    ACTION_KEY_RE,
    COMMIT_SHA_RE,
    SHA256_RE,
    ControlError,
    canonical_json,
    load_json,
    require,
    resolve_json_pointer,
    sha256_bytes,
)


# Row classes php.net assigns on supported-versions.php. A branch keeps an `eol` row for
# 28 days after its security support ends (php.net's `KEEP_EOL`), which is what makes
# its EOL date readable at all. A watcher that misses that whole window finds the branch
# with no row, which is a lifecycle contradiction for a human, never a guessed date.
# Any other class is a page this parser was not reviewed against.
SUPPORT_STATES = frozenset({"stable", "security", "eol", "future"})
SUPPORTED_STATES = frozenset({"stable", "security"})
SUPPORT_TABLE_HEADERS = (
    "Branch",
    "Initial Release",
    "Active Support Until",
    "Security Support Until",
    "Notes",
)
_TABLE_RE = re.compile(rb'<table class="standard">(.*?)</table>', re.DOTALL)
_THEAD_RE = re.compile(rb"<thead>(.*?)</thead>", re.DOTALL)
_TBODY_RE = re.compile(rb"<tbody>(.*?)</tbody>", re.DOTALL)
_HEADER_RE = re.compile(rb"<th(?:\s[^>]*)?>(.*?)</th>", re.DOTALL)
_ROW_RE = re.compile(rb'<tr class="([^"]*)">(.*?)</tr>', re.DOTALL)
_BRANCH_LINK_RE = re.compile(rb'<a href="/downloads\.php\?version=(\d+\.\d+)">(\d+\.\d+)</a>')
_DATE_CELL_RE = re.compile(rb"<td>(\d{1,2} [A-Z][a-z]{2} \d{4})</td>")
_STABLE_PATCH_RE = re.compile(r"^(\d+)\.(\d+)\.(\d+)$")
_BRANCH_RE = re.compile(r"^\d+\.\d+$")
PRECONDITION_FIELDS = ("phpBinHead", "misePhpHead", "supportPolicyDigest")


class SourceFormatError(ControlError):
    """A healthy capture whose body does not have its reviewed shape."""

    def __init__(self, capture_id: str, reason: str):
        super().__init__(f"{capture_id}: {reason}")
        self.capture_id = capture_id
        self.reason = reason


@dataclasses.dataclass(frozen=True)
class SupportRow:
    """One branch row of the supported-versions table, with the exact bytes it spans."""

    branch: str
    state: str
    initial_release: dt.date
    active_until: dt.date
    security_until: dt.date
    fragment: str


def version_key(version: str) -> tuple[int, ...]:
    """Order dotted numeric versions and branches numerically, never lexically."""
    return tuple(int(part) for part in version.split("."))


def branch_of(version: str) -> str:
    """Return the `<major>.<minor>` branch of an exact stable patch version."""
    match = _STABLE_PATCH_RE.fullmatch(version)
    require(bool(match), f"not an exact stable patch version: {version}")
    return f"{match.group(1)}.{match.group(2)}"


def parse_supported_versions(body: bytes) -> dict[str, SupportRow]:
    """Parse php.net/supported-versions.php into its branch rows, or raise.

    The parser accepts exactly the reviewed page shape: one `standard` table with a
    header row, whose headers are the five reviewed columns, and a body made only of
    branch rows. Each
    row carries one known state class, one branch download link whose target and text
    agree, and exactly three absolute dates (initial release, active support end,
    security support end). Anything else raises `SourceFormatError`, so a redesigned
    page becomes an owner issue instead of a guess about which branches are supported.
    The returned fragment is a contiguous slice of the body, from the row start through
    its security date, so a plan can cite it as a text locator.
    """
    capture_id = "php_supported_versions"
    # The page also carries a headerless `standard` table: the colour key below the
    # calendar. Only a table with a header row can be the support table.
    tables = [table for table in _TABLE_RE.finditer(body) if _THEAD_RE.search(table.group(1))]
    if len(tables) != 1:
        raise SourceFormatError(capture_id, f"expected one support table, found {len(tables)}")
    table = tables[0]
    theads = _THEAD_RE.findall(table.group(1))
    if len(theads) != 1:
        raise SourceFormatError(capture_id, "support table has no single header")
    headers = tuple(
        re.sub(rb"\s+", b" ", cell).strip().decode("utf-8", "replace")
        for cell in _HEADER_RE.findall(theads[0])
    )
    if headers != SUPPORT_TABLE_HEADERS:
        raise SourceFormatError(capture_id, f"support table headers changed: {list(headers)}")
    tbodies = list(_TBODY_RE.finditer(body, table.start(1), table.end(1)))
    if len(tbodies) != 1:
        raise SourceFormatError(capture_id, "support table has no single body")
    tbody = tbodies[0]
    rows: dict[str, SupportRow] = {}
    cursor = tbody.start(1)
    for row in _ROW_RE.finditer(body, tbody.start(1), tbody.end(1)):
        if body[cursor : row.start()].strip():
            raise SourceFormatError(capture_id, "support table body holds content outside branch rows")
        cursor = row.end()
        state = row.group(1).decode("utf-8", "replace")
        if state not in SUPPORT_STATES:
            raise SourceFormatError(capture_id, f"unknown support state: {state}")
        links = list(_BRANCH_LINK_RE.finditer(body, row.start(2), row.end(2)))
        if len(links) != 1 or links[0].group(1) != links[0].group(2):
            raise SourceFormatError(capture_id, "support row does not name exactly one branch")
        branch = links[0].group(1).decode()
        if branch in rows:
            raise SourceFormatError(capture_id, f"branch {branch} is listed twice")
        dates = list(_DATE_CELL_RE.finditer(body, row.start(2), row.end(2)))
        if len(dates) != 3:
            raise SourceFormatError(capture_id, f"branch {branch} does not carry exactly three dates")
        try:
            initial, active, security = (
                dt.datetime.strptime(item.group(1).decode(), "%d %b %Y").date() for item in dates
            )
        except ValueError as error:
            raise SourceFormatError(capture_id, f"branch {branch} carries an unreadable date") from error
        if not initial <= active <= security:
            raise SourceFormatError(capture_id, f"branch {branch} support dates are out of order")
        try:
            fragment = body[row.start() : dates[2].end()].decode("utf-8")
        except UnicodeDecodeError as error:
            raise SourceFormatError(capture_id, f"branch {branch} row is not valid UTF-8") from error
        rows[branch] = SupportRow(branch, state, initial, active, security, fragment)
    if body[cursor : tbody.end(1)].strip():
        raise SourceFormatError(capture_id, "support table body holds content outside branch rows")
    if not rows:
        raise SourceFormatError(capture_id, "support table lists no branch")
    return rows


def _short_digest(value: Any) -> str:
    """Return a stable 16-hex suffix for an action key derived from `value`."""
    return sha256_bytes(canonical_json(value)).removeprefix("sha256:")[:16]


class _Capture:
    """Read access to one retained capture set, with digests re-derived from bytes."""

    def __init__(self, manifest_path: pathlib.Path):
        self.manifest_path = manifest_path
        self.manifest = load_json(manifest_path)
        require(isinstance(self.manifest, dict), "evidence manifest must be an object")
        captures = self.manifest.get("captures")
        require(isinstance(captures, list), "evidence manifest captures must be an array")
        self.captures = captures
        self.index = {
            capture.get("captureId"): position
            for position, capture in enumerate(captures)
            if isinstance(capture, dict)
        }
        require(len(self.index) == len(captures), "evidence manifest captures are not unique objects")
        _decision_capture, decision_body = load_plan_evidence(manifest_path, "watch_decision")
        try:
            self.decision = json.loads(decision_body)
        except json.JSONDecodeError as error:
            raise ControlError(f"watch decision is not valid JSON: {error}") from error
        require(isinstance(self.decision, dict), "watch decision must be an object")
        require(
            self.decision.get("manifestDigest") == self.manifest.get("manifestDigest"),
            "watch decision was not taken on this evidence manifest",
        )

    def has(self, capture_id: str) -> bool:
        return capture_id in self.index

    def body(self, capture_id: str) -> tuple[dict[str, Any], bytes]:
        return load_capture(self.manifest_path, capture_id)

    def json_body(self, capture_id: str) -> Any:
        _capture, body = self.body(capture_id)
        try:
            return json.loads(body)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise SourceFormatError(capture_id, "body is not valid JSON") from error

    def pointer(self, capture_id: str, pointer: str, claim: str) -> tuple[dict[str, Any], Any]:
        """Cite one JSON value of a capture or runtime input, resolved from its bytes."""
        capture, body = load_plan_evidence(self.manifest_path, capture_id)
        value = resolve_json_pointer(json.loads(body), pointer)
        return (
            {
                "captureId": capture_id,
                "digest": capture["digest"],
                "claim": claim,
                "locator": {"kind": "json_pointer", "value": pointer},
            },
            value,
        )

    def fragment(self, capture_id: str, fragment: str, claim: str) -> dict[str, Any]:
        """Cite one exact text fragment of a capture, verified present in its bytes."""
        capture, body = self.body(capture_id)
        require(bool(fragment) and fragment.encode() in body, f"text fragment does not resolve in {capture_id}")
        return {
            "captureId": capture_id,
            "digest": capture["digest"],
            "claim": claim,
            "locator": {"kind": "text_fragment", "value": fragment},
        }


class _Classifier:
    """One classification run: the capture, preconditions, records, and policy it reads."""

    def __init__(
        self,
        manifest_path: pathlib.Path,
        preconditions: dict[str, Any],
        events: Iterable[dict[str, Any]],
        maintained_branches: list[str],
    ):
        self.capture = _Capture(manifest_path)
        require(isinstance(preconditions, dict), "preconditions must be an object")
        require(
            bool(COMMIT_SHA_RE.fullmatch(str(preconditions.get("phpBinHead", ""))))
            and bool(COMMIT_SHA_RE.fullmatch(str(preconditions.get("misePhpHead", ""))))
            and bool(SHA256_RE.fullmatch(str(preconditions.get("supportPolicyDigest", "")))),
            "preconditions are not exact commits and a policy digest",
        )
        self.preconditions = {field: preconditions[field] for field in PRECONDITION_FIELDS}
        self.events: dict[str, dict[str, Any]] = {}
        for event in events:
            require(isinstance(event, dict), "event record must be an object")
            key = event.get("actionKey")
            require(isinstance(key, str) and bool(ACTION_KEY_RE.fullmatch(key)), f"event record key is invalid: {key}")
            require(key not in self.events, f"two event records claim {key}")
            self.events[key] = event
        require(
            all(isinstance(branch, str) and _BRANCH_RE.fullmatch(branch) for branch in maintained_branches),
            "maintained branches are invalid",
        )
        self.maintained = sorted(set(maintained_branches), key=version_key)
        self.completed = {key for key, event in self.events.items() if event.get("state") == "complete"}

    # Plan construction ---------------------------------------------------------------

    def plan(
        self,
        *,
        action: str,
        action_key: str,
        evidence: list[dict[str, Any]],
        summary: str,
        edits_required: bool = False,
        allowed_php_bin: list[str] | None = None,
        repositories: list[str] | None = None,
        release_intent: dict[str, str] | None = None,
        risk: str = "routine",
        severity: str = "info",
        human_action_required: bool = False,
    ) -> dict[str, Any]:
        require(bool(ACTION_KEY_RE.fullmatch(action_key)), f"classifier built an invalid action key: {action_key}")
        return {
            "schemaVersion": 1,
            "actionKey": action_key,
            "action": action,
            "evidence": evidence,
            "repositories": repositories or ["php-bin"],
            "preconditions": dict(self.preconditions),
            "editsRequired": edits_required,
            "allowedPaths": {"php-bin": list(allowed_php_bin or []), "mise-php": []},
            "requiredChecks": list(REQUIRED_PLAN_CHECKS),
            "releaseIntent": release_intent,
            "notification": {
                "suggestedSeverity": severity,
                "summary": summary,
                "humanActionRequired": human_action_required,
            },
            "risk": risk,
            "summary": summary,
        }

    def stop(
        self,
        action: str,
        action_key: str,
        evidence: list[dict[str, Any]],
        summary: str,
    ) -> dict[str, Any]:
        """Return an explicit `blocked` or `needs_human` plan that authorizes nothing."""
        return self.plan(
            action=action,
            action_key=action_key,
            evidence=evidence,
            summary=summary,
            risk="recovery",
            severity="warning",
            human_action_required=action == "needs_human",
        )

    def source_format_stop(self, error: SourceFormatError) -> dict[str, Any]:
        capture_id = error.capture_id
        position = self.capture.index.get(capture_id)
        evidence = []
        digest = ""
        if position is not None:
            item, _value = self.capture.pointer(
                "evidence_manifest",
                f"/captures/{position}/captureId",
                f"The {capture_id} capture is healthy but its body has no reviewed shape.",
            )
            evidence.append(item)
            digest = str(self.capture.captures[position].get("digest", ""))
        return self.stop(
            "blocked",
            f"source_unhealthy:{_short_digest([capture_id, digest])}",
            evidence,
            f"The {capture_id} capture could not be read in its reviewed shape ({error.reason}). "
            "Nothing was classified or changed; the reader needs a reviewed update before the "
            "pipeline can continue.",
        )

    # Shared readers ----------------------------------------------------------------

    def published_versions(self) -> set[str]:
        """Return every PHP version with a published release or a completed release record."""
        releases = self.capture.json_body("php_bin_releases")
        if not isinstance(releases, list):
            raise SourceFormatError("php_bin_releases", "body is not a release array")
        published = set()
        for release in releases:
            if not isinstance(release, dict) or release.get("draft") or release.get("prerelease"):
                continue
            tag = PUBLISHED_RELEASE_TAG_RE.fullmatch(str(release.get("tag_name", "")))
            if tag:
                published.add(tag.group(1))
        for key in self.completed:
            family, _, rest = key.partition(":")
            if family in {"new_patch", "recipe_rebuild"}:
                published.add(rest.split(":")[0])
        return published

    def branch_feed_version(self, branch: str) -> str | None:
        """Return the version a maintained branch's own feed names, or None if not captured."""
        capture_id = branch_feed_capture_id(branch)
        if not self.capture.has(capture_id):
            return None
        document = self.capture.json_body(capture_id)
        version = document.get("version") if isinstance(document, dict) else None
        if not isinstance(version, str) or not re.fullmatch(rf"{re.escape(branch)}\.\d+", version):
            raise SourceFormatError(capture_id, f"feed does not name a stable {branch} release")
        return version

    def aggregate_version(self, major: str) -> str | None:
        """Return the newest stable version the aggregate feed names for one major, if any."""
        document = self.capture.json_body("php_release_feed")
        if not isinstance(document, dict):
            raise SourceFormatError("php_release_feed", "body is not an object")
        entry = document.get(major)
        version = entry.get("version") if isinstance(entry, dict) else None
        if isinstance(version, str) and _STABLE_PATCH_RE.fullmatch(version):
            return version
        return None

    def superseded_by(self, version: str) -> str | None:
        """Return a later patch on the same branch that a captured feed names, if any."""
        branch = branch_of(version)
        newer = [
            candidate
            for candidate in (self.branch_feed_version(branch), self.aggregate_version(branch.split(".")[0]))
            if candidate and branch_of(candidate) == branch and version_key(candidate) > version_key(version)
        ]
        return max(newer, key=version_key) if newer else None

    def feed_proof(self, version: str) -> dict[str, Any] | None:
        """Cite the one feed value proving `version`: its own branch feed, else the aggregate."""
        branch = branch_of(version)
        capture_id = branch_feed_capture_id(branch)
        if self.branch_feed_version(branch) == version:
            item, _value = self.capture.pointer(
                capture_id, "/version", f"The official PHP {branch} release feed names {version}."
            )
            return item
        if not self.capture.has(capture_id) and self.aggregate_version(branch.split(".")[0]) == version:
            item, _value = self.capture.pointer(
                "php_release_feed",
                f"/{branch.split('.')[0]}/version",
                f"The official PHP release feed names {version}.",
            )
            return item
        return None

    # Priority rules ----------------------------------------------------------------

    def health(self) -> dict[str, Any] | None:
        decision = self.capture.decision
        if decision.get("trigger") == "health_failed":
            item, _value = self.capture.pointer(
                "watch_decision", "/trigger", "The watcher health check failed."
            )
            return self.stop(
                "blocked",
                f"health_failed:{_short_digest(self.capture.manifest.get('manifestDigest'))}",
                [item],
                "The watcher health check failed, so no captured evidence was classified.",
            )
        unhealthy = [
            (position, capture.get("captureId"))
            for position, capture in enumerate(self.capture.captures)
            if capture.get("status") != 200
        ]
        if not unhealthy:
            return None
        names = sorted(str(capture_id) for _position, capture_id in unhealthy)
        evidence = [
            self.capture.pointer(
                "evidence_manifest",
                f"/captures/{position}/status",
                f"The {capture_id} capture did not return HTTP 200.",
            )[0]
            for position, capture_id in unhealthy
        ]
        return self.stop(
            "blocked",
            f"source_unhealthy:{_short_digest(names)}",
            evidence,
            f"Evidence capture failed for {', '.join(names)}, so nothing was classified or changed. "
            "The next watcher run retries the capture.",
        )

    def incomplete_event(self) -> dict[str, Any] | None:
        pending = self.capture.decision.get("incompleteActions") or []
        require(
            isinstance(pending, list) and pending == sorted(pending),
            "watch decision incomplete actions are not a sorted array",
        )
        if not pending:
            return None
        key = pending[0]
        record = self.events.get(key)
        require(record is not None, f"incomplete action {key} has no event record")
        require(record.get("state") != "complete", f"incomplete action {key} is recorded complete")
        cited, _value = self.capture.pointer(
            "watch_decision", "/incompleteActions/0", f"The {key} event record is incomplete."
        )
        state = record.get("state")
        family, _, rest = key.partition(":")
        if state in {"blocked", "needs_human"}:
            return self.stop(
                "needs_human",
                key,
                [cited],
                f"The {key} event record stopped in state '{state}'. It resumes only after an "
                "operator resolves the recorded cause.",
            )
        if family == "branch_eol":
            branch = rest.split(":")[0]
            return self.plan(
                action="branch_eol",
                action_key=key,
                evidence=[cited],
                repositories=["php-bin", "mise-php"],
                risk="lifecycle",
                summary=f"PHP {branch} support retirement resumes from state '{state}'.",
            )
        if family == "recipe_rebuild":
            if key != self.capture.decision.get("rebuildActionKey"):
                return self.stop(
                    "needs_human",
                    key,
                    [cited],
                    f"The {key} event record is incomplete, but the watcher selected "
                    f"'{self.capture.decision.get('rebuildActionKey') or 'no rebuild'}' as due.",
                )
            return self.recipe_rebuild()
        if family in {"new_patch", "new_branch"}:
            if family == "new_patch":
                version = rest
            else:
                version = self.branch_feed_version(rest) or self.aggregate_version(rest.split(".")[0]) or ""
                if not version or branch_of(version) != rest:
                    return self.stop(
                        "needs_human",
                        key,
                        [cited],
                        f"The {key} event record is incomplete, but no official feed names a PHP {rest} release.",
                    )
            proof = self.feed_proof(version)
            successor = self.superseded_by(version)
            if proof is None or successor:
                reason = f"{successor} supersedes it" if successor else "no official feed proves it"
                return self.stop(
                    "needs_human",
                    key,
                    [cited],
                    f"The {key} event record is incomplete, but PHP {version} cannot be released: {reason}.",
                )
            return self.plan(
                action=family,
                action_key=key,
                evidence=[proof, cited],
                repositories=["php-bin", "mise-php"] if family == "new_branch" else ["php-bin"],
                release_intent={"version": version, "sourceIdentifier": proof["captureId"]},
                risk="lifecycle" if family == "new_branch" else "routine",
                summary=f"The {key} release resumes from state '{state}' for PHP {version}.",
            )
        return self.stop(
            "needs_human",
            key,
            [cited],
            f"The {key} event record is incomplete and no deterministic path resumes it.",
        )

    def lifecycle(self) -> dict[str, Any] | None:
        _capture, body = self.capture.body("php_supported_versions")
        rows = parse_supported_versions(body)
        maintained = set(self.maintained)
        vanished = [branch for branch in self.maintained if branch not in rows]
        misclassified = [
            branch for branch in self.maintained if branch in rows and rows[branch].state == "future"
        ]
        newest = self.maintained[-1] if self.maintained else None
        unmaintained_older = [
            branch
            for branch, row in rows.items()
            if row.state in SUPPORTED_STATES
            and branch not in maintained
            and newest is not None
            and version_key(branch) < version_key(newest)
        ]
        contradictions = sorted(set(vanished + misclassified + unmaintained_older), key=version_key)
        if contradictions:
            item, _value = self.capture.pointer(
                "evidence_manifest",
                f"/captures/{self.capture.index['php_supported_versions']}/digest",
                "The supported-versions capture contradicts the accepted support policy.",
            )
            return self.stop(
                "needs_human",
                f"policy_failure:{_short_digest(['lifecycle', contradictions, item['digest']])}",
                [item],
                "The supported-versions page contradicts the accepted support policy for PHP "
                f"{', '.join(contradictions)}: a maintained branch has no support row, is not yet "
                "released, or an older supported branch is not maintained. The policy needs a "
                "reviewed change.",
            )
        for branch in sorted((set(rows) - maintained), key=version_key):
            row = rows[branch]
            if row.state not in SUPPORTED_STATES:
                continue
            major = branch.split(".")[0]
            version = self.aggregate_version(major)
            if not version or branch_of(version) != branch:
                continue
            proof, _value = self.capture.pointer(
                "php_release_feed",
                f"/{major}/version",
                f"The official PHP release feed names {version}, the first release seen on branch {branch}.",
            )
            listed = self.capture.fragment(
                "php_supported_versions",
                row.fragment,
                f"php.net lists PHP {branch} as a supported branch.",
            )
            return self.plan(
                action="new_branch",
                action_key=f"new_branch:{branch}",
                evidence=[proof, listed],
                edits_required=True,
                allowed_php_bin=[f"expected-modules/{branch}.txt", "support-policy.json"],
                repositories=["php-bin", "mise-php"],
                release_intent={"version": version, "sourceIdentifier": "php_release_feed"},
                risk="lifecycle",
                summary=f"PHP {branch} is a new supported branch, first released as PHP {version}.",
            )
        for branch in self.maintained:
            row = rows[branch]
            if row.state != "eol":
                continue
            ended = row.security_until.isoformat()
            listed = self.capture.fragment(
                "php_supported_versions",
                row.fragment,
                f"php.net lists PHP {branch} as end of life since {ended}.",
            )
            return self.plan(
                action="branch_eol",
                action_key=f"branch_eol:{branch}:{ended}",
                evidence=[listed],
                edits_required=True,
                allowed_php_bin=["support-policy.json"],
                repositories=["php-bin", "mise-php"],
                risk="lifecycle",
                summary=f"PHP {branch} reached end of life on {ended} and leaves the maintained set.",
            )
        return None

    def waiting_lifecycle_record(self) -> bool:
        """Tell whether the only incomplete record is lifecycle work waiting for mise-php.

        A `new_branch` or `branch_eol` record at `php_bin_ready` has merged its php-bin
        change and waits for mise-php to record readiness, which the watcher checks only
        at dispatch time. When it is the only incomplete record nothing is half
        published, so a patch on another branch need not wait behind it.
        """
        pending = self.capture.decision.get("incompleteActions") or []
        return (
            len(pending) == 1
            and pending[0].partition(":")[0] in {"new_branch", "branch_eol"}
            and self.events.get(pending[0], {}).get("state") == "php_bin_ready"
        )

    def resume_incomplete(self) -> dict[str, Any] | None:
        """Resume the first incomplete record, unless it only waits and a patch is due."""
        resumed = self.incomplete_event()
        if resumed is None or resumed["action"] not in {"new_branch", "branch_eol"}:
            return resumed
        if not self.waiting_lifecycle_record():
            return resumed
        try:
            patch = self.new_patch()
        except SourceFormatError:
            # A feed this run cannot read never holds back the waiting record itself.
            return resumed
        # A waiting new branch never ships as a plain patch: having no release yet, it
        # stops as `needs_human` in `new_patch`, and that stop yields to the resume.
        return patch if patch is not None and patch["action"] == "new_patch" else resumed

    def new_patch(self) -> dict[str, Any] | None:
        published = self.published_versions()
        shipped = {branch_of(version) for version in published} | {
            key.partition(":")[2] for key in self.completed if key.startswith("new_branch:")
        }
        for branch in self.maintained:
            version = self.branch_feed_version(branch)
            if version is None and not self.capture.has(branch_feed_capture_id(branch)):
                # Only a capture predating per-branch feeds lacks one; the aggregate
                # feed then still proves the newest release of the newest branch.
                aggregate = self.aggregate_version(branch.split(".")[0])
                version = aggregate if aggregate and branch_of(aggregate) == branch else None
            if version is None or version in published:
                continue
            if branch not in shipped:
                # A branch's first release is a `new_branch`, published only after the
                # exact php_bin_ready and mise_ready records. A maintained branch with no
                # release and no record in flight means that record went missing, so a
                # plain patch would skip the mise-php readiness gate.
                proof = self.feed_proof(version)
                require(proof is not None, f"branch feed version {version} is not provable")
                return self.stop(
                    "needs_human",
                    f"new_branch:{branch}",
                    [proof],
                    f"PHP {branch} is maintained and its feed names {version}, but no {branch} release "
                    f"has shipped and no new_branch:{branch} record is in flight. Its first release "
                    "must pass the cross-repository readiness gate, so an operator needs to restore "
                    "the missing event record.",
                )
            newest_published = max(
                (item for item in published if branch_of(item) == branch), key=version_key, default=None
            )
            if newest_published and version_key(version) <= version_key(newest_published):
                # The feed is behind what already shipped: a stale snapshot, never news.
                continue
            if self.superseded_by(version):
                # Another feed already names a later patch; wait for this branch's own
                # feed to catch up rather than publish an intermediate release.
                continue
            proof = self.feed_proof(version)
            require(proof is not None, f"branch feed version {version} is not provable")
            return self.plan(
                action="new_patch",
                action_key=f"new_patch:{version}",
                evidence=[proof],
                release_intent={"version": version, "sourceIdentifier": proof["captureId"]},
                summary=f"PHP {version} is a new stable patch on maintained branch {branch}.",
            )
        return None

    def recipe_rebuild(self) -> dict[str, Any] | None:
        key = self.capture.decision.get("rebuildActionKey") or ""
        if not key:
            return None
        match = re.fullmatch(r"recipe_rebuild:(\d+\.\d+\.\d+):([1-9]\d*)", key)
        require(bool(match), f"watch decision names an invalid rebuild: {key}")
        version, revision = match.group(1), int(match.group(2))
        superseded = version if revision == 1 else f"{version}-{revision - 1}"
        releases = self.capture.json_body("php_bin_releases")
        positions = [
            position
            for position, release in enumerate(releases if isinstance(releases, list) else [])
            if isinstance(release, dict) and release.get("tag_name") == superseded
        ]
        require(len(positions) == 1, f"rebuild source release {superseded} is not captured exactly once")
        item, _value = self.capture.pointer(
            "php_bin_releases",
            f"/{positions[0]}/tag_name",
            f"The published release {superseded} was built from a different recipe.",
        )
        return self.plan(
            action="recipe_rebuild",
            action_key=key,
            evidence=[item],
            release_intent={"version": f"{version}-{revision}", "sourceIdentifier": "php_bin_releases"},
            summary=f"PHP {version} is rebuilt from the current recipe as revision {version}-{revision}.",
        )

    def no_change(self) -> dict[str, Any]:
        digest = str(self.capture.manifest.get("manifestDigest", ""))
        require(bool(SHA256_RE.fullmatch(digest)), "evidence manifest digest is invalid")
        item, _value = self.capture.pointer(
            "evidence_manifest", "/manifestDigest", "The reviewed evidence snapshot requires no release work."
        )
        return self.plan(
            action="no_change",
            action_key=f"no_change:{digest.removeprefix('sha256:')[:16]}",
            evidence=[item],
            summary="Upstream evidence changed without any release or lifecycle consequence.",
        )

    def classify(self) -> dict[str, Any]:
        for rule in (self.health, self.resume_incomplete, self.new_patch, self.lifecycle, self.recipe_rebuild):
            try:
                plan = rule()
            except SourceFormatError as error:
                return self.source_format_stop(error)
            if plan is not None:
                return plan
        return self.no_change()


def classify_evidence(
    manifest_path: pathlib.Path,
    preconditions: dict[str, Any],
    events: Iterable[dict[str, Any]],
    maintained_branches: list[str],
) -> dict[str, Any]:
    """Classify one retained watcher capture into exactly one autorelease plan.

    `manifest_path` is `autorelease-run/evidence/evidence-manifest.json`; the watch
    decision is read from its fixed runtime location beside it, the same file a plan
    may cite as `watch_decision`. `events` are the durable records under
    `autorelease-events/`, and `maintained_branches` the accepted policy's branches.
    The same inputs always produce the same plan bytes. A malformed input that the
    watcher itself produced (manifest, decision, preconditions, records) raises
    `ControlError` and fails the job; a malformed upstream body becomes a `blocked`
    plan instead.
    """
    return _Classifier(manifest_path, preconditions, events, maintained_branches).classify()
