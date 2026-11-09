"""Behavior of scripts/dispatch-pr-checks against a scripted gh.

The dispatcher is byte-identical in php-bin and mise-php, and so is this test
apart from PRIMARY, the functional check each repository's callers name.
"""

import json
import os
import pathlib
import subprocess
import tempfile
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
DISPATCHER = ROOT / "scripts/dispatch-pr-checks"
PRIMARY = "Script checks"
LINUX = [f"{PRIMARY} on ubuntu-latest", f"{PRIMARY} on ubuntu-24.04-arm"]
REPOSITORY = "Bigpixelrocket/example"
HEAD = "c" * 40

# Answers gh calls from scenario.json and appends each mutation to log.jsonl. The
# check-run listing switches from "before" to "after" once both validators are
# dispatched, and the PR rollup holds exactly the statuses published so far.
FAKE_GH = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
state = pathlib.Path(os.environ["FAKE_GH_DIR"])
scenario = json.loads((state / "scenario.json").read_text())
log_path = state / "log.jsonl"
log = [json.loads(line) for line in log_path.read_text().splitlines()] if log_path.exists() else []
def record(entry):
    with log_path.open("a") as handle:
        handle.write(json.dumps(entry) + "\n")
args = sys.argv[1:]
if args[:2] == ["workflow", "run"]:
    record({"dispatch": args[2]})
elif args[:2] == ["pr", "checks"]:
    rollup = [{"name": e["status"], "bucket": "pass", "link": "gate"} for e in log if "status" in e]
    print(json.dumps(rollup + scenario.get("rollupExtra", [])))
elif args[0] == "api":
    path = next(arg for arg in args if arg.startswith("repos/"))
    if "POST" in args and path.endswith("/check-runs"):
        body = json.loads(pathlib.Path(args[args.index("--input") + 1]).read_text())
        record({"gate": body["name"], "details": body["details_url"], "head": body["head_sha"]})
        print(json.dumps({**body, "id": 9000 + len(log)}))
    elif "POST" in args and "/statuses/" in path:
        fields = dict(args[i + 1].split("=", 1) for i, arg in enumerate(args) if arg == "-f")
        record({"status": fields["context"], "target": fields["target_url"]})
    elif "/pulls/" in path:
        print(json.dumps({"state": "open", "base": {"ref": "main"},
                          "head": {"ref": "autorelease/sync", "sha": "%s",
                                   "repo": {"full_name": "%s"}}}))
    elif "/rules/branches/main" in path:
        if scenario["rules"] == "unavailable":
            sys.exit("HTTP 403: Resource not accessible by integration")
        print(json.dumps(scenario["rules"]))
    elif "/check-runs?" in path:
        dispatched = {e["dispatch"] for e in log if "dispatch" in e}
        phase = "after" if dispatched == {"ci.yml", "protected-controls.yml"} else "before"
        print(json.dumps({"check_runs": scenario[phase]}))
    else:
        sys.exit(f"unexpected gh api {path}")
else:
    sys.exit(f"unexpected gh {args}")
''' % (HEAD, REPOSITORY)


def rules(*contexts):
    """Branch rules as the rules API returns them, requiring each context."""
    return [
        {"type": "deletion"},
        {"type": "required_status_checks", "ruleset_id": 1, "parameters": {
            "strict_required_status_checks_policy": True,
            "required_status_checks": [{"context": c, "integration_id": 15368} for c in contexts],
        }},
    ]


def run(id_, name, conclusion="success", status="completed"):
    return {"id": id_, "name": name, "status": status, "conclusion": conclusion,
            "details_url": f"https://example.invalid/runs/{id_}"}


class DispatchPrChecksTests(unittest.TestCase):
    def dispatch(self, scenario, checks=(PRIMARY,)):
        """Runs the dispatcher; returns (exit code, stderr, output or None, log)."""
        with tempfile.TemporaryDirectory() as temporary:
            work = pathlib.Path(temporary)
            bin_dir = work / "bin"
            bin_dir.mkdir()
            (bin_dir / "gh").write_text(FAKE_GH)
            (bin_dir / "sleep").write_text("#!/bin/sh\nexit 0\n")
            for tool in ("gh", "sleep"):
                (bin_dir / tool).chmod(0o755)
            (work / "scenario.json").write_text(json.dumps(scenario))
            output = work / "out/checks.json"
            arguments = [str(DISPATCHER), "--pr", "7", "--output", str(output)]
            for check in checks:
                arguments += ["--check", check]
            env = {**os.environ, "PATH": f"{bin_dir}:{os.environ['PATH']}", "FAKE_GH_DIR": str(work),
                   "GITHUB_REPOSITORY": REPOSITORY, "DISPATCH_PR_CHECKS_TIMEOUT": "2"}
            result = subprocess.run(arguments, env=env, capture_output=True, text=True, timeout=60)
            log_path = work / "log.jsonl"
            log = [json.loads(line) for line in log_path.read_text().splitlines()] if log_path.exists() else []
            published = json.loads(output.read_text()) if output.exists() else None
        return result.returncode, result.stderr, published, log

    def test_waits_for_and_publishes_every_check_the_rules_require(self):
        required = [PRIMARY, *LINUX, "Protected controls"]
        stale = [run(index + 1, name) for index, name in enumerate(required)]
        fresh = [run(index + 101, name) for index, name in enumerate(required)]
        code, stderr, published, log = self.dispatch(
            {"rules": rules(*required), "before": stale, "after": stale + fresh})
        self.assertEqual(0, code, stderr)
        self.assertEqual(sorted(required), [entry["name"] for entry in published])
        self.assertTrue(all(entry["bucket"] == "pass" and entry["headSha"] == HEAD for entry in published))
        # Each gate and status carries the new run's URL, never an earlier run's.
        fresh_urls = {run["name"]: run["details_url"] for run in fresh}
        gates = {entry["gate"]: entry["details"] for entry in log if "gate" in entry}
        statuses = {entry["status"]: entry["target"] for entry in log if "status" in entry}
        self.assertEqual(fresh_urls, gates)
        self.assertEqual(fresh_urls, statuses)
        self.assertEqual([{"dispatch": "ci.yml"}, {"dispatch": "protected-controls.yml"}], log[:2])

    def test_a_failed_required_check_stops_before_anything_is_published(self):
        required = [PRIMARY, *LINUX, "Protected controls"]
        fresh = [run(index + 101, name) for index, name in enumerate(required)]
        fresh[2] = run(103, LINUX[1], conclusion="failure")
        code, stderr, published, log = self.dispatch({"rules": rules(*required), "before": [], "after": fresh})
        self.assertEqual(1, code)
        self.assertIn(f"{LINUX[1]}: https://example.invalid/runs/103", stderr)
        self.assertIsNone(published)
        self.assertFalse([entry for entry in log if "gate" in entry or "status" in entry])

    def test_a_required_check_that_never_runs_again_times_out(self):
        required = [PRIMARY, *LINUX, "Protected controls"]
        # The arm check passed before the dispatch, but only a new run counts.
        stale = [run(1, LINUX[1])]
        fresh = [run(index + 101, name) for index, name in enumerate(required) if name != LINUX[1]]
        code, stderr, published, log = self.dispatch(
            {"rules": rules(*required), "before": stale, "after": stale + fresh})
        self.assertEqual(1, code)
        self.assertIn("Timed out", stderr)
        self.assertIn(f"Missing or unfinished: {LINUX[1]}", stderr)
        self.assertIsNone(published)
        self.assertFalse([entry for entry in log if "gate" in entry or "status" in entry])

    def test_a_caller_check_stays_required_when_the_rules_omit_it(self):
        fresh = [run(101, "Protected controls")]
        code, stderr, published, _ = self.dispatch(
            {"rules": rules("Protected controls"), "before": [], "after": fresh})
        self.assertEqual(1, code)
        self.assertIn(f"Missing or unfinished: {PRIMARY}", stderr)
        self.assertIsNone(published)

    def test_unreadable_branch_rules_stop_before_any_dispatch(self):
        for broken in ("unavailable", {"message": "Not Found"}, rules("")):
            with self.subTest(rules=broken):
                code, _, published, log = self.dispatch({"rules": broken, "before": [], "after": []})
                self.assertNotEqual(0, code)
                self.assertIsNone(published)
                self.assertEqual([], log)

    def test_a_rollup_that_never_shows_every_required_check_passing_fails(self):
        required = [PRIMARY, "Protected controls"]
        fresh = [run(index + 101, name) for index, name in enumerate(required)]
        code, stderr, published, _ = self.dispatch({
            "rules": rules(*required), "before": [], "after": fresh,
            "rollupExtra": [{"name": "Another required check", "bucket": "fail", "link": "x"}],
        })
        self.assertEqual(1, code)
        self.assertIn("does not show every required check as passing", stderr)
        self.assertIsNone(published)

    def test_usage_requires_a_pull_request_a_check_and_an_output(self):
        for arguments in ([], ["--pr", "7", "--output", "x"], ["--pr", "0", "--check", PRIMARY, "--output", "x"],
                          ["--pr", "7", "--check", "", "--output", "x"]):
            with self.subTest(arguments=arguments):
                result = subprocess.run([str(DISPATCHER), *arguments], capture_output=True, text=True,
                                        env={**os.environ, "GITHUB_REPOSITORY": REPOSITORY})
                self.assertEqual(2, result.returncode)


if __name__ == "__main__":
    unittest.main()
