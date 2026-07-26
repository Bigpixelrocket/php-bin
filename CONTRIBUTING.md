# Contributing

Changes are welcome through pull requests.

## Build changes

1. Open an issue describing recipe, dependency, or release-contract changes.
2. Keep the pinned StaticPHP version and checksum together.
3. Run `scripts/test.sh` and `scripts/check-public-language.sh`.
4. For extension changes, run the earliest affected spike stage on an Apple
   Silicon Mac and attach the module diff to the pull request.
5. Do not remove a required module to make a build green. Document the blocker
   and request a maintainer decision.

Pull requests require passing CI and one approving owner review. Direct pushes
to `main` are not part of the project workflow.

