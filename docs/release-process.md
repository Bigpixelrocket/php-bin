# Release process

1. Update `expected-modules/<minor>.txt` only from a reviewed module baseline.
2. Update the recipe and run the exact module comparison on macOS arm64.
3. Confirm `scripts/test.sh` and public-language checks pass.
4. Open a pull request with the build log and module diff.
5. After approval and merge, create and push a version tag such as `8.4.5`.
   Use `8.4.5-1` for a recipe-only rebuild of the same PHP patch.
6. The release workflow rebuilds from the tag, verifies modules, packages the
   archive, writes `SHA256SUMS`, and creates the GitHub Release.
7. Verify the release asset names and run an installation through `mise-php`
   before announcing the release.

Never upload a locally built replacement over an existing release asset. A
changed recipe or artifact requires a new rebuild revision.

