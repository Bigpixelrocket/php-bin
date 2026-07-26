# Repository settings

Apply these settings after creating the public GitHub repository.

For the `main` branch ruleset:

- Require a pull request before merging.
- Require one approving review and Code Owner review.
- Dismiss stale approvals when new commits are pushed.
- Require the `Script checks` status check.
- Require conversation resolution.
- Block force pushes and branch deletion.

Enable private vulnerability reporting and automatically delete head branches
after pull requests merge. Grant workflow write access only where the release
workflow explicitly requires it.

