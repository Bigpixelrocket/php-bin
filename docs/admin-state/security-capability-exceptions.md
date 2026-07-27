# Administrator-state capability exceptions

Captured: 2026-07-27

Review by: 2026-10-27

The repository settings installer requests secret-scanning validity checks and
non-provider pattern scanning. GitHub retained both controls as disabled in the
Bigpixelrocket organization on 2026-07-27. GitHub documents these controls as
requiring GitHub Team or Enterprise with GitHub Secret Protection enabled.

This is a platform/plan limitation, not an accepted permanent security posture.
Re-test no later than 2026-10-27, or immediately after GitHub Secret Protection
is enabled for the organization. Dependabot security updates, provider-pattern
secret scanning, and secret-scanning push protection remain mandatory and the
installer fails if GitHub does not enable them.

References:

- https://docs.github.com/en/code-security/secret-scanning/using-advanced-secret-scanning-and-push-protection-features/non-provider-patterns/enabling-secret-scanning-for-non-provider-patterns
- https://docs.github.com/en/enterprise-cloud@latest/code-security/how-tos/secure-your-secrets/customize-leak-detection/enabling-validity-checks-for-your-repository
