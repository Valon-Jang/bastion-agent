# Security Policy

## Supported status

The first public source snapshot is a release candidate intended for review and
controlled testing. It is not a signed production release.

## Reporting a vulnerability

Do not include credentials, private source code, internal paths, personal data,
or exploit details in a public issue. Use GitHub private vulnerability reporting
when it is available for this repository.

## Runtime boundary

The latest active runtime and the next portable installer resolve two allowed
filesystem boundaries at startup:

1. the active Bastion Agent installation directory; and
2. the project directories explicitly selected by the user.

Local tools and their child work are restricted to those canonical roots.
Install and project roots may be nested or located on different drives; no
drive letter or drive-root location is hardcoded. Paths outside the resolved
roots are denied. Runtime state, skills, snapshots, temporary work, and staged
self-repair updates stay beneath the installation root.

This filesystem boundary is designed to coexist with managed Windows sessions
where a separate sandbox-user logon is unavailable. It does not bypass
SmartScreen, AppLocker, WDAC, EDR, network controls, or organizational policy.

Hosted Codex communication and public web search remain intentionally enabled.
Content placed in a selected project or prompt may therefore be transmitted to
the configured Codex service when needed for the requested work. Bastion Agent
is not a complete DLP product; use only an organization-approved account,
workspace, data set, and deployment policy.
