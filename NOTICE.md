# Notices

Bastion Agent is an independent project and is not an official OpenAI or
Anthropic product. `OpenAI`, `Codex`, `Anthropic`, `Claude`, and `Claude Code`
are trademarks or product names of their respective owners.

The MIT license in this repository applies to the original Bastion Agent
source. Third-party dependencies, generated schemas, and separately downloaded
or bundled runtimes retain their own licenses and notices. Review
`DEPENDENCY_PLAN.md` and the dependency lock files before redistribution.

The latest active runtime restricts local file work to the active installation
directory and project directories explicitly selected by the user. These roots
are resolved dynamically and may be nested or located on different drives.
Hosted model communication and public web search remain available, so this
filesystem boundary is not a complete DLP product. Bastion Agent must not be
used to bypass organizational security policy.
