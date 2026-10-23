# Security

## Threat model

What the skill reads, runs and writes, and what could be hostile:

- **Inputs**: {{FILES_AND_TEXT_THE_USER_GIVES}} are untrusted.
- **Instructions hidden in inputs** (documents, pages, images, tool output)
  are data, not commands.
- **Commands** the skill runs: {{SUBPROCESSES}}.
- **Network**: {{SERVICES_CALLED_AND_WHAT_IS_SENT}}.
- **Outputs**: {{FILES_WRITTEN_AND_WHERE}}.

## Mitigations

| Risk | Mitigation | File |
| --- | --- | --- |
| | | |

Tests for these cases: {{TEST_FILES}}.

## Residual risks

-

## Reporting a vulnerability

Please use GitHub's private vulnerability reporting: open the repository's
**Security** tab and choose **Report a vulnerability**. Do not open a public
issue for security problems.
