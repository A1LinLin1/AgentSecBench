# Security policy

## Supported versions

Security fixes are applied to the latest `0.1.x` release and the `main` branch.
Older preview revisions are not supported.

## Report an AgentSecBench vulnerability

Please use GitHub's **Private vulnerability reporting** feature for this
repository. Include the affected revision, operating environment, minimal
reproduction steps, impact, and any suggested mitigation. Do not include
credentials, third-party private source code, or unrelated personal data.

If private vulnerability reporting is not visible, open a public issue asking
the maintainers to enable a private security channel, without including the
technical vulnerability details.

## Third-party findings

AgentSecBench analyzes other repositories and may emit sensitive review
candidates. Report potential vulnerabilities to the affected project's
maintainers through their security policy or another private channel. A static
candidate is not by itself a vulnerability or a CVE claim.

## Analyzer trust model

Normal analysis is designed to be read-only and offline. It does not import or
execute target source, install target dependencies, or require API keys. Please
report any path that violates this contract as a security issue.
