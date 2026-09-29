# Changelog

AgentSecBench follows semantic versioning for the installable CLI and its
documented output contracts.

## 0.2.0 - 2026-09-30

- Add framework coverage diagnostics with modeled, signal-only, not-observed,
  generic-candidate, fallback, and parse-failure evidence.
- Embed framework coverage in the offline report and publish its versioned JSON
  Schema.
- Redesign the repository README around the product value, visual workflow,
  quick start, and CI adoption path.
- Move detailed operation and adapter guidance into focused documentation.

## 0.1.1 - 2026-09-30

- Add `agentsecbench demo`, a network-free authored example that produces a
  complete offline report without executing analyzed code.
- Test the first-use path in GitHub Actions.
- Point the quick start at the versioned release wheel.

## 0.1.0 - 2026-09-29

- Initial public preview with local repository analysis, Security-ADG JSONL,
  SARIF, an offline review dashboard, CI policy, baselines, suppressions,
  output schemas, and a reusable GitHub Action.
