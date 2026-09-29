# AgentSecBench engineering roadmap

This roadmap separates the installable security-analysis product from the
paper-reproduction workflow. Product users should be able to analyze one local
repository without downloading the research corpus or understanding the paper.

## Product contract

AgentSecBench performs read-only static analysis. It does not import or execute
target code, install target dependencies, or access the network. Results are
security-review candidates with source provenance; they are not automatic
vulnerability claims.

The supported first-run path is:

```text
install -> doctor -> demo -> init -> analyze -> inspect HTML/SARIF -> triage
```

## P0: usable public preview

- [x] Installable Python package and stable `agentsecbench` entry point.
- [x] Local repository analysis without a corpus manifest.
- [x] `doctor` environment diagnostics.
- [x] Safe `init` command with validated project configuration.
- [x] JSONL, Security-ADG, SARIF, validation, and summary outputs.
- [x] Responsive offline review dashboard with evidence coverage, graph views,
  source context, embedded CI policy status, browser-local dispositions, audit
  export, and guarded exact-fingerprint suppression drafts.
- [x] Built-in and project-defined framework adapters.
- [x] Python and JavaScript/TypeScript project-level call propagation.
- [x] Deterministic tests, wheel build, and CI artifact generation.
- [x] Public release workflow with versioned GitHub releases and checksums.
- [x] End-user documentation for installation, configuration, CI, and result
  interpretation.
- [x] A self-contained, offline first-run demo that generates a complete report.

## P1: practical team workflow

- [x] Baseline files so teams can distinguish existing findings from new findings.
- [x] Auditable suppression syntax with reason, owner, and optional expiry.
- [x] Policy configuration by category, confidence, and new/existing status.
- [x] Stable CI exit codes and a concise pull-request summary.
- Path-scoped policy for monorepos without permitting broad silent suppression.
- SARIF fingerprints that remain stable across unrelated source movement.
- Framework coverage diagnostics explaining which adapters matched and which
  files could not be modeled.
- [x] A machine-readable output schema and compatibility policy.

## P2: scale and extensibility

- Incremental analysis and content-addressed caching.
- Parallel parsing with deterministic output ordering.
- Additional language front ends behind a shared intermediate representation.
- Adapter conformance fixtures for newly released agent frameworks.
- Plugin discovery with explicit trust and version boundaries.
- Repository-level performance budgets and regression dashboards.

## P3: security-product maturity

- Threat model and secure-development policy for the analyzer itself.
- Signed releases and a software bill of materials.
- [x] A documented vulnerability-reporting process.
- [x] False-positive/false-negative issue templates with minimal reproducible
  examples.
- Compatibility testing across supported Python versions and operating systems.

## Next implementation milestone

The next product milestone is path-scoped monorepo policy and framework coverage
diagnostics. The initial public release now includes versioned schemas, a
reusable GitHub Action, baselines, exact-fingerprint suppressions,
category/confidence policy, and Markdown CI summaries.
