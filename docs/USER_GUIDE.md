# AgentSecBench user guide

This guide covers the installable analyzer. Paper-facing reproduction workflows
are documented separately in `SECURITY_ADG_PIPELINE.md`.

## 1. Install

AgentSecBench requires Python 3.11 or newer and has no runtime dependencies.

```bash
python -m pip install https://github.com/A1LinLin1/AgentSecBench/releases/download/v0.2.0/agentsecbench-0.2.0-py3-none-any.whl
agentsecbench doctor
```

`doctor` checks Python and reports optional integrations without running them or
using the network. Git, Docker, Semgrep, CodeQL, and Graphviz are optional; the
core analyzer does not require them.

## 2. Verify the installation

```bash
agentsecbench demo --output agentsecbench-demo
```

The command creates an authored two-operation sample and analyzes it. It does
not download a repository or execute the sample. Open:

```text
agentsecbench-demo/results/report/index.html
```

The demo refuses to overwrite a non-empty directory.

## 3. Analyze a repository

```bash
agentsecbench analyze /path/to/repository --output agentsecbench-results
```

PowerShell:

```powershell
agentsecbench analyze H:\projects\my-agent --output agentsecbench-results
Start-Process agentsecbench-results\report\index.html
```

The analysis is read-only with respect to the target repository. AgentSecBench
does not import target modules, execute source, install project packages, follow
directory symlinks, or contact external services.

### Useful scan options

```text
--include GLOB             analyze only matching paths; repeatable
--exclude GLOB             skip matching paths; repeatable
--max-file-bytes N         skip oversized source files
--granularity line|symbol  emit per line or aggregate within a symbol
--no-interprocedural       disable project-level propagation
--json                     print the run summary as JSON
--fail-on-findings         return 3 when any candidate exists
```

## 4. Output directory

| File | Meaning |
|---|---|
| `findings.jsonl` | One candidate record per line |
| `security-adg.jsonl` | One candidate-centered graph per finding |
| `security-adg-summary.json` | Graph and evidence coverage counts |
| `framework-coverage.json` | Adapter signals, modeled evidence, generic candidate files, and parse failures |
| `validation.json` | Graph/provenance invariant checks |
| `report/index.html` | Self-contained offline review interface |
| `report/manifest.json` | Report identity and integrity metadata |
| `results.sarif` | SARIF 2.1.0 for GitHub and compatible IDEs |
| `summary.json` | Stable run summary and output paths |
| `policy.json` | Policy classification when policy is enabled |
| `policy-summary.md` | Concise CI summary when policy is enabled |

Print bundled JSON Schemas without network access:

```bash
agentsecbench schema --json
agentsecbench schema framework-coverage
agentsecbench schema security-adg
```

## 5. Review the report

Start with candidates that combine:

1. agent-facing or external input evidence;
2. a dependency path;
3. a security-sensitive operation and external effect; and
4. no clearly effective guard.

The report supports operation-only, simplified ADG, and Security-ADG views.
Human dispositions and notes remain in browser local storage. Export review JSON
before changing browser or machine. A disposition is triage metadata, not
vulnerability ground truth.

Suppression drafts are generated only for findings marked `not relevant` and
still require a reviewed owner and rationale.

## 6. Project configuration

Create a safe default configuration:

```bash
agentsecbench init /path/to/repository
```

This writes `.agentsecbench.toml` and refuses to overwrite an existing file
unless `--force` is provided. Configuration controls scan selection,
interprocedural analysis, policy, and custom framework adapters. Unknown keys,
invalid regular expressions, duplicate adapter IDs, and unsupported languages
stop the scan instead of silently lowering coverage.

See `agentsecbench.example.toml` for a complete example.

## 7. Adopt a baseline

First review the initial candidate set, then freeze its stable fingerprints:

```bash
agentsecbench baseline agentsecbench-results/findings.jsonl \
  --output .agentsecbench-baseline.json
```

Configure policy:

```toml
[policy]
baseline = ".agentsecbench-baseline.json"
suppressions = ".agentsecbench-suppressions.toml"
blocking_categories = ["command_execution", "filesystem_write", "dynamic_code_execution"]
minimum_confidence = "high"
```

Then block only new, unsuppressed policy matches:

```bash
agentsecbench analyze . --output agentsecbench-results --fail-on-new
```

Policy changes only the CI decision. It never removes a candidate from JSONL,
graphs, SARIF, or the HTML report.

## 8. Suppressions

Suppressions use exact stable fingerprints, not broad path patterns. Every
record requires an ID, reason, and owner and may carry an expiry date. Expired
suppressions are reported and no longer applied.

```toml
schema_version = "1.0"

[[suppressions]]
id = "reviewed-build-helper"
fingerprint = "ASBFP-REPLACE_WITH_EXACT_FINGERPRINT"
reason = "Reviewed internal build helper with fixed input"
owner = "security-team"
expires = "2027-01-31"
```

See `agentsecbench-suppressions.example.toml` and
`BASELINE_MATCHING_POLICY.md`.

## 9. Exit codes

| Code | Meaning |
|---:|---|
| `0` | Scan completed and the requested policy passed |
| `2` | Invalid input, configuration, output, or analysis failure |
| `3` | `--fail-on-findings` found at least one candidate |
| `4` | `--fail-on-new` found at least one new blocking candidate |

## 10. GitHub Actions

Use `A1LinLin1/AgentSecBench@v0.2.0`, upload the output directory with
`if: always()`, and publish `policy-summary.md` to `$GITHUB_STEP_SUMMARY` when
you want an inline pull-request summary. The complete minimal workflow is in
the repository README.

## Troubleshooting

- **No candidates:** inspect `summary.json`, include/exclude patterns, and the
  framework coverage diagnostic. A clean scan is not proof of absence.
- **Signal-only framework:** inspect the listed signal files and add or improve
  a project adapter if the entrypoint idiom is unsupported.
- **Generic candidate files:** security-sensitive operations were detected, but
  no framework context was attached. The operation finding remains valid as a
  review candidate.
- **Parse failures:** project-level source propagation may be incomplete for the
  listed files; lexical candidate scanning still runs.
- **Large generated trees:** use `agentsecbench init` and add precise exclusions.

## Claim boundary

A finding is not automatically a vulnerability. Confirm input reachability,
trust boundary, guard effectiveness, deployment exposure, privileges, and
impact before making or disclosing a vulnerability claim.
