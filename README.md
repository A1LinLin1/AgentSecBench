# AgentSecBench

AgentSecBench is a research artifact for studying security-sensitive behavior
in real-world LLM-agent systems. It combines a frozen benchmark design with
Security-Aware Agent Dependency Graphs (Security-ADGs): candidate-level evidence
graphs that preserve operations, external effects, dependency paths,
trust-boundary evidence, and guard context.

The project is designed around one claim boundary:

```text
security-sensitive behavior discovery != vulnerability counting
```

Static candidates are review targets, not vulnerability claims. Vulnerability
claims require additional impact and trust/authentication-boundary evidence.

## Current public artifact snapshot

The public repository contains the method implementation, deterministic
fixtures, CI checks, paper-facing protocols, and reproducibility scripts. The
current research snapshot is:

| Item | Value |
|---|---:|
| Frozen corpus used by the study | 67 repositories |
| Agent ecosystems | 11 |
| Source files | 37,542 |
| Source size | 291 MB |
| Static candidate pool | 531 candidates |
| Reproduction-confirmed behavior GT | 22 cases |
| Vulnerability GT | 1 case |
| Pending disclosure / upgrade candidate | 1 case |
| Guarded not-vulnerability / negative-control cases | 20 cases |

Important: the full frozen corpus, local analysis outputs, disclosure material,
credentials, raw annotations, and model-panel outputs are intentionally not
included in this public code release.

## What is in this repository

- Static candidate extraction and baseline matching policy.
- Security-ADG construction, framework-adaptive normalization, and local
  dependency/guard evidence extraction.
- Deterministic CI fixtures and unit tests.
- A standalone Security-ADG showcase / figure renderer.
- Reproduction-ground-truth builders and vulnerability-disposition tooling.
- Mutation and microbenchmark evaluation protocols.
- Public method and experiment documentation.

## What is intentionally not included

This repository does not publish:

- private API keys or `.secrets`;
- downloaded third-party repository snapshots under `dataset/repos`;
- private vulnerability-disclosure reports;
- raw participant annotation submissions;
- raw model-panel outputs;
- local runtime artifacts or full analysis outputs.

If you reproduce the full study locally, keep those materials outside public
commits unless they have been explicitly reviewed for release.

## Claim boundaries

Use these boundaries when citing or extending this artifact:

- `531` static candidates are not `531` vulnerabilities.
- Reproduction-confirmed behavior GT is not automatically vulnerability GT.
- Vulnerability GT is not an assigned CVE unless a CNA or maintainer advisory
  assigns one.
- Guarded not-vulnerability cases are not failures; they are negative-control
  and semantic-disambiguation evidence.
- The committed fixtures support deterministic artifact checks, not
  population-level precision/recall/F1 claims.

## Quick start

Run the deterministic CI-equivalent tests:

```powershell
python -m unittest `
  tests.test_security_adg_dataflow `
  tests.test_security_adg_showcase `
  tests.test_heldout_reproduction_case_matrix `
  tests.test_guard_ablation_table `
  tests.test_paper_results_snapshot `
  tests.test_export_paper_tables
```

Build the portable interactive evidence view from the committed fixture:

```powershell
python scripts\generate_security_adg_showcase.py `
  --graphs tests\fixtures\security_adg_showcase.jsonl `
  --output-dir artifacts\security-adg-showcase `
  --max-graphs 2
```

Open:

```text
artifacts/security-adg-showcase/index.html
```

The page lets you compare a sink-only view, a simplified ADG projection, and
the full Security-ADG evidence view for the same candidate.

## Reproducing paper-facing artifacts

The following commands rebuild the public, deterministic paper-facing artifact
pipeline from local evidence files and committed fixtures:

```powershell
python scripts\build_reproduction_ground_truth.py
python scripts\build_vulnerability_gt_upgrade_queue.py
python scripts\build_vulnerability_gt_disposition_matrix.py
python scripts\evaluate_reproduction_gt_coverage.py
python scripts\build_paper_results_snapshot.py
python scripts\export_paper_tables.py
```

Main generated outputs:

```text
analysis/ground_truth/reproduction_confirmed_gt.jsonl
analysis/ground_truth/reproduction_confirmed_gt_summary.json
analysis/ground_truth/vulnerability_gt_upgrade_queue.jsonl
analysis/ground_truth/disposition/vulnerability_gt_disposition_matrix.md
analysis/paper_results/README.md
analysis/paper_results/tables/
```

Depending on your local `.gitignore` policy, these generated outputs may remain
local and untracked.

## Full corpus pipeline

If you have prepared your own frozen corpus manifest, the Security-ADG pipeline
can run static scanning, graph generation, validation, review-queue generation,
and showcase generation:

```powershell
python scripts\run_security_adg_pipeline.py `
  --manifest dataset\corpus_manifest.csv `
  --scope all_corpus `
  --analysis-mode v2_5 `
  --skip-sample-id ASB0024 `
  --output-root artifacts\security_adg\all_corpus_v2_5
```

See [docs/SECURITY_ADG_PIPELINE.md](docs/SECURITY_ADG_PIPELINE.md) for the
artifact layout and CI behavior.

## Method overview

Security-ADG represents each candidate as a typed evidence graph:

```text
G_c = (V, E, A)
```

where `V` contains typed nodes, `E` contains typed evidence edges, and `A`
contains provenance and analysis metadata.

Core node types:

- `agent_or_program_symbol`
- `security_sensitive_operation`
- `external_effect`
- `input_source`
- `trust_boundary`
- `guard_candidate`

Core edge types:

- `contains`
- `may_cause`
- `may_data_depend_on`
- `may_cross`
- `may_guard`

The framework-adaptive normalization layer currently recognizes MCP/FastMCP,
LangChain, CrewAI, AutoGen, OpenAI Agents SDK, Semantic Kernel, and LlamaIndex
tool idioms.

See [docs/METHOD_SECTION_DRAFT.md](docs/METHOD_SECTION_DRAFT.md) and
[docs/PAPER_RQ_EXPERIMENT_MAPPING.md](docs/PAPER_RQ_EXPERIMENT_MAPPING.md) for
the paper-facing method and experiment design.

## Repository layout

```text
.github/workflows/              CI checks and artifact uploads
annotations/                    UI source and public annotation protocols
baselines/                      predefined baseline rules
benchmarks/security_adg_micro/   microbenchmark cases
docs/                           public method and experiment documentation
experiments/                    method configurations and visualization templates
scripts/                        analysis, graph, GT, baseline, and artifact tooling
tests/                          unit tests and deterministic fixtures
tools/                          toolchain metadata
```

## Useful documents

- [docs/METHOD_SECTION_DRAFT.md](docs/METHOD_SECTION_DRAFT.md)
- [docs/PAPER_RQ_EXPERIMENT_MAPPING.md](docs/PAPER_RQ_EXPERIMENT_MAPPING.md)
- [docs/REPRODUCTION_GROUND_TRUTH_PROTOCOL.md](docs/REPRODUCTION_GROUND_TRUTH_PROTOCOL.md)
- [docs/PAPER_GROUND_TRUTH_CONSTRUCTION_SECTION.md](docs/PAPER_GROUND_TRUTH_CONSTRUCTION_SECTION.md)
- [docs/BASELINE_MATCHING_POLICY.md](docs/BASELINE_MATCHING_POLICY.md)
- [docs/SECURITY_ADG_PIPELINE.md](docs/SECURITY_ADG_PIPELINE.md)
- [docs/MUTATION_V4_PROTOCOL.md](docs/MUTATION_V4_PROTOCOL.md)

## Status

This is an active research artifact. Interfaces and experiment protocols may
evolve while the benchmark and paper are being finalized. Public claims should
follow the claim boundaries above.
