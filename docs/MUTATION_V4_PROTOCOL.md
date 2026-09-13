# AgentSecBench-Mutate v4 protocol

## Purpose

v4 is a post-freeze, controlled semantic-confounder evaluation for the frozen
Security-ADG v2.4 engine. It asks whether the method distinguishes a local
input-to-security-effect dependency from a nearby but non-dependent
security-sensitive operation.

## Source selection

- Select 10 Python repositories deterministically from the frozen corpus.
- Exclude all pilot repositories and all source repositories used by mutation
  suites v1, v2, and v3.
- Exclude `ASB0024`, whose tracked Windows-incompatible path prevents a
  portable `git archive` operation.
- Record the selection seed, source commits, and derived commits in the v4
  catalog and manifest.

The corpus has only seven TypeScript repositories; three are pilot repositories
and the other four were consumed by v1. Therefore v4 makes **no** claim of a
new independent TypeScript real-repository sample. TypeScript remains covered
by the separately reported v1 controlled evaluation and the hand-authored
microbenchmark.

## Fixed mutations per repository

Each source receives eight fresh Python files: four positives and four
negatives. Every file contains a scanner-detectable command-execution operation.

| Group | Cases | Oracle |
|---|---:|---|
| Tool/argv, mapping transform, environment source | 3 | dependency present with the declared source type |
| Guarded command | 1 | dependency present and a `dominating_if` guard candidate |
| Constant overwrite, dead input, literal argv, discarded source | 4 | no input-to-effect dependency |

## Freeze and scoring rule

The v2.4 analysis engine is frozen before v4 is built. No analysis-engine,
scanner, taxonomy, or oracle change is permitted after v4 results are observed.
The primary endpoint is dependency precision, recall, and F1; secondary
endpoints are source-type relation F1, guard-kind relation F1, exact oracle
matches, and per-repository variance. This controlled oracle assesses local
semantic recovery only; it is not a real-world vulnerability prevalence claim.
