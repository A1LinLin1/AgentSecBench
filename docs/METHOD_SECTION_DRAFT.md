# Method Section Draft

> Draft status: method-section writing material. This document describes the
> research method and experimental protocol. It should not be read as final
> evaluation results, vulnerability claims, or CVE evidence.

## 1. Overview

AgentSecBench studies security-critical behavior discovery in real-world
LLM-agent systems. The core observation is that security relevance in agent
software is rarely captured by a sink API alone. A call to `subprocess.run`,
`fetch`, `fs.writeFile`, a browser-control primitive, or a file operation may be
benign internal plumbing, an intended local tool capability, a guarded
operation, or a security-sensitive behavior reachable from an agent-facing
entrypoint. Conversely, many agent-specific effects are missed by narrow
predefined sink lists because the effect is expressed through framework
abstractions, tool registries, agent adapters, or semantic capability names.

Our method therefore separates four concepts:

1. **Operation:** a source-code location that performs or prepares a
   security-sensitive effect.
2. **Source/dependency evidence:** local evidence that a less-trusted source,
   such as an agent tool parameter, request field, model output, repository
   argument, or external package content, can influence the operation.
3. **Trust-boundary evidence:** evidence that the value crosses from an
   external, agent-facing, or less-trusted context into a local effect.
4. **Guard evidence:** validation, escaping, allowlisting, fixed-argv
   construction, size limits, path restrictions, authentication checks, or
   other constraints that affect interpretation.

The output of the method is a Security-Aware Agent Dependency Graph
(Security-ADG). A Security-ADG is an evidence representation, not an automatic
vulnerability verdict.

## 2. Corpus Construction

AgentSecBench is built from real GitHub repositories that implement or support
LLM-agent behavior. The current frozen corpus contains 67 repositories spanning
11 agent ecosystems, 37,542 source files, 291 MB of source code, and 67 recorded
commits. Each corpus entry records repository identity, ecosystem metadata,
frozen commit, source-language summary, source-file count, source-byte count,
and worktree validity.

The corpus is frozen at commit granularity. All experiments refer to the
recorded commit rather than the moving upstream default branch. This matters
because agent projects change quickly: tools are renamed, APIs are refactored,
repositories disappear, and security-relevant defaults can change without
warning. A frozen manifest makes each result reproducible and makes later
publication possible without relying on live upstream state.

Before using the corpus for analysis, we run a snapshot audit that checks:

- every manifest row has a unique sample ID;
- every repository and frozen commit is unique;
- each local worktree points to the expected commit;
- the worktree is clean or the exception is explicitly disclosed; and
- publication gates are blocked if snapshot exceptions are unresolved.

The pilot methodology uses repository-level split isolation. Development
repositories are used for method design and debugging. Held-out repositories
are reserved for one-time frozen evaluation or local reproduction evidence.
Rules, prompts, thresholds, taxonomy, and Security-ADG logic must not be tuned
using held-out labels.

## 3. Static Candidate Extraction

The first stage extracts candidate security-sensitive operations from frozen
source files. This stage is intentionally broad: it creates a candidate
population, not a vulnerability list.

The extractor scans supported source files for operation families such as:

- command execution and process creation;
- dynamic code execution;
- filesystem read, write, and delete operations;
- browser and desktop automation;
- network and remote-service access;
- credential or secret access;
- database access;
- external tool invocation; and
- permission or authorization changes.

Each candidate records repository provenance, frozen commit, file path, line
location, operation category, detector identity, confidence tier, and local code
context. These records are useful as a review frame, but they are insufficient
for security interpretation because a sink match alone does not answer whether
the operation is agent-relevant, source-dependent, guarded, or exploitable.

This distinction is central to the paper: the 531 pilot candidates are
automatically detected candidates, not 531 vulnerabilities.

## 4. Security-ADG Representation

Security-ADG augments each candidate operation with security-specific evidence.
For each candidate, the graph may include:

- an `agent_or_program_symbol` node for the containing tool, handler, adapter,
  function, or program symbol;
- a `security_sensitive_operation` node for the operation itself;
- an `external_effect` node describing the effect class, such as local process,
  filesystem mutation, remote service access, browser control, or system state;
- `input_source` nodes for values that may originate outside the local trusted
  computation;
- `trust_boundary` nodes for external-to-local or less-trusted-to-privileged
  transitions;
- `guard_candidate` nodes for validation, escaping, allowlisting,
  fixed-command construction, size limits, path normalization, authentication,
  or other defensive context; and
- typed edges such as `contains`, `may_cause`, `may_data_depend_on`,
  `may_cross`, and `may_guard`.

The same candidate can be projected into three views:

1. **Sink-only view:** shows only that a sensitive operation exists.
2. **Simplified ADG view:** shows program structure and possible external
   effect.
3. **Security-ADG view:** shows operation, effect, source/dependency evidence,
   trust boundary, and guard context.

The simplified ADG view is a local projection used for ablation; it is not an
implementation of the AgentFlow baseline.

## 5. Semantic Dependency Analysis

Security-ADG uses local, label-independent dependency analysis. The current
implementation combines Python AST analysis with lexical TypeScript/JavaScript
backward slicing. The purpose is not to perform full interprocedural program
verification. Instead, the method tries to preserve enough local evidence to
support review of agent security behavior.

For Python, the analyzer uses AST structure to identify function boundaries,
parameters, assignments, calls, decorators, and selected dataflow-like
relationships. Tool-entrypoint decorators are treated as important semantic
signals: parameters of functions decorated as agent tools can become
`agent_tool_parameter` sources when they are consumed by a security-sensitive
operation inside the same tool body.

For TypeScript/JavaScript, the analyzer uses lexical slicing and syntax-aware
patterns to connect local symbols, operation calls, framework adapters, and
guard candidates. TypeScript evidence explicitly records limitations: lexical
slices do not prove full control-flow dominance, alias soundness, or
interprocedural completeness.

The dependency layer is designed to answer a narrower question than
vulnerability analysis:

> Is there local evidence that a less-trusted or agent-facing value may reach a
> security-sensitive operation?

This makes the method more informative than sink matching while keeping its
claim boundary honest.

## 6. Guard-aware Interpretation

A key design goal is to avoid flattening all sensitive operations into the same
risk bucket. Guard evidence is therefore represented explicitly rather than
discarded.

Examples of guard evidence include:

- escaping before insertion into shell, XML, SQL, or template contexts;
- use of argv-list process invocation rather than shell-string execution;
- fixed executable names and fixed argument structure;
- allowlists or schema validation;
- path traversal and absolute-path rejection;
- symlink and hardlink rejection;
- compressed and decompressed size caps;
- authentication or bind-address checks; and
- staged writes, atomic rename, and rollback.

Guard evidence changes interpretation but does not automatically make an
operation safe. A guard node means the analysis found relevant defensive context;
it does not prove the guard is complete, correctly placed, or sufficient against
all attacks.

This distinction lets Security-ADG support three review outcomes:

- confirmed sensitive behavior with no guard evidence found;
- confirmed sensitive behavior with guard context preserved; and
- downgraded behavior where the operation is sensitive but the construction
  reduces or changes the security concern.

## 7. Baselines and Normalization

We compare Security-ADG against predefined-sink baselines under a fixed matching
policy.

The sink-only comparator treats each matched static operation as positive. It
does not claim dependency evidence and cannot distinguish guarded from
unguarded behavior.

Semgrep uses a fixed predefined-sink rule set. Its role is to represent a
lightweight static scanner based on known API patterns. Semgrep results are
normalized to candidate or inventory records through repository-relative file
paths, line overlap, and category compatibility.

CodeQL uses pinned language suites, primarily security-and-quality rules for
Python and JavaScript/TypeScript. CodeQL `path-problem` results with explicit
code-flow evidence can support dependency-style baseline predictions when they
match the frozen inventory under the predefined matching policy. Unsupported or
ambiguous mappings are recorded rather than manually assigned.

All baseline normalization is fixed before reading held-out gold labels. No
manual per-item matching or label-aware tolerance adjustment is allowed.

## 8. Evaluation Protocol

The evaluation protocol separates development evidence, model-assisted
diagnostics, independent labels, held-out predictions, and local reproduction
evidence.

### 8.1 Candidate-level annotation

The pilot candidate study samples 150 tasks from 531 candidates using
deterministic stratification. The intended primary human labels are:

- behavior-positive: `behavior_confirmed=true` and `agent_relevant=true`;
- strict dependency-positive: `dependency_confirmed=true`;
- inclusive dependency-positive: `dependency_confirmed` is `true` or
  `partial`.

Uncertain and unknown values are excluded from field-specific complete-case
primary analysis and counted separately. Weakness and vulnerability fields are
secondary because they require deployment and threat-model context.

### 8.2 Model panel

A five-model panel can be used for scalable pre-annotation, disagreement
analysis, and prioritization. It is not human ground truth. Model votes,
model rationales, reviewer03 output, Security-ADG predictions, and baseline
outputs must not be shown to blinded annotators.

### 8.3 Held-out operation inventory

The held-out recall protocol uses an independently frozen operation inventory.
Predictions from Security-ADG, sink-only, Semgrep, and CodeQL are joined to this
inventory only through the fixed matching policy. Final recall and F1 require
independent review and adjudication of the inventory labels.

### 8.4 Local reproduction evidence

Local reproduction evidence is used for qualitative case studies and sanity
checks. A reproduction-confirmed record means that the recorded local or
source-level procedure confirmed a security-sensitive behavior path. It does
not establish prevalence, exploitability, deployment exposure, or affected
version range.

Recent local/source evidence is summarized into:

- a held-out reproduction case matrix;
- a guard-aware representation ablation;
- a paper results snapshot; and
- CSV/LaTeX paper table exports.

These artifacts help write RQ3 and RQ4 but are not final accuracy metrics.

## 9. Leakage Prevention

The main leakage risks are method tuning on held-out labels, model-assisted
labels being mistaken for human gold, and local reproduction evidence being
treated as population-level evaluation.

The protocol prevents these risks through:

- repository-level development/held-out separation;
- frozen commits and frozen method artifacts;
- blind annotation interfaces that hide model and method outputs;
- explicit distinction between model panel, reviewer03 audit, and independent
  human labels;
- fixed candidate-to-baseline matching before gold labels are read;
- validation gates that report missing labels rather than silently filling them;
  and
- claim-boundary files generated alongside paper-facing tables.

The expected held-out validation state remains `PASS_PENDING_LABELS` while the
second blinded reviewer file is missing. This is a valid interim state and must
not be described as final evaluation.

## 10. Claims Supported by the Current Method Artifacts

The current method artifacts support the following claims:

- AgentSecBench provides a frozen, reproducible corpus of real-world LLM-agent
  repositories.
- Static extraction can produce a broad candidate population of
  security-sensitive behaviors.
- Security-ADG represents operation, effect, source/dependency, trust-boundary,
  and guard context in a single candidate-level graph.
- Guard-aware representation preserves defensive context omitted by sink-only
  and simplified ADG views.
- Local/source reproduction evidence can support qualitative case studies of
  real-world agent behavior.

The current method artifacts do not by themselves support:

- a claim that all candidates are vulnerabilities;
- final precision, recall, or F1 on held-out repositories;
- repository-wide vulnerability prevalence;
- CVE-grade affected-version ranges; or
- exploitability claims without deployment and maintainer-confirmed security
  boundaries.

## 11. Reproducibility Commands

Run from the repository root.

```powershell
python scripts\audit_corpus_snapshot.py
python scripts\validate_heldout_evaluation.py --allow-pending-labels
```

Refresh local reproduction-derived paper artifacts:

```powershell
python scripts\summarize_heldout_reproduction_evidence.py
python scripts\build_heldout_reproduction_case_matrix.py
python scripts\build_guard_ablation_table.py
python scripts\build_paper_results_snapshot.py
python scripts\export_paper_tables.py
```

Run public CI-equivalent tests:

```powershell
python -m unittest `
  tests/test_security_adg_dataflow.py `
  tests/test_security_adg_showcase.py `
  tests/test_heldout_reproduction_case_matrix.py `
  tests/test_guard_ablation_table.py `
  tests/test_paper_results_snapshot.py `
  tests/test_export_paper_tables.py
```

The full corpus and real reproduction evidence remain local unless explicitly
released. Public CI uses small committed fixtures to verify that artifact
generation remains deterministic without publishing the private analysis
outputs.
