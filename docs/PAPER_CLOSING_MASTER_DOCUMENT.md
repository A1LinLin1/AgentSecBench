# AgentSecBench Paper Closing Master Document

> Status: integrated writing and experiment-control document.
>
> This document merges the current paper story, method, experiment artifacts,
> reproduction evidence, claim boundaries, and remaining closing tasks. It is
> intended to help turn the project into a paper draft. It is not itself a
> final vulnerability advisory, CVE report, or final held-out accuracy result.

## 1. Short Answer: Can the Paper Enter the Closing Stage?

Yes. The project can now enter the paper-closing stage.

However, "closing" should mean different things depending on the target:

| Target | Current readiness | Required caution |
|---|---:|---|
| Internal report, thesis chapter, workshop-style paper | High | Write claims as benchmark + method + case-study evidence. |
| Systems/security empirical paper with qualitative contribution | Medium-high | Emphasize frozen corpus, Security-ADG, reproducible case studies, and representation ablation. |
| Top-tier security paper with strong quantitative effectiveness claims | Not fully closed | Needs independent held-out gold labels and final precision/recall/F1 before strong effectiveness claims. |

The paper is no longer in the "collect some repositories and see what happens"
stage. It has a coherent research object, a frozen corpus, a method, baselines,
CI-backed artifacts, local reproduction evidence, and paper-facing tables.

The remaining danger is claim overreach. The safest closing posture is:

> AgentSecBench is a frozen real-world benchmark and Security-ADG is a
> guard-aware semantic evidence representation for discovering and explaining
> security-critical behaviors in LLM-agent systems.

Do not yet write:

> We proved final recall/F1 superiority over all baselines on the held-out
> corpus.

unless the independent held-out labels and adjudication are completed.

## 2. Current Paper Thesis

A strong current thesis is:

> Existing static security analyses often start from predefined sink APIs, but
> LLM-agent systems expose security-critical behavior through agent tools,
> model-mediated decisions, framework adapters, local automation, external
> package ingestion, and MCP-style capability surfaces. AgentSecBench provides a
> frozen real-world corpus for studying these behaviors, and Security-ADG
> augments candidate operations with semantic dependency, trust-boundary, and
> guard evidence so that reviewers can distinguish API presence, reachable
> agent behavior, guarded behavior, and higher-risk unguarded behavior.

Possible title:

```text
Beyond Predefined Sinks:
Discovering Security-Critical Behaviors in LLM Agents
via Security-Aware Dependency Graphs
```

Alternative, more benchmark-forward title:

```text
AgentSecBench:
A Real-World Benchmark and Security-Aware Dependency Graphs
for LLM-Agent Behavior Discovery
```

## 3. Contributions

The paper currently has three clean contributions.

### Contribution 1: AgentSecBench

AgentSecBench is a frozen, reproducible corpus of real-world LLM-agent
repositories.

Current corpus statistics:

| Metric | Value |
|---|---:|
| Repositories | 67 |
| Agent ecosystems | 11 |
| Source files | 37,542 |
| Source size | 291 MB |
| Frozen commits | 67 |
| Snapshot audit status | pass |

Why this matters:

- the repositories are real projects rather than synthetic examples;
- commits are frozen for reproducibility;
- the corpus covers multiple agent ecosystems rather than one framework;
- the snapshot audit checks uniqueness, commit state, and worktree cleanliness.

### Contribution 2: Security-Critical Behavior Discovery

The project reframes the task away from "vulnerability count" and toward
"security-critical behavior discovery."

The current pipeline is:

```text
Frozen repositories
  -> broad static candidate extraction
  -> semantic dependency and guard analysis
  -> Security-ADG evidence graphs
  -> model/human/reproduction review
  -> paper-facing tables and case studies
```

The important distinction:

```text
531 candidates != 531 vulnerabilities
```

The 531 pilot candidates are automatically detected security-sensitive
operation candidates. They become evidence only after dependency review,
guard interpretation, and, where appropriate, local reproduction or human
adjudication.

### Contribution 3: Security-Aware ADG

Security-ADG extends a normal dependency/effect graph with security-specific
semantics:

- operation;
- external effect;
- input source;
- semantic dependency path;
- trust boundary;
- guard evidence.

This is stronger than a predefined sink list because it preserves why an
operation matters, not merely that a sensitive API appears in source code.

## 4. Method Overview

The method separates four concepts that are often collapsed in static security
experiments.

| Concept | Meaning | Example |
|---|---|---|
| Operation | A source-code location that performs or prepares a sensitive effect. | `subprocess.run`, `fs.writeFile`, browser automation, service control. |
| Source/dependency evidence | Local evidence that an external or agent-facing value may influence the operation. | MCP tool parameter reaches command execution. |
| Trust-boundary evidence | Evidence that data crosses from less-trusted input to local/system effect. | User-supplied repository URL reaches local process invocation. |
| Guard evidence | Defensive context that changes interpretation. | escaping, argv-list invocation, allowlist, schema validation, path checks. |

The Security-ADG output is an evidence representation, not an automatic
vulnerability verdict.

## 5. Static Candidate Extraction

The first stage extracts broad security-sensitive operation candidates from
frozen source files.

Operation families include:

- command execution and process creation;
- dynamic code execution;
- filesystem read, write, and delete;
- browser and desktop automation;
- network and remote-service access;
- credential or secret access;
- database access;
- external tool invocation;
- permission or authorization changes.

Each candidate records repository provenance, frozen commit, file path, line,
operation category, detector identity, confidence tier, and local code context.

This stage should be described as candidate generation, not vulnerability
discovery.

## 6. Security-ADG Representation

Security-ADG represents a candidate as a graph with typed nodes and edges.

Typical nodes:

- `agent_or_program_symbol`;
- `security_sensitive_operation`;
- `external_effect`;
- `input_source`;
- `trust_boundary`;
- `guard_candidate`.

Typical edges:

- `contains`;
- `may_cause`;
- `may_data_depend_on`;
- `may_cross`;
- `may_guard`.

For ablation, the same candidate can be projected into:

| View | What it shows | Main limitation |
|---|---|---|
| Sink-only | Sensitive operation exists. | Cannot distinguish reachable, guarded, or unguarded behavior. |
| Simplified ADG | Operation and effect. | Does not preserve security-specific dependency, boundary, or guard evidence. |
| Security-ADG | Operation, effect, dependency, boundary, and guard context. | Still needs labels/reproduction for final correctness claims. |

## 7. Guard-aware Interpretation

A core advantage of Security-ADG is that it does not flatten all sensitive APIs
into the same bucket.

Guard examples:

- shell/XML/SQL/template escaping;
- argv-list subprocess invocation instead of shell-string execution;
- fixed executable and fixed argument structure;
- allowlists or schema validation;
- path traversal and absolute-path rejection;
- symlink/hardlink rejection;
- size caps for compressed and decompressed content;
- authentication and bind-address checks;
- staged writes, atomic rename, and rollback.

Guard evidence changes interpretation but does not automatically prove safety.
It means the representation preserved relevant defensive context for reviewers
to inspect.

## 8. Baselines

The current baseline story is:

| Baseline | Role |
|---|---|
| Sink-only | A permissive predefined-operation comparator. |
| Semgrep | Lightweight predefined sink rules. |
| CodeQL | Traditional static security analysis where supported. |
| Simplified ADG | Ablation view without security-specific source, boundary, and guard semantics. |

The matching policy is fixed before held-out labels are read:

```text
repository + frozen commit + repository-relative file
+ operation category + line overlap
```

No cross-file matching, no label-aware tolerance adjustment, and no manual
per-item matching are allowed.

## 9. Annotation and Model Panel Status

The project has a scalable annotation framework, but the distinction between
model labels, reviewer audit, and gold labels must remain explicit.

Current pilot annotation assets:

| Asset | Status | Paper-safe use |
|---|---:|---|
| Static candidates | 531 candidates | Candidate population and sampling frame. |
| Stratified sample | 150 tasks | Pilot annotation/evaluation frame. |
| Five-model panel | 750/750 completed calls | Triage, disagreement analysis, prioritization. |
| Model cost | $7.367518 accounted conservative cost | Reproducibility/cost reporting. |
| Model agreement | Fleiss' kappa available | Inter-model agreement only, not correctness. |
| reviewer03 | 150 model-assisted reviews | Development diagnostics and provisional analysis only. |
| Blind human labels | Not complete | Required for final human-gold quantitative claims. |

Known model-panel agreement values:

| Field | Fleiss' kappa |
|---|---:|
| behavior | 0.570 |
| agent relevance | 0.689 |
| dependency | 0.411 |
| trust boundary | 0.410 |

These are useful, but they do not prove accuracy.

## 10. Held-out Recall Protocol

The held-out recall inventory currently covers two repositories:

| Repository | Sample ID | Frozen commit | Inventory records |
|---|---|---|---:|
| `dddabtc/winremote-mcp` | ASB0063 | `2185ee68428e76f29176291a2a862b1561468462` | 148 |
| `nexu-io/html-anything` | ASB0008 | `779fce327024612eba752fe42e1267a3918f7640` | 196 |

Total held-out operation inventory:

```text
344 records
```

Category distribution:

| Category | Count |
|---|---:|
| browser_control | 27 |
| command_execution | 76 |
| dynamic_code_execution | 17 |
| external_tool_invocation | 58 |
| filesystem_delete | 15 |
| filesystem_read | 43 |
| filesystem_write | 62 |
| network_access | 46 |

Current validator state:

```text
PASS_PENDING_LABELS
```

This is expected while independent reviewer labels are missing. It means the
method state and inventory can be checked, but final held-out precision,
recall, and F1 should not yet be claimed.

## 11. Local Reproduction Evidence

The current strongest real-world evidence is a local/source reproduction case
set. It supports qualitative case studies and representation analysis.

Summary:

| Metric | Value |
|---|---:|
| Held-out reproduction-confirmed cases | 9 |
| Confirmed behavior cases | 9 |
| Guarded cases | 5 |
| No-guard-confirmed cases | 4 |
| Repositories | 2 |
| Ecosystems | 2 |
| Human labels used | false |
| Model labels used | false |

Case matrix:

| ID | Repo | Ecosystem | Behavior | Sink | Guard | Evidence mode |
|---|---|---|---|---|---|---|
| HSQ-0014 | `dddabtc/winremote-mcp` | MCP / desktop automation | shell command execution | PowerShell `-Command` | no_guard_confirmed | local monkeypatch proof |
| HSQ-0087 | `dddabtc/winremote-mcp` | MCP / desktop automation | application launch | PowerShell `Start-Process` | no_guard_confirmed | local monkeypatch proof |
| HSQ-0089 | `dddabtc/winremote-mcp` | MCP / desktop automation | desktop notification script | PowerShell toast script | guarded | local monkeypatch proof |
| HSQ-0091 | `dddabtc/winremote-mcp` | MCP / desktop automation | network diagnostic process | subprocess argv list | no_guard_confirmed | local monkeypatch proof |
| HSQ-0103 | `dddabtc/winremote-mcp` | MCP / desktop automation | service control | PowerShell `Start-Service` | guarded | local monkeypatch proof |
| HSQ-0211 | `nexu-io/html-anything` | Coding agent / skill marketplace | agent CLI discovery process | `child_process.spawn` | no_guard_confirmed | source-level construction proof |
| HSQ-0298 | `nexu-io/html-anything` | Coding agent / skill marketplace | external content file write | `fs.writeFile` | guarded | source-level construction proof |
| HSQ-0300 | `nexu-io/html-anything` | Coding agent / skill marketplace | external tarball extraction | `child_process.spawn tar` | guarded | source-level construction proof |
| HSQ-0302 | `nexu-io/html-anything` | Coding agent / skill marketplace | validated skill file write | `fs.writeFile` | guarded | source-level construction proof |

Paper-safe interpretation:

- These cases show real security-sensitive agent behavior patterns.
- They show why operation, dependency, trust boundary, and guard evidence matter.
- They support qualitative case studies and RQ4 representation evidence.
- They do not establish corpus-wide vulnerability prevalence.

## 12. Guard-aware Representation Ablation

The current RQ4 artifact compares sink-only, simplified ADG, and Security-ADG
on the same 9 reproduction-confirmed held-out cases.

| View | Operation | Effect | Dependency path | Trust boundary | Guard | Guarded-case guard coverage | Context completeness |
|---|---:|---:|---:|---:|---:|---:|---:|
| Sink-only | 9 | 0 | 0 | 0 | 0 | 0.00% | 20.00% |
| Simplified ADG | 9 | 9 | 0 | 0 | 0 | 0.00% | 40.00% |
| Security-ADG | 9 | 9 | 9 | 9 | 5 | 100.00% | 91.11% |

Suggested paper sentence:

> Across 9 reproduction-confirmed held-out cases, sink-only and simplified ADG
> views expose 0/5 and 0/5 observed guard contexts, respectively, while
> Security-ADG preserves 5/5 guard contexts and raises representation
> completeness from 20.0% / 40.0% to 91.1%.

Claim boundary:

- This supports the claim that Security-ADG preserves security context omitted
  by simpler representations.
- It should not be reported as final method accuracy.

## 13. Agent-focused Discovery Evidence

The project also moved beyond MCP-only examples into broader agent/coding-agent
repositories.

Confirmed or high-priority agent-focused examples include:

| ID | Repository | Evidence status | Safe interpretation |
|---|---|---|---|
| ALR-001 | `comet-ml/opik` | local benign metric execution confirmed | Strong local behavior evidence; possible disclosure/CVE candidate depending on maintainer security boundary. |
| ALR-003 | `heshengtao/comfyui_LLM_party` | workflow-level LLM tool to interpreter behavior confirmed | Useful agent-workflow case study. |
| ALR-007 | `FSoft-AI4Code/AgileCoder` | LLM code block to `exec` path confirmed | Strong semantic dependency example. |
| ASE-0007 | `QuantaAlpha/RepoMaster` | source-level repository argument to `shell=True` git clone trace confirmed | High-priority follow-up candidate; not yet a vulnerability claim. |

Example ALR-007 result:

```text
LLM/code block text
  -> CodePrompt processing
  -> exec(self, global_vars, local_vars)
  -> benign local marker observed
```

Example ASE-0007 trace:

```text
run_repository_agent(repository)
  -> repo_config["url"]
  -> TaskManager.initialize_tasks()
  -> DataProcessor.setup_task_environment()
  -> repo_url = repo_info["url"]
  -> clone_cmd = f"git clone {repo_url} {target_repo_path}"
  -> subprocess.run(clone_cmd, shell=True, check=True)
```

Safe claim:

> Semantic review can uncover deeper agent-relevant traces beyond the first
> static hit while also downgrading weaker candidates when the source is
> internal setup rather than external input.

## 14. CVE and Disclosure Position

CVE evidence is useful for case-study strength, but it is not required for the
main paper contribution.

The paper should not depend on receiving a CVE number. CVE timelines are
external and uncertain.

Use CVE/disclosure evidence as:

- optional qualitative validation;
- evidence that the benchmark finds real maintainer-relevant issues;
- a short case study if confirmed by maintainers.

Do not make the benchmark or method contribution depend on:

- maintainer response speed;
- CVE assignment;
- exact affected version range;
- public exploitability confirmation.

The safest wording is:

> We prepared private disclosure material for selected locally reproduced
> cases. These disclosures are treated as qualitative evidence and are not used
> as labels for the main benchmark evaluation.

## 15. Current Public Repository Artifacts

The repository now contains CI-friendly, disclosure-safe artifacts:

| Artifact | Purpose |
|---|---|
| `scripts/build_heldout_reproduction_case_matrix.py` | Builds reproduction case matrix from local evidence records. |
| `scripts/build_guard_ablation_table.py` | Builds guard-aware representation ablation tables. |
| `scripts/build_paper_results_snapshot.py` | Builds a paper-facing result snapshot. |
| `scripts/export_paper_tables.py` | Exports CSV and LaTeX tables for the paper. |
| `docs/METHOD_SECTION_DRAFT.md` | Method section draft. |
| `docs/PAPER_CLOSING_MASTER_DOCUMENT.md` | This integrated closing document. |
| `.github/workflows/security-adg-artifacts.yml` | CI artifact generation workflow. |

Public CI uses small fixtures rather than private corpus/reproduction outputs.
This is the correct design for a security paper repository.

## 16. Reproducibility Commands

Run from the repository root.

Snapshot audit:

```powershell
python scripts\audit_corpus_snapshot.py
```

Held-out protocol validation:

```powershell
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

## 17. What Can Be Written Now

The following claims are currently safe:

1. AgentSecBench is a frozen real-world corpus of 67 LLM-agent repositories.
2. The benchmark spans 11 ecosystems and records 37,542 source files and 291 MB
   of code.
3. Static scanning produced 531 pilot candidates, which are candidate
   security-sensitive operations rather than vulnerabilities.
4. Security-ADG represents operation, external effect, source/dependency,
   trust-boundary, and guard context.
5. Local/source reproduction confirmed 9 held-out behavior cases across 2
   repositories and 2 ecosystems.
6. Security-ADG preserved guard context in 5/5 guarded reproduction-confirmed
   cases, whereas sink-only and simplified ADG projections preserved 0/5.
7. Security-ADG raised representation completeness from 20.0% / 40.0% to 91.1%
   in the reproduction-confirmed case-study set.
8. Model panels are useful for scalable triage, but are not treated as ground
   truth.
9. The public repository provides deterministic artifact-generation tests
   without publishing sensitive local reproduction outputs.

## 18. What Should Not Be Claimed Yet

Avoid these claims until the missing evidence exists:

1. Do not claim 531 vulnerabilities.
2. Do not claim final held-out precision, recall, or F1.
3. Do not claim the model panel is more accurate than humans unless there is an
   independently verified oracle or reproduction-backed gold set.
4. Do not claim CVE-grade vulnerability status without maintainer/security
   boundary confirmation.
5. Do not claim repository-wide prevalence of vulnerabilities.
6. Do not claim Semgrep/CodeQL are fully defeated across the full corpus unless
   final matching and labels support it.

## 19. Recommended Paper Structure

Suggested paper outline:

```text
1. Introduction
   - LLM-agent systems expose real-world security-critical behavior.
   - Predefined sink lists are insufficient.
   - Need semantic dependency + trust-boundary + guard-aware evidence.

2. Background and Motivation
   - LLM agents, MCP/tools, coding agents, local automation.
   - Why conventional sinks miss agent-specific semantics.

3. AgentSecBench
   - Collection criteria.
   - Corpus statistics.
   - Commit freeze and reproducibility audit.

4. Security-ADG
   - Graph schema.
   - Candidate extraction.
   - Dependency analysis.
   - Guard-aware representation.

5. Experimental Protocol
   - Development vs held-out split.
   - Baselines.
   - Matching policy.
   - Annotation/model/reproduction separation.

6. Results
   - RQ1 corpus diversity.
   - RQ2 candidate discovery and baseline overlap.
   - RQ3 reproduction-confirmed case studies.
   - RQ4 guard-aware representation ablation.

7. Case Studies
   - MCP/desktop automation.
   - Coding-agent/skill marketplace.
   - Agent code-execution or repository-ingestion traces.

8. Discussion
   - Why guard context matters.
   - Why model panels are useful but not gold.
   - Disclosure and CVE boundaries.

9. Threats to Validity
   - Static-analysis incompleteness.
   - Annotation subjectivity.
   - Local reproduction vs deployment exposure.
   - Corpus representativeness.

10. Conclusion
```

## 20. Minimum Closing Checklist

If the goal is to submit a careful pilot/case-study paper:

- [x] Corpus frozen and audited.
- [x] Candidate extraction pipeline exists.
- [x] Security-ADG generation exists.
- [x] Reproduction case matrix exists.
- [x] Guard ablation exists.
- [x] Paper table export exists.
- [x] Public CI fixtures exist.
- [x] Method section draft exists.
- [ ] Results section draft.
- [ ] Introduction and abstract.
- [ ] Threats-to-validity section.
- [ ] One polished figure for Security-ADG.
- [ ] Final claim-boundary review.

If the goal is a strong quantitative security paper:

- [x] Held-out inventory exists.
- [x] Matching policy exists.
- [x] Validation gate reports pending labels.
- [ ] Independent held-out labels or reproduction-backed adjudicated gold.
- [ ] Final method-vs-baseline precision/recall/F1.
- [ ] Confidence intervals.
- [ ] Frozen final evaluation tag.
- [ ] No post-label tuning audit.

## 21. Recommended Next Step

The next most valuable step is not more collection. It is writing and freezing
the paper-facing argument.

Recommended immediate sequence:

1. Create a Results section draft from existing artifacts.
2. Create one polished Security-ADG figure and one guard-ablation table.
3. Write the Threats to Validity section honestly.
4. Decide the submission posture:
   - pilot/case-study paper now; or
   - wait for gold labels and submit stronger quantitative version.

My current recommendation:

> Start paper closing now, but close it as a benchmark + method + reproducible
> case-study paper unless the held-out gold labels are completed. If the target
> is a high bar empirical security venue, keep one more experiment loop for
> independent labels or reproduction-backed adjudication.

