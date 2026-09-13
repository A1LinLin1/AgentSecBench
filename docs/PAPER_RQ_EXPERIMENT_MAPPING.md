# Paper RQ and Experiment Mapping

This document maps the current AgentSecBench artifacts to paper research
questions.  It is written for the current evidence posture: reproduction-backed
ground truth, conservative vulnerability claims, and Security-ADG
representation evidence.  It does not assume completed blind human annotation.

## Summary of current evidence

| Evidence asset | Current value | Paper use |
|---|---:|---|
| Frozen corpus | 67 repositories, 11 ecosystems, 37,542 source files, 291 MB | benchmark scale and reproducibility |
| Static candidate pool | 531 candidates | candidate-generation and sampling frame, not vulnerability count |
| Reproduction-confirmed behavior GT | 22 cases across 13 repositories | main real-world evidence for behavior discovery |
| Vulnerability GT | 1 case | vulnerability-level evidence; not an assigned CVE |
| Pending disclosure / upgrade candidate | 1 case | follow-up candidate, not public vulnerability claim |
| Guarded not-vulnerability cases | 20 cases | negative-control and semantic-disambiguation evidence |
| Reproduction GT graph coverage | 22/22 source, graph, and dependency-path coverage | Security-ADG can represent all current reproduction-confirmed cases |
| Held-out representation study | 9 cases; 5 guarded cases | guard/context preservation ablation |
| RQ4 context completeness | sink-only 20.0%, plain ADG 40.0%, Security-ADG 91.1% | representation advantage, not final detection accuracy |
| Human/model labels used as GT | 0 | claim that GT is reproduction-confirmed, not label-confirmed |

## Recommended research questions

### RQ1. Corpus and benchmark coverage

**Question.** Does AgentSecBench capture diverse real-world LLM-agent
implementation patterns?

**Evidence.**

- `dataset/corpus_manifest.csv`
- `analysis/paper_results/README.md`
- corpus audit scripts and snapshot outputs

**Metrics / outputs.**

- repository count;
- ecosystem count;
- source-file count;
- source size;
- frozen commit count;
- snapshot audit pass/fail.

**Current claim.**

AgentSecBench contains 67 frozen real-world repositories across 11 agent
ecosystems, with 37,542 source files and 291 MB of source code.  The corpus is
frozen at repository commits and can support reproducible static and
representation-level experiments.

**Do not claim.**

- The corpus is statistically representative of all LLM-agent software.
- The 531 static candidates are vulnerabilities.

### RQ2. Reproduction-confirmed behavior ground truth

**Question.** Can the method produce a conservative real-world ground truth of
security-sensitive agent behaviors without relying on model votes or
single-reviewer labels?

**Evidence.**

- `analysis/ground_truth/reproduction_confirmed_gt.jsonl`
- `analysis/ground_truth/reproduction_confirmed_gt_summary.json`
- `analysis/ground_truth/disposition/vulnerability_gt_disposition_matrix.md`
- `docs/REPRODUCTION_GROUND_TRUTH_PROTOCOL.md`
- `docs/PAPER_GROUND_TRUTH_CONSTRUCTION_SECTION.md`

**Metrics / outputs.**

- behavior GT count;
- vulnerability GT count;
- pending upgrade/disclosure count;
- guarded not-vulnerability count;
- behavior-category distribution;
- proof-type distribution;
- label-source flags.

**Current claim.**

The current reproduction-confirmed ground truth contains 22
security-sensitive behavior cases across 13 repositories.  The disposition is
conservative: one vulnerability-GT case, one pending disclosure/upgrade
candidate, and 20 guarded not-vulnerability cases.  No single-reviewer labels
or model labels are used as ground truth.

**Do not claim.**

- The one vulnerability-GT case has an assigned CVE.
- The pending disclosure case is a confirmed public vulnerability.
- The 22 behavior cases estimate prevalence.

### RQ3. Beyond predefined sinks and case-study depth

**Question.** What kinds of security-sensitive agent behaviors does
Security-ADG expose beyond a sink-only view?

**Evidence.**

- `analysis/paper_results/rq3_case_study_table.md`
- `analysis/paper_results/tables/table_rq3_case_study.csv`
- `analysis/ground_truth/disposition/vulnerability_gt_disposition_matrix.md`
- case-specific reproduction records under
  `analysis/agent_discovery/reproduction_readiness/` and
  `analysis/reproduction/heldout/`

**Metrics / outputs.**

- case-study rows by repository, ecosystem, behavior, sink, guard posture, and
  evidence mode;
- disposition category for each reproduction-confirmed case;
- concrete dependency paths and claim boundaries.

**Current claim.**

Security-ADG supports qualitative case studies across command execution,
dynamic code execution, filesystem write, and network access behaviors.  The
method preserves dependency and boundary context needed to distinguish
vulnerability candidates from guarded local helpers, compile-only validators,
fixed argv-list tools, sandboxed evaluators, and intended local automation.

**Do not claim.**

- Quantitative recall/F1 superiority from these case studies alone.
- Any case is a CVE unless assigned by a CNA or maintainer advisory.

### RQ4. Representation and guard-context preservation

**Question.** Does Security-ADG preserve security-relevant context that
sink-only and simplified ADG views lose?

**Evidence.**

- `analysis/paper_results/rq4_guard_ablation_table.md`
- `analysis/paper_results/tables/table_rq4_guard_ablation.csv`
- `analysis/paper_results/README.md`
- `analysis/paper_results/paper_results_snapshot.json`

**Metrics / outputs.**

- operation visibility;
- external-effect visibility;
- dependency-path visibility;
- trust-boundary visibility;
- guard visibility;
- context completeness.

**Current claim.**

Across 9 reproduction-confirmed held-out cases, sink-only and simplified ADG
views expose 0/5 observed guard contexts, while Security-ADG preserves 5/5
guard contexts.  Context completeness increases from 20.0% for sink-only and
40.0% for simplified ADG to 91.1% for Security-ADG.

**Do not claim.**

- This is final detection precision, recall, or F1.
- Guard visibility proves the guard is sufficient or vulnerability-preventing.

## Optional RQ5. Disclosure and vulnerability confirmation

**Question.** Can reproduction-confirmed Security-ADG evidence support
coordinated vulnerability disclosure?

**Evidence.**

- ALR-001 disclosure material and support ticket status;
- ALR-003 private report / follow-up plan;
- `analysis/ground_truth/vulnerability_gt_upgrade_queue.jsonl`;
- `docs/VULNERABILITY_GT_ROADMAP.md`.

**Current claim.**

The workflow can produce disclosure-ready evidence packages, but assigned-CVE
claims require maintainer/CNA confirmation.  ALR-001 is the current
vulnerability-GT case and disclosure/CVE-track candidate; ALR-003 remains a
pending upgrade/disclosure candidate.

**Do not claim.**

- Assigned CVE.
- Maintainer-confirmed affected version range unless confirmed in writing.

## Experimental narrative

The paper should present the experiments in this order:

1. **Corpus construction and audit.** Establish AgentSecBench as a frozen,
   reproducible benchmark.
2. **Candidate extraction.** Show that static scanning produces broad
   security-sensitive operation candidates, not vulnerabilities.
3. **Security-ADG construction.** Explain how candidate operations are enriched
   with dependency, effect, trust-boundary, and guard context.
4. **Reproduction-confirmed GT.** Build the 22-case ground truth from
   reproducible evidence only.
5. **Disposition analysis.** Report the conservative 1 / 1 / 20 split:
   vulnerability GT, pending disclosure, and guarded not-vulnerability.
6. **Representation ablation.** Compare sink-only, simplified ADG, and
   Security-ADG using context completeness and guard visibility.
7. **Case studies.** Present a small number of representative cases, including
   one vulnerability-track case and several guarded negative controls.

## Claim boundary table

| Claim type | Allowed now? | Required evidence |
|---|---:|---|
| Dataset scale and reproducibility | Yes | frozen corpus manifest and audit |
| Candidate count | Yes | static scanner outputs |
| Candidate count as vulnerability count | No | not applicable |
| Behavior GT | Yes | reproduction-confirmed evidence |
| Vulnerability GT | Yes, for confirmed case only | impact plus trust/auth boundary |
| Assigned CVE | No | CNA or maintainer advisory |
| Method recall/F1 | No | exhaustive recall gold set or final blind held-out labels |
| Representation completeness | Yes | RQ4 ablation artifacts |
| Guard sufficiency | No | case-specific security proof or maintainer confirmation |

## Reproducibility commands

Run from the repository root:

```powershell
python scripts\audit_corpus_snapshot.py
python scripts\build_reproduction_ground_truth.py
python scripts\build_vulnerability_gt_upgrade_queue.py
python scripts\build_vulnerability_gt_disposition_matrix.py
python scripts\evaluate_reproduction_gt_coverage.py
python scripts\build_paper_results_snapshot.py
python scripts\export_paper_tables.py
```

Recommended validation tests:

```powershell
python -m unittest `
  tests.test_build_reproduction_ground_truth `
  tests.test_build_vulnerability_gt_upgrade_queue `
  tests.test_vulnerability_gt_disposition_matrix `
  tests.test_reproduction_gt_coverage `
  tests.test_paper_results_snapshot
```
