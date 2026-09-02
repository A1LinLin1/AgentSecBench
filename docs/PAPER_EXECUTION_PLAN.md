# AgentSecBench Paper Execution Plan

## Current Evidence Snapshot

| Asset | Status | What it can support now |
|---|---:|---|
| Frozen corpus | 67 repositories, 11 ecosystems, 37,542 source files, 291 MB, 67 frozen commits | Dataset description and reproducibility |
| Pilot static candidates | 531 candidates across 5 repositories | Candidate population and stratified sample frame |
| Annotation sample | 150 candidates (100 high-confidence, 50 medium-confidence) | Precision/agreement study after blind labels |
| Five-model panel | 750 completed annotations; $7.367518 accounted cost | Pre-annotation and model-disagreement analysis only |
| Model agreement | Fleiss' kappa: 0.570 behavior, 0.689 agent relevance, 0.411 dependency, 0.410 trust boundary | Descriptive inter-model analysis only, not ground truth |
| Independent human annotation | 0 completed complete cases | **Main blocking item for quantitative claims** |
| Model-assisted audit | reviewer03 completed 150 tasks | Post-blind adjudication/error analysis only; not blind ground truth |
| Security-ADG v2 | 163 development graphs from 2 development repositories; 73 dependency paths | Method artifact and development-stage analysis |
| Baselines | Semgrep and CodeQL development artifacts exist | Pipeline validation; no final effectiveness claim yet |
| Disclosure case | ASB-CASE-0001 privately reported/prepared | Qualitative case study; not the paper's main quantitative evidence |

## Non-Negotiable Experimental Rule

Do not tune rules, thresholds, prompts, taxonomy, or the Security-ADG using
labels from the three held-out repositories:

- `dddabtc/winremote-mcp`
- `nexu-io/html-anything`
- `microsoft/magentic-ui`

The development repositories are `mantrakp04/manusmcp` and
`SWE-agent/mini-swe-agent`. The existing model panel is not ground truth. A
reviewer who has seen model votes/rationales must not be counted as a blind
annotator for the affected tasks.

## Phase 1 — Create the Gold Labels (First Priority)

Recruit **two new independent annotators** who have not seen the model panel or
model-audit interface. Give each a distinct ID, for example `blind01` and
`blind02`. They should independently label all 150 tasks with the blinded
human annotation interface.

Start the interface locally:

```powershell
python scripts\serve_human_annotation.py --annotator blind01 --port 8765
python scripts\serve_human_annotation.py --annotator blind02 --port 8766
```

For remote participants, use the already prepared sharing launcher, but send
each person only their own invitation URL and do not show model outputs:

```powershell
powershell -ExecutionPolicy Bypass -File scripts\start_annotation_panel.ps1 -Annotator blind01 blind02
```

After both complete 150 tasks, compute agreement:

```powershell
python scripts\analyze_human_agreement.py
```

Then adjudicate only disagreements. Preserve both raw files and save a separate
adjudicated label file with a written source-code rationale. Never overwrite
the two independent files.

### Pre-register the primary labels before looking at results

- **Behavior-positive:** `behavior_confirmed=true` and `agent_relevant=true`.
- **Dependency-positive (strict):** `dependency_confirmed=true`.
- **Dependency-positive (sensitivity analysis):** `true` or `partial`.
- Treat `uncertain` / `unknown` as excluded in the primary complete-case
  analysis and report their count separately.
- Treat `weakness_present` and `vulnerability_status` as secondary analyses;
  they are inherently more subjective and should not be the primary claim.

## Phase 2 — Freeze the Method on Development Repositories

### Temporary route when independent annotators are unavailable

Use `analysis/provisional/reviewer03_model_assisted_labels.jsonl` as a
**provisional single-reviewer, model-assisted label set**. It contains all 150
tasks and preserves the fact that the reviewer saw model outputs. It can be
used now for development diagnostics, case selection, and clearly marked
provisional/sensitivity tables. It cannot be used for human inter-annotator
agreement, independent human ground truth, final held-out evaluation claims, or
held-out method tuning.

The companion summary currently records 70 provisional behavior-positive
labels, 40 strict dependency-positive labels, and 46 inclusive
dependency-positive labels. Its weighted estimates are descriptive only.

Use only adjudicated labels from `ASB0001` and `ASB0044` to make the final
method choices:

1. Freeze Security-ADG v2 source/dependency rules and guard rules.
2. Freeze the candidate-to-baseline matching policy.
3. Freeze the Semgrep rule set (`predefined_sinks_v1.yml`) and CodeQL suite.
4. Record each change in a short changelog with date, reason, and development
   evidence.
5. Tag or archive the final configuration as the evaluation version.

The current v2 artifact is explicitly a development artifact: 163 graphs from
two repositories, with 73 dependency paths. Do not compare it to held-out
labels until this phase is frozen.

## Phase 3 — Run the Held-out Evaluation Once

Run the frozen method, Semgrep baseline, and CodeQL baseline on the three
held-out repositories. Do not modify the method after seeing these results.

For the 150-candidate stratified sample, report:

- raw positive/negative counts;
- weighted precision using `sample_weight`;
- a stratified confidence interval;
- Fleiss' kappa and pairwise Cohen's kappa for human labels;
- method coverage: candidates with a validated source/dependency path;
- baseline overlap and unique behavior discoveries;
- results by behavior category and by repository.

Do **not** report recall or F1 from this sample alone. It contains only scanner
candidates, so it cannot establish how many true behaviors were missed.

## Phase 4 — Build a Recall Gold Set (Needed for Recall/F1 Claims)

To make a recall claim, create an exhaustive behavior inventory for the two
predefined recall repositories:

- `dddabtc/winremote-mcp`
- `nexu-io/html-anything`

Independently inspect all plausible security-critical operations in those two
repositories, including operations absent from the static scanner's candidates.
Adjudicate this inventory as the recall gold set. Then compute recall and F1
for the frozen method and baselines against that inventory.

Until this is complete, write **precision, agreement, coverage, and case-study
results** — not recall/F1.

## Paper Structure You Can Write Now

1. **Introduction:** LLM-agent systems expose security-relevant effects through
   tools, files, browsers, networks, and runtime actions; predefined sinks do
   not capture the dependency/trust context needed for prioritization.
2. **AgentSecBench:** corpus construction, inclusion criteria, frozen commits,
   ecosystem/language statistics, ethics, and release protocol.
3. **Method:** static candidate extraction → Security-ADG def-use/dependency
   analysis → guard/trust-boundary evidence → ranked security-critical behavior.
4. **Experimental protocol:** repository-level development/held-out split,
   deterministic sampling, blinded annotation, adjudication, weighted metrics,
   baseline normalization, and no held-out tuning.
5. **Results:** add only after the labels and frozen evaluation are available.
6. **Case study:** ASB-CASE-0001, described as a responsibly disclosed local
   verification. Do not include unpatched technical details in a public draft.
7. **Limitations:** static-analysis incompleteness, language support, sampled
   precision versus exhaustive recall, deployment-dependent impact, and model
   panel labels not being ground truth.

## This Week's Deliverables

1. Assign `blind01` and `blind02`; start independent annotation.
2. Freeze a one-page evaluation protocol and primary label definitions.
3. Write the Dataset and Method sections using only confirmed corpus/method
   facts, leaving result tables as templates.
4. Add a reproducibility manifest: repository URL, frozen commit, language
   counts, scanner version/config hash, baseline version/config hash, and run
   command.
5. After labels arrive, calculate agreement first; only then adjudicate and
   populate precision/coverage tables.
