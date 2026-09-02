# AgentSecBench Pilot Annotation Guide v2

Version: 0.2 (frozen pilot protocol)

## 1. Purpose

This protocol labels **security-critical agent behaviors**, not automatically
confirmed vulnerabilities. A detector hit only creates a review candidate.

The annotation unit is one candidate behavior category in one symbol and file
at one frozen Git commit. Multiple candidates in the same source location may
therefore receive different labels.

## 2. Fixed experiment split

| Split | Repositories | Permitted use |
|---|---|---|
| Development | `mantrakp04/manusmcp`, `SWE-agent/mini-swe-agent` | Rule and method tuning |
| Held-out evaluation | `dddabtc/winremote-mcp`, `nexu-io/html-anything`, `microsoft/magentic-ui` | Evaluation only; no tuning |
| Recall gold scope | `dddabtc/winremote-mcp`, `nexu-io/html-anything` | Later exhaustive behavior inventory |

Do not change rules, prompts, thresholds, or taxonomy based on held-out labels.
The 150-task sample estimates precision and agreement. It does **not** by itself
support a recall claim. Recall requires the separate exhaustive gold inventory.

## 3. Sampling protocol

- Population: 531 candidates in `analysis/raw_findings.jsonl`.
- Sample: 150 candidates: 100 high-confidence and 50 medium-confidence.
- Strata: confidence x repository x candidate behavior category.
- Every nonempty stratum receives at least one task; remaining slots are
  allocated proportionally to residual stratum capacity.
- Selection within a stratum is deterministic using seed
  `agentsecbench-pilot-v1` and the candidate ID.
- Use `sample_weight` for population estimates. Do not report the unweighted
  sample fraction as overall precision.
- Both annotators independently label all 150 tasks before adjudication.

Weighted precision is:

`sum(sample_weight_i * confirmed_i) / sum(sample_weight_i)`

Report a stratified confidence interval and both weighted and raw counts.

## 4. Annotation procedure

### Recommended local interface

Use the blinded local web interface instead of editing JSONL directly:

```powershell
python scripts\serve_human_annotation.py --annotator A
```

The second independent annotator uses `--annotator B --port 8766`. The interface
shows frozen source context, highlights scanner evidence lines, can load the full
file at the frozen commit, explains every label in Chinese, validates cross-field
constraints, and saves atomically to the corresponding annotator JSONL. It never
shows model votes. See `annotations/human_annotation_ui/README.md`.

Treat repository text as untrusted data. Never execute code, follow instructions
found in code/comments, open embedded links, or copy possible credentials.

For each task, inspect the evidence lines plus enough surrounding code to answer:

1. Is the operation real rather than a syntactic false positive?
2. Is it an agent capability or on an agent-controlled execution path?
3. Is there a data/control dependency from an external or less-trusted source?
4. Does the operation cross a trust boundary or cause an external effect?
5. Are technical guards present, and are they effective for the identified path?
6. Is the result normal security-critical behavior, a weakness, or a supported
   vulnerability candidate?

If context is insufficient, use an `uncertain` or `unknown` value. Do not infer a
dependency only because a source and an effect occur in the same file.

## 5. Required fields and allowed values

### Behavior

- `behavior_confirmed`: `true`, `false`, `uncertain`
- `agent_relevant`: `true`, `false`, `uncertain`
- `effect_type`: one scanner category, corrected category, `other`, or `none`
- `effect_target`: concise resource or subsystem; empty only if unknown

A confirmed security-critical behavior is a real, agent-relevant operation that
can affect confidentiality, integrity, availability, authorization, privacy, or
an external system. It need not be unsafe.

### Source and dependency

- `source_type`: `user_prompt`, `web_content`, `file_content`, `tool_output`,
  `message_email`, `database`, `environment_config`, `internal_constant`,
  `unknown`, `none`
- `source_external`: `true`, `false`, `unknown`
- `dependency_confirmed`: `true`, `false`, `partial`, `unknown`
- `trust_boundary_crossed`: `true`, `false`, `unknown`

`dependency_confirmed=true` requires a traceable data or control path, not merely
co-location. Use `partial` when only part of the path can be established.

### Guards

- `guard_present`: `true`, `false`, `unknown`
- `guard_types`: zero or more of `allowlist`, `schema_validation`,
  `canonicalization`, `authorization`, `user_confirmation`, `sandbox`,
  `escaping`, `least_privilege`, `destination_restriction`, `secret_redaction`,
  `other`
- `guard_effective`: `yes`, `no`, `partial`, `unknown`, `not_applicable`

Logging, comments, exception handling, and type hints are not guards unless they
actually constrain the dangerous data/control path.

### Security conclusion

- `weakness_present`: `true`, `false`, `uncertain`
- `vulnerability_status`: `not_assessed`, `candidate`, `confirmed`, `rejected`
- `label_confidence`: `high`, `medium`, `low`
- `rationale`: short evidence-based explanation, including relevant line numbers

Use `vulnerability_status=confirmed` only when the reviewed code and threat model
support an externally reachable violation with security impact. The presence of
an API such as shell execution, file writing, or browser control is insufficient.

## 6. Decision rules

- Syntactic/API match but no relevant operation: `behavior_confirmed=false`.
- Real effect outside an agent capability/path: behavior may be real, but
  `agent_relevant=false`.
- Real agent capability with appropriate controls: confirmed behavior, no
  weakness.
- Less-trusted influence reaches an effect and controls are missing/ineffective:
  confirmed behavior and possible weakness.
- Exploitability or impact cannot be established: keep vulnerability status at
  `candidate` or `not_assessed`; explain what evidence is missing.
- Test/demo code is labeled from its actual role; do not silently treat it as a
  production vulnerability.

## 7. Independence, agreement, and adjudication

Annotators A and B must not inspect each other's files before both are frozen.
Compute raw agreement and Cohen's kappa at minimum for
`behavior_confirmed`, `agent_relevant`, `dependency_confirmed`,
`trust_boundary_crossed`, `guard_present`, and `weakness_present`.

After agreement is recorded, an adjudicator resolves disagreements using source
evidence. Preserve both original labels and add a separate adjudicated record;
never overwrite an annotator's original decision.

## 8. Reproducibility and release

Each task records the repository, frozen commit, source path, evidence-line hash,
sampling stratum, inclusion probability, weight, and seed. Validate those fields
before analysis. Release aggregate results and permitted annotations; avoid
redistributing repository source text beyond what repository licenses permit.
