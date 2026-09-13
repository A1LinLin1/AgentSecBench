# Ground Truth Construction Section Draft

This draft is written as a paper-facing section.  It intentionally avoids
claiming that every reproduced behavior is a vulnerability.

## Ground truth construction

We construct ground truth from reproduction evidence rather than from model
judgments or single-reviewer labels.  For each candidate behavior, we require at
least one concrete evidence record: a local runtime reproduction, a benign
runtime marker, a runtime stub or monkeypatch observation, a source-level trace,
or a boundary/reachability proof.  The resulting ground truth is therefore
evidence-backed and replayable from repository artifacts.

We distinguish two levels of evidence.  First, a case is counted as
reproduction-confirmed behavior ground truth when the evidence confirms that a
security-sensitive behavior path exists.  This level supports evaluation of
behavior discovery and graph construction.  Second, a case is counted as
vulnerability ground truth only when the evidence also confirms impact and a
trust or authentication boundary.  This stricter level supports vulnerability
claims and coordinated disclosure.  Cases that reproduce security-sensitive
behavior but also show guarding, intended local operation, compile-only
validation, fixed argv-list tool invocation, or an unconfirmed deployment
boundary are retained as guarded not-vulnerability cases rather than discarded.

This separation is important for LLM-agent systems.  Many agent frameworks
legitimately expose powerful local operations such as shell tools, file tools,
package installers, browser controls, GitHub CLI helpers, or code validators.
Treating every occurrence of these operations as a vulnerability would
overstate risk and inflate evaluation metrics.  Conversely, discarding them
would hide the semantic distinctions needed by security-oriented dependency
graphs.  We therefore keep guarded cases as negative-control and
semantic-disambiguation evidence.

In the current snapshot, the reproduction-confirmed ground truth contains 22
security-sensitive behavior cases across 13 repositories.  Only one case is
classified as vulnerability ground truth, one case remains a pending
disclosure/upgrade candidate, and 20 cases are explicitly retained as guarded
not-vulnerability cases.  No single-reviewer labels or model labels are used to
construct this ground truth.

| Disposition | Count | Interpretation |
|---|---:|---|
| Vulnerability GT | 1 | confirmed impact plus trust/auth boundary; not an assigned CVE unless a CNA or maintainer assigns one |
| Pending upgrade / disclosure | 1 | strong follow-up candidate, but not a public vulnerability claim |
| Guarded not-vulnerability | 20 | reproduced behavior retained as negative-control / semantic-disambiguation evidence |

The behavior categories covered by the reproduction-confirmed ground truth are:
14 command-execution cases, 6 dynamic-code-execution cases, 1 filesystem-write
case, and 1 network-access case.  The proof corpus includes boundary or
reachability evidence, source traces, local reproductions, runtime markers, and
runtime stubs or monkeypatch observations.

## Claim boundaries

The following boundaries should be preserved in the paper:

- Reproduction-confirmed behavior GT is not equivalent to vulnerability GT.
- Vulnerability GT is not equivalent to an assigned CVE.
- Pending upgrade or disclosure candidates are not public vulnerability claims.
- Guarded not-vulnerability cases are not failures; they are used to evaluate
  whether the method preserves guard context and avoids sink-only overclaiming.
- Single-reviewer labels and model labels are diagnostic inputs only and are
  not used as ground truth.

## Suggested paper wording

```text
Our ground truth construction is intentionally conservative.  We first confirm
security-sensitive behavior paths using local/runtime, stubbed, source-level,
or boundary evidence.  We then separate behavior ground truth from
vulnerability ground truth: the latter requires both impact and a confirmed
trust or authentication boundary.  This distinction prevents intended local
features, guarded helpers, compile-only validators, and fixed tool invocations
from being misreported as vulnerabilities.  In our current snapshot, 22
reproduction-confirmed behavior cases yield one vulnerability-ground-truth case,
one pending disclosure candidate, and 20 guarded not-vulnerability cases.  No
single-reviewer or model-generated labels are used to construct this ground
truth.
```

## Reproducibility commands

Run from the repository root:

```powershell
python scripts\build_reproduction_ground_truth.py
python scripts\build_vulnerability_gt_upgrade_queue.py
python scripts\build_vulnerability_gt_disposition_matrix.py
python scripts\evaluate_reproduction_gt_coverage.py
python scripts\build_paper_results_snapshot.py
python scripts\export_paper_tables.py
```

Primary generated artifacts:

- `analysis/ground_truth/reproduction_confirmed_gt.jsonl`
- `analysis/ground_truth/reproduction_confirmed_gt_summary.json`
- `analysis/ground_truth/vulnerability_gt_upgrade_queue.jsonl`
- `analysis/ground_truth/disposition/vulnerability_gt_disposition_matrix.md`
- `analysis/paper_results/README.md`
