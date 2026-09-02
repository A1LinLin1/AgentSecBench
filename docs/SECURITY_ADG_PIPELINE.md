# Reproducible Security-ADG pipeline

The pipeline keeps four layers separate: static candidates, Security-ADG
evidence, structural validation, and a human-readable evidence view.  The
generated view labels every record as a **static candidate**, not a confirmed
vulnerability.

## Full local corpus run

Run this from the repository root. `ASB0024` is explicitly skipped because its
frozen Git tree contains a Windows-incompatible `:Zone.Identifier` path; the
skip is written into `pipeline_manifest.json`.

```powershell
python scripts/run_security_adg_pipeline.py `
  --manifest dataset/corpus_manifest.csv `
  --scope all_corpus `
  --analysis-mode v2_4 `
  --skip-sample-id ASB0024 `
  --output-root artifacts/security_adg/all_corpus_v2_4
```

Open `artifacts/security_adg/all_corpus_v2_4/showcase/index.html` locally in a
browser.  The page provides a candidate selector and switches between the
sink-only view, a plain ADG, and the Security-ADG view.

The output root contains:

- `findings.jsonl` and `static_scan_summary.csv`: static candidate extraction.
- `security_adg.jsonl` and `security_adg_summary.json`: evidence graphs.
- `security_adg_validation.json`: structural and split-isolation checks.
- `all_corpus_summary.json` and `review_queue.jsonl`: descriptive analysis and
  deterministic review priority for the all-corpus scope.
- `showcase/index.html` and `showcase/manifest.json`: portable visual evidence
  view and its selected-case provenance.
- `pipeline_manifest.json`: the command configuration and artifact locations.

To make a focused case-study page, add one or more exact candidate IDs:

```powershell
python scripts/generate_security_adg_showcase.py `
  --graphs graphs/security_adg/all_corpus_v2_4.jsonl `
  --output-dir artifacts/security_adg/case_study `
  --candidate-id SB-ASB0063-00002
```

If you are already invoking `generate_security_adg_v2.py` directly, add
`--showcase-dir artifacts/security_adg/my_run/showcase`.  The graph generator
will then write its ordinary JSONL and summary **plus** the standalone evidence
view in the same run.

## CI behavior

`.github/workflows/security-adg-artifacts.yml` deliberately runs on a small,
committed fixture rather than the private/local 67-repository corpus.  Each
pull request therefore tests the dataflow logic and verifies that the
interactive evidence page can still be generated.  The resulting standalone
HTML and manifest are uploaded as the `security-adg-showcase` workflow
artifact.

The full corpus run remains local and reproducible from its frozen manifest;
it is not required for ordinary CI and does not publish data or claim
vulnerabilities.
