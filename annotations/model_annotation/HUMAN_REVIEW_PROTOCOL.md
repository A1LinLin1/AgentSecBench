# Human review after the model panel

The five-model panel is an independent pre-annotation and triage instrument. It
is not ground truth and must not be reported as human inter-annotator agreement.

1. Annotators A and B independently label all 150 tasks using
   `annotations/annotator/annotator_a.jsonl` and `annotator_b.jsonl`.
2. During independent annotation, do not show either annotator model votes,
   rationales, agreement scores, or review priorities.
3. Compute human raw agreement and Cohen's kappa before adjudication.
4. A separate adjudication pass resolves human disagreements with a written
   source-code rationale. Preserve both original human labels.
5. Only after independent human labels are frozen may
   `analysis/model_disagreement_queue.*` be used for error analysis and review
   ordering. Fleiss' kappa from that directory is inter-model agreement only.
