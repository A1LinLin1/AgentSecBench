# Model Annotation Package

This directory contains the materials for independent annotation of the 150
formal Pilot tasks through a hybrid OpenRouter + DeepSeek-official panel.

## Files given to every model

1. `system_prompt.md`
2. `model_annotation_guide.md`
3. `output_schema.json`
4. Exactly one record from `inputs/model_tasks_blinded.jsonl`, or the matching
   `inputs/by_task/AT-xxxx.json` file

Do not provide models with scanner confidence, detector name, experiment split,
sampling weight, human annotations, or another model's response.

## Fixed protocol

- Each model labels all 150 tasks independently in a fresh single-turn session.
- Disable tools, browsing, code execution, memory, and retrieval.
- Use structured JSON output when the provider supports it.
- Record the exact returned model ID, provider request ID, parameters, UTC time,
  token usage, prompt-file hashes, task input hash, and raw response.
- Do not retry a semantically valid answer merely because it disagrees with
  another model. Retry only transport failures or invalid JSON, and record every
  attempt.
- Store each model's results separately. Never expose one model's output to
  another model.
- Use the exact model identifiers in `model_panel.md`. For OpenRouter, disable fallbacks,
  require structured-output support, and enforce no-data-collection routing.
  ZDR is the default. Any non-ZDR run requires the explicit
  `--allow-non-zdr` flag and is recorded in the run manifest.
- Route only the DeepSeek rater to the official DeepSeek API and record this
  distinct endpoint and privacy policy in the run manifest.
- Record and verify the upstream provider returned for every generation. Stop if
  one model is routed through more than one upstream provider.
- Include every HTTP 200 response in budget accounting, including responses
  discarded after invalid JSON or schema validation failures.

Model agreement is **inter-model agreement**, not human inter-annotator
agreement and not ground truth. Human adjudication remains required.
