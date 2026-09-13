# Reproducible Security-ADG pipeline

The pipeline keeps four layers separate: static candidates, Security-ADG
evidence, structural validation, and a human-readable evidence view.  The
generated view labels every record as a **static candidate**, not a confirmed
vulnerability.

## Framework-adaptive graph construction

Security-ADG now includes a framework-adaptive normalization layer implemented
in `scripts/security_adg_frameworks.py`.  The layer converts framework-specific
agent/tool idioms into a common semantic record before the graph is built.

The current adapter registry recognizes:

- MCP / FastMCP: `@mcp.tool`, `@server.tool`, `registerTool`, `server.tool`.
- LangChain: `@tool`, `Tool(...)`, `StructuredTool.from_function(...)`.
- CrewAI: `BaseTool` subclasses with `_run(...)` / `run(...)`, and CrewAI
  `@tool` import context.
- AutoGen: `register_for_llm(...)` and `register_for_execution(...)` bindings.
- OpenAI Agents SDK: `@function_tool`.
- Semantic Kernel: `@kernel_function`.
- LlamaIndex: `FunctionTool.from_defaults(...)` and related function-tool
  factories.

Each adapter emits framework evidence such as:

```json
{
  "framework": "LangChain",
  "semantic_role": "tool_definition",
  "symbol": "run_shell",
  "parameters": ["command"],
  "confidence": "high"
}
```

`security_adg_dataflow.py` consumes this evidence.  When a security-sensitive
operation depends on a parameter of a framework-confirmed tool, that parameter
is represented as:

```json
{
  "type": "input_source",
  "source_type": "agent_tool_parameter",
  "framework": "LangChain",
  "entrypoint_type": "tool_definition",
  "trust": "agent_or_external_caller"
}
```

`generate_security_adg_v2.py` then lifts the same evidence to the graph-level
symbol node:

```json
{
  "type": "agent_or_program_symbol",
  "agent_relevance": "framework_confirmed",
  "frameworks": ["LangChain"],
  "entrypoint_types": ["tool_definition"]
}
```

This design keeps Security-ADG framework-agnostic: adapters recognize front-end
syntax, while the graph schema remains stable across current and future agent
frameworks.  To add a new framework, add one adapter pattern plus a small
fixture in `tests/test_security_adg_frameworks.py`; the graph builder does not
need framework-specific rewrites.

## Full local corpus run

Run this from the repository root. `ASB0024` is explicitly skipped because its
frozen Git tree contains a Windows-incompatible `:Zone.Identifier` path; the
skip is written into `pipeline_manifest.json`.

```powershell
python scripts/run_security_adg_pipeline.py `
  --manifest dataset/corpus_manifest.csv `
  --scope all_corpus `
  --analysis-mode v2_5 `
  --skip-sample-id ASB0024 `
  --output-root artifacts/security_adg/all_corpus_v2_5
```

Open `artifacts/security_adg/all_corpus_v2_5/showcase/index.html` locally in a
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
  --graphs graphs/security_adg/all_corpus_v2_5.jsonl `
  --output-dir artifacts/security_adg/case_study `
  --candidate-id SB-ASB0063-00002
```

If you are already invoking `generate_security_adg_v2.py` directly, add
`--showcase-dir artifacts/security_adg/my_run/showcase`.  The graph generator
will then write its ordinary JSONL and summary **plus** the standalone evidence
view in the same run.

## CI behavior

`v2_5` is the current framework-adaptive mode.  It preserves the v2.4
parameter-precedence, overwrite, and sink-exclusion behavior, and adds
framework evidence from the adapter layer.  Historical v2.4 artifacts remain
useful for ablations and for comparing the effect of framework-adaptive
normalization.

### Figure renderer v2 (2026-09-09)

The existing generation commands now produce `figures/*.svg` for every case
and all three views, plus `layout.json` with node rectangles and edge routes.
The HTML is self-contained and needs no CDN, model API, or corpus access to open.
Use the case selector, click a node to highlight incident relations, zoom, or
choose **专注图形** to hide the evidence panel. **导出 SVG** saves the current
view; the generated SVG files are also available without opening a browser.
Browser print uses a separate landscape figure layout.

The renderer uses deterministic dependency ranks, separate context/policy
columns, wrapped labels, and obstacle-avoiding orthogonal arrows. It preserves
the selected nodes and typed edges from the JSONL; changing the layout does not
add dependency evidence or strengthen a security claim. Dashed guard relations
do not establish guard effectiveness.

`Simplified ADG` is the local `plain_adg` projection in the input graph. It is
**not an output of the AgentFlow implementation** and must not be reported as
an AgentFlow baseline result. The AgentFlow paper used as a design reference is
https://arxiv.org/abs/2607.01640 (particularly its typed-node ADG figures).

For the four local agent case studies:

```powershell
python scripts/generate_security_adg_showcase.py --graphs analysis/agent_discovery/security_adg_agent_cases_v1/graphs.jsonl --output-dir analysis/agent_discovery/security_adg_agent_cases_v1/showcase --max-graphs 4
python -m unittest tests/test_security_adg_showcase.py tests/test_security_adg_dataflow.py
```

Regression tests cover all four case studies in all three views: node/edge
preservation, non-overlapping node bounds, routes avoiding unrelated nodes,
SVG parsing, deterministic output, and safe handling of long/untrusted labels.
Existing CI commands and artifact uploads include the new SVGs automatically.

`.github/workflows/security-adg-artifacts.yml` deliberately runs on a small,
committed fixture rather than the private/local 67-repository corpus.  Each
pull request therefore tests the dataflow logic and verifies that the
interactive evidence page can still be generated.  The resulting standalone
HTML and manifest are uploaded as the `security-adg-showcase` workflow
artifact.

The full corpus run remains local and reproducible from its frozen manifest;
it is not required for ordinary CI and does not publish data or claim
vulnerabilities.
