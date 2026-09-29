# Framework coverage diagnostics

AgentSecBench writes `framework-coverage.json` for every scan and embeds the
same diagnostic in the offline report. Its purpose is to expose modeling gaps,
not to advertise unsupported completeness.

## Status meanings

Each active built-in or project adapter receives one status:

| Status | Exact meaning |
|---|---|
| `modeled` | At least one candidate graph contains semantic evidence from the adapter |
| `signal_only` | Scanned source matched an adapter source/candidate pattern, but no candidate graph received its semantic evidence |
| `not_observed` | No source or candidate signal for the adapter appeared in scanned files |

These states are observations from one configured scan. `not_observed` does not
prove that the framework is absent, and `modeled` does not prove that every
framework construct was recovered.

## Repository-level fields

- `framework_signal_file_count`: distinct files with adapter source or candidate
  signals;
- `framework_modeled_file_count`: distinct files contributing adapter evidence
  to candidate graphs;
- `candidate_files_with_framework_context`: candidate-bearing files with any
  framework evidence;
- `generic_candidate_file_count`: candidate-bearing files without framework
  evidence;
- `generic_candidate_files`: bounded, sorted file list for follow-up;
- `parse_failures`: Python files that project-level indexing could not parse;
- `fallback_framework_counts`: generic tool-decorator evidence not attributed to
  a registered adapter.

Lists are capped at 100 paths and include a corresponding `*_truncated` flag.

## How to use the diagnostic

1. Review `signal_only` adapters first. They identify repositories where a
   framework likely exists but the current semantic entrypoint patterns did not
   attach to a candidate.
2. Review generic candidate files that contain agent entrypoints. Ordinary
   utility files may correctly remain generic.
3. Inspect parse failures before relying on cross-function source recovery.
4. Add a narrowly scoped project adapter and rerun the scan.
5. Confirm that the adapter changes from `signal_only` to `modeled` on the
   intended candidate without creating unrelated matches.

## Add a project adapter

```toml
[[framework_adapters]]
id = "acme-agent"
name = "Acme Agent"
languages = ["python"]
source_patterns = ['(?:from|import)\s+acme_agent\b']
decorator_patterns = ['(?:^|\.)acme_tool$']
candidate_patterns = ['@acme_tool\b']
confidence = "high"
```

Available fields:

- `source_patterns`: establish repository/source context;
- `decorator_patterns`: identify decorated Python tool functions;
- `registration_patterns`: identify explicit function registration and may use
  `{symbol}` as a placeholder;
- `candidate_patterns`: add candidate discovery at framework entrypoints;
- `languages`: `python`, `javascript_typescript`, or both;
- `confidence`: `high` or `medium`.

Adapter IDs must be unique and may not collide with built-ins. Regular
expressions are compiled during configuration loading, so malformed adapters
fail closed.

## Built-in adapter registry

The current registry covers common entrypoint idioms for MCP/FastMCP,
LangChain, CrewAI, AutoGen, OpenAI Agents SDK, Semantic Kernel, and LlamaIndex.
The registry is deliberately declarative: a new framework should add focused
patterns and deterministic fixtures instead of framework-specific branching
throughout the graph engine.

## Machine-readable contract

```bash
agentsecbench schema framework-coverage
```

The bundled JSON Schema version is independent from the package version. See
`OUTPUT_SCHEMA_COMPATIBILITY.md` for compatibility rules.

## Claim boundary

Coverage diagnostics describe static signals and attached graph evidence. They
do not establish semantic completeness, vulnerability presence or absence,
runtime reachability, or guard effectiveness.
