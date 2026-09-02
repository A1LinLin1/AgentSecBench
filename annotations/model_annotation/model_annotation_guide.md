# AgentSecBench Model Annotation Guide

## Unit of analysis

One task represents one candidate behavior category in one symbol and source
file at a frozen Git commit. Judge only that candidate. Multiple tasks can refer
to the same file.

## Decisions

1. `behavior_confirmed`: whether the detected operation is real rather than a
   syntactic, import-only, documentation, or otherwise non-operative match.
2. `agent_relevant`: whether it implements an agent capability or lies on an
   agent-controlled execution path. Build/release scripts and unrelated tests
   are usually not agent-relevant unless the supplied code establishes that path.
3. Source/dependency: whether an external or less-trusted source has a traceable
   data or control dependency to the effect. Co-location is not a dependency.
4. Trust boundary: whether the path crosses from a less-trusted principal or
   data domain into a more privileged component or external side effect.
5. Guards: mechanisms that constrain the relevant path, such as authorization,
   validation, allowlisting, confirmation, sandboxing, escaping, or destination
   restriction. Logging, comments, exception handling, and type hints are not
   guards by themselves.
6. Security conclusion: a real security-critical behavior can be legitimate and
   well guarded. A weakness requires a security-relevant deficiency. A confirmed
   vulnerability requires evidence of an externally reachable violation and
   security impact; an API match alone is insufficient.

Use `uncertain` or `unknown` whenever the provided context cannot support a firm
decision. Set `vulnerability_status` to `not_assessed` when exploitability is not
assessable, `candidate` when evidence supports further investigation,
`confirmed` only when the definition above is met, and `rejected` when the
candidate is contradicted by the evidence.

The rationale should cite the most relevant supplied line numbers. Do not invent
missing call sites, configurations, threat actors, or data flows.

## Operational definitions

### Effect type

- Classify the primary operation represented by the candidate, not incidental
  side effects.
- `subprocess`, `os.system`, shell, process-spawn, and equivalent APIs are
  `command_execution`, even when the executable is Git, Docker, or another
  external tool.
- `external_tool_invocation` is reserved for agent/tool-framework dispatch when
  no more specific effect type applies.
- Use `filesystem_write` only when the candidate operation itself writes a file;
  do not infer it from the possible behavior of a spawned process.
- If `behavior_confirmed=false`, use `effect_type=none`.

### Source and dependency

- `source_type` identifies the origin of the value that influences the relevant
  effect target, arguments, content, or control decision.
- Use `internal_constant` for fixed literals, module constants, or paths derived
  only from trusted program location. Use `none` when no runtime value is
  relevant. Do not select `user_prompt` merely because user input occurs
  elsewhere in the same function.
- Configuration or environment values are `environment_config`. Their external
  trust status is `unknown` unless the supplied context proves their caller or
  provenance.
- `dependency_confirmed=true` requires a visible data/control path from an
  external or less-trusted source to the effect. Use `partial` for a visible but
  incomplete path, `unknown` when required context is absent, and `false` when
  the supplied code establishes no such path. Never hypothesize an unseen
  caller to create a dependency.

### Trust boundary and guards

- A host-side effect alone is not a trust-boundary crossing. The supplied code
  must also establish a less-trusted source or principal reaching it; otherwise
  use `unknown` or `false` as supported by the evidence.
- Passing a subprocess argument vector without shell interpretation may be an
  `escaping` guard against shell metacharacter injection. A fixed finite set of
  allowed executables, subcommands, paths, or destinations is an `allowlist`.
- Do not count Docker as a `sandbox` guard for the operation that launches or
  configures Docker itself. Do not count exception handling, timeouts, logging,
  or `check=True` as security guards.
- If `guard_present=false`, `guard_types` must be empty and
  `guard_effective=not_applicable`. If `guard_present=true`, provide at least one
  guard type and assess its effectiveness for the relevant path.

### Security conclusion

- `weakness_present=true` requires a security-relevant deficiency supported by
  supplied evidence. A configurable executable or image is not a weakness by
  itself when caller provenance is absent.
- Use `vulnerability_status=not_assessed` when material reachability, provenance,
  privilege, or impact context is missing. Use `candidate` only when the supplied
  evidence supports at least a partial plausible exploit path; do not use it for
  a purely hypothetical unseen configuration source.
- `confirmed` requires `weakness_present=true`, a confirmed less-trusted
  dependency, a confirmed trust-boundary crossing, and supported impact.
- Material missing context normally precludes `label_confidence=high` for the
  affected security conclusion.

## Cross-field consistency

- `dependency_confirmed=false` implies `trust_boundary_crossed=false` for this
  task's candidate path.
- `vulnerability_status=confirmed` requires `weakness_present=true`,
  `dependency_confirmed=true`, and `trust_boundary_crossed=true`.
- `agent_relevant=false` does not imply `behavior_confirmed=false`; maintenance
  scripts and tests can contain real effects outside an agent path.

## JSON shape example

Return the same fields and JSON value types as this shape; replace every value
with the task-specific judgment:

```json
{"task_id":"AT-0000","candidate_id":"example","behavior_confirmed":"true","agent_relevant":"false","source_type":"internal_constant","source_external":"false","dependency_confirmed":"false","trust_boundary_crossed":"false","effect_type":"command_execution","effect_target":"fixed local command","guard_present":"true","guard_types":["allowlist","escaping"],"guard_effective":"yes","weakness_present":"false","vulnerability_status":"rejected","label_confidence":"high","evidence_line_numbers":[10],"missing_context":"","rationale":"Line 10 executes a fixed argument-vector command outside an agent path."}
```
