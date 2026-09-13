# Held-out Baseline Matching Policy

This policy is fixed before human gold is read. It normalizes every method to the frozen 344-record held-out operation inventory; it does not alter a method's raw result.

## Inventory key

The primary matching key is:

```text
repository + frozen commit + repository-relative file + operation category + line overlap
```

The canonical inventory line is the operation line. A result matches when it has the same frozen repository and repository-relative normalized path, an overlapping source range under the tolerance below, and a compatible category mapping.

## Location tolerance

- A result range that contains the inventory line matches.
- A point result matches when it is within plus or minus two source lines of the inventory line.
- No cross-file matching is permitted.
- Any result matching more than one inventory item is retained as `ambiguous`; it is counted and reported rather than manually assigned.

## Category mapping

Security-ADG uses its emitted operation category. Sink-only predicts every inventory operation positive. Semgrep category labels come from `baselines/semgrep/predefined_sinks_v1.yml`. CodeQL uses a fixed rule-to-task mapping: only security-tagged `path-problem` alerts with an explicit code-flow can support dependency prediction; any security-tagged, location-matched alert can support weakness coverage. Unsupported mappings are recorded as unavailable rather than inferred.

## Prediction semantics

- **Security-ADG dependency**: positive only when the frozen v2.4 graph provides def-use source evidence to the operation.
- **Sink-only operation**: every inventory row is positive. It has no dependency discrimination and therefore predicts every inventory row dependency-positive for the intentionally permissive sink-only comparator.
- **CodeQL dependency**: a matched security `path-problem` with code-flow evidence.
- **Semgrep operation**: a matched predefined sink rule. Semgrep does not claim dependency evidence under this configuration.

Raw tool output, normalized output, matching metadata, and unmatched/ambiguous counts are saved independently. No manual per-item matching, label-aware rule adjustment, or method-specific tolerance is permitted.
