# Output schema and compatibility policy

AgentSecBench publishes JSON Schema Draft 2020-12 contracts for its primary
machine-readable outputs. The canonical copies ship inside the Python package
under `agentsecbench.schemas` and can be printed with `agentsecbench schema`.

## Versioning contract

- Every record carries a `schema_version` independent from the package version.
- A schema version remains backward compatible when optional fields are added.
- Removing or renaming a field, changing its type, or strengthening a required
  semantic constraint requires a new schema version.
- JSONL files apply the named schema independently to every non-empty line.
- Consumers should reject unknown major schema versions and ignore unknown
  optional fields only when the corresponding schema permits them.
- Candidate IDs identify one scan result. Stable `ASBFP-...` fingerprints are
  the supported key for baselines and exact suppressions.

## Published schemas

| Name | Output | Version |
|---|---|---:|
| `finding` | `findings.jsonl` | 1.0 |
| `security-adg` | `security-adg.jsonl` | 1.0 |
| `summary` | `summary.json` | 1.0 |
| `policy` | `policy.json` | 1.0 |
| `report-manifest` | `report/manifest.json` | 1.1 |
| `review-export` | Browser-exported `agentsecbench-review.json` | 1.0 |

These schemas describe serialization and interoperability. They do not change
the claim boundary: a valid finding or graph is a static review candidate, not
a confirmed vulnerability.
