# Interprocedural Security-ADG microbenchmark

This frozen microbenchmark measures the representation delta produced by the
project-level propagation stage. It is intentionally small and hand-authored.
The paired evaluation scans the same files twice, changing only the
`interprocedural` analysis toggle.

Cases:

- `python_positive`: a two-hop MCP tool parameter to `subprocess.run` flow.
- `python_constant`: a constant reaches `subprocess.run`; no agent input source
  should be introduced.
- `typescript_positive`: a two-hop MCP tool parameter to `exec` flow.
- `typescript_constant`: a constant reaches `exec`; no agent input source
  should be introduced.

This benchmark validates graph construction behavior. It is not a vulnerability
ground truth set and does not support precision, recall, or vulnerability-rate
claims.
