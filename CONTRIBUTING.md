# Contributing to AgentSecBench

Thank you for helping improve AgentSecBench. Contributions should preserve its
core safety and evidence contracts: analysis is read-only, target code is not
executed, and static candidates are not presented as confirmed vulnerabilities.

## Development setup

```bash
git clone https://github.com/A1LinLin1/AgentSecBench.git
cd AgentSecBench
python -m pip install --no-deps .
python -m unittest discover -s tests
```

Before opening a pull request:

1. Add deterministic tests for behavior changes.
2. Run the complete unit-test suite.
3. Build a wheel with
   `python -m pip wheel . --no-deps --no-build-isolation`.
4. Keep generated analysis results, third-party repositories, credentials, raw
   annotations, and disclosure records out of the commit.
5. Document any output-schema change and follow
   `docs/OUTPUT_SCHEMA_COMPATIBILITY.md`.

## Framework adapters

New framework support should include a narrowly scoped adapter, positive and
negative fixtures, and an explanation of the semantic role represented by each
pattern. Avoid broad name-only patterns that match ordinary application code.

## Reporting analyzer security issues

Do not open a public issue for a vulnerability in AgentSecBench itself. Follow
the private process in `SECURITY.md`.

Potential vulnerabilities found in third-party projects must be coordinated
with those maintainers. Do not attach uncoordinated exploit details to an
AgentSecBench issue or pull request.
