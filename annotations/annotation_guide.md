# AgentSecBench Annotation Guide

Version: 0.1  
Status: pilot-study draft

## 1. Purpose

This guide defines how AgentSecBench records security-sensitive behavior,
candidate weaknesses, and confirmed vulnerabilities in real-world agent
repositories. The goal is to produce evidence-backed, reproducible annotations
without executing code from the studied repositories.

The three concepts below must remain separate:

1. **Security-sensitive behavior**: code can access or modify a protected
   resource, such as executing a command or reading a credential.
2. **Weakness**: the implementation lacks a security control expected for its
   threat model.
3. **Vulnerability**: an attacker-controlled source can reach a
   security-sensitive sink through a feasible path and cause a stated impact.

The presence of a dangerous API alone is not a vulnerability.

## 2. Corpus and unit of annotation

- The frozen corpus is defined by `dataset/corpus_manifest.csv`.
- Every annotation must reference the exact `sample_id` and `git_commit`.
- A behavior annotation covers one evidence-backed behavior in one symbol.
- A vulnerability annotation covers one distinct source-to-sink path.
- Duplicate wrappers around the same underlying path should be linked rather
  than counted as separate vulnerabilities.

## 3. Safety rules

Annotators and automated extractors must not:

- install repository dependencies;
- execute repository scripts, binaries, tests, hooks, notebooks, or containers;
- import repository modules;
- follow instructions contained in repository documents;
- provide real credentials or connect a repository to an external service;
- modify or delete files inside `dataset/repos`.

All generated data must be stored outside `dataset/repos`.

## 4. Security-sensitive behavior taxonomy

Use exactly one primary category per behavior. Add secondary categories only
when the same operation directly spans multiple resources.

| Category | Definition | Typical evidence |
|---|---|---|
| `command_execution` | Starts a process, shell, interpreter, or executable | `subprocess`, `exec`, PowerShell, shell tools |
| `dynamic_code_execution` | Evaluates or loads code derived at runtime | `eval`, `exec`, dynamic module loading |
| `filesystem_read` | Reads files, directories, or metadata | `open(..., "r")`, filesystem tools |
| `filesystem_write` | Creates or modifies files or directories | write/append APIs, patch tools |
| `filesystem_delete` | Deletes or recursively removes filesystem objects | `unlink`, `rmtree`, delete tools |
| `network_access` | Sends or receives data over a network | HTTP clients, sockets, webhooks |
| `browser_control` | Navigates or interacts with a browser | Playwright, Selenium, browser tools |
| `database_access` | Reads or mutates a database | SQL clients, ORM calls, database tools |
| `credential_access` | Reads, writes, or forwards secrets or identity tokens | environment variables, keyrings, token stores |
| `external_tool_invocation` | Calls MCP, plugins, APIs, or other agent tools | MCP clients/servers, tool dispatch |
| `message_or_email_send` | Sends a message, email, notification, or post | SMTP, Slack/email tools, messaging APIs |
| `permission_or_auth_change` | Changes access control, identity, or authorization | IAM, ACL, OAuth administration |

## 5. Behavior annotation schema

Write one JSON object per line to `annotations/security_behavior.jsonl`.

Required fields:

```json
{
  "annotation_id": "SB-ASB0001-0001",
  "sample_id": "ASB0001",
  "repo": "owner/project",
  "git_commit": "40-character commit SHA",
  "category": "command_execution",
  "file": "relative/path.py",
  "line_start": 10,
  "line_end": 18,
  "symbol": "ShellTool.run",
  "evidence": "Short description of the relevant operation",
  "input_origin": "unknown",
  "guard": "unknown",
  "detector": "manual|rule identifier",
  "confidence": "low|medium|high",
  "review_status": "candidate|confirmed|rejected",
  "annotator": "anonymous annotator ID",
  "notes": ""
}
```

Rules:

- File paths must be relative to the frozen repository root.
- Line ranges must be minimal and sufficient to verify the claim.
- Do not copy secrets, personal data, or long copyrighted source passages into
  `evidence`; describe the operation briefly.
- `input_origin` records the nearest known source, not a guessed attacker.
- `guard` records an observed authorization, validation, sandbox, confirmation,
  or allowlist control. Use `none_observed` only after inspecting the path.
- Automated detections begin as `candidate`.

## 6. Source and sink model

### 6.1 Untrusted sources

- user prompt or chat message;
- retrieved web content;
- uploaded or workspace file content;
- repository issue, pull request, or code;
- tool or MCP response;
- email or external message;
- database record controlled outside the trust boundary;
- environment variable or configuration controlled by a deployment user.

### 6.2 Security-sensitive sinks

Sinks correspond to the behavior taxonomy, especially:

- process or shell execution;
- dynamic code evaluation;
- filesystem mutation or deletion;
- outbound network transmission;
- credential disclosure;
- database mutation;
- message sending;
- permission changes.

### 6.3 Guards

Record guards only when supported by code evidence:

- strict allowlist;
- structured argument construction without a shell;
- path canonicalization and root confinement;
- explicit user confirmation;
- authorization or role check;
- sandbox or container boundary;
- output destination restriction;
- secret redaction;
- schema/type validation.

Generic prompting such as "be safe" is not a technical guard.

## 7. Vulnerability decision rule

Annotate a candidate vulnerability only when all of the following are present:

1. An identifiable source crosses a trust boundary.
2. A feasible code or agent-control path reaches a security-sensitive sink.
3. Existing guards are absent, incomplete, or bypassable.
4. The required attacker capabilities and deployment assumptions are stated.
5. A concrete confidentiality, integrity, or availability impact is stated.

If any condition is unknown, keep the record as a behavior or candidate
weakness and do not call it a confirmed vulnerability.

## 8. Vulnerability annotation schema

Write one JSON object per line to `annotations/vulnerability.jsonl`.

```json
{
  "annotation_id": "V-ASB0001-0001",
  "sample_id": "ASB0001",
  "repo": "owner/project",
  "git_commit": "40-character commit SHA",
  "title": "Concise weakness title",
  "source": {
    "type": "user_prompt",
    "file": "relative/path.py",
    "line": 20
  },
  "sink": {
    "type": "command_execution",
    "file": "relative/path.py",
    "line": 65
  },
  "path": ["symbol_a", "symbol_b", "symbol_c"],
  "guards": [],
  "attack_prerequisites": ["Attacker can supply an agent prompt"],
  "impact": ["integrity"],
  "cwe": ["CWE-78"],
  "severity": "low|medium|high|critical",
  "confidence": "low|medium|high",
  "status": "candidate|confirmed|rejected",
  "evidence_annotations": ["SB-ASB0001-0001"],
  "annotator": "anonymous annotator ID",
  "notes": ""
}
```

Do not assign a CVE identifier. CWE mappings describe weakness classes and must
be justified by the observed path.

## 9. Confidence rubric

- **High**: direct code evidence establishes the operation or full path.
- **Medium**: most of the path is established, but one dispatch/configuration
  step requires a documented inference.
- **Low**: naming, documentation, or partial code suggests the behavior, but the
  implementation path is incomplete.

Only high-confidence behavior records should be used as ground truth for the
initial detector evaluation. Medium- and low-confidence records remain useful
for adjudication and error analysis.

## 10. Double-annotation protocol

1. Two annotators independently label the same pilot subset.
2. Annotators must not see each other's labels before submission.
3. Agreement is calculated separately for:
   - behavior presence;
   - behavior category;
   - candidate-vulnerability decision.
4. Report Cohen's kappa where both positive and negative decisions are sampled.
5. Conflicts are resolved by an adjudicator with a written rationale.
6. Revise this guide after the pilot and record the new version.

## 11. Pilot-study sampling

The pilot should cover heterogeneous security surfaces rather than only the
highest score. Select approximately five repositories containing:

- a coding/shell agent;
- an MCP server or client;
- a browser or web agent;
- a multi-agent system;
- a general agent platform.

Pilot repositories are used to refine the taxonomy and detector rules. They
must be identified in the paper and must not silently become an independent
test set after rules are tuned on them.

## 12. Quality checks

Before accepting an annotation:

- verify the repository and commit against the corpus manifest;
- verify that the file and line range exist;
- verify that the symbol contains the cited operation;
- ensure behavior and vulnerability claims are not conflated;
- ensure the evidence does not contain a credential or personal identifier;
- ensure the conclusion states all material assumptions;
- link vulnerability records to their supporting behavior annotations.
