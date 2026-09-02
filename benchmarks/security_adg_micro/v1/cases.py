"""Versioned, label-independent microbenchmark cases for Security-ADG.

Each case has a deliberately small program and a semantic oracle.  ``scored``
cases contribute to engine-mechanism metrics.  ``known_limitation`` cases are
retained as regression probes but excluded from the primary score because their
construct is outside the documented v2.1 analysis contract.
"""

CASES = [
    {
        "id": "PY-01-direct-parameter",
        "language": "python",
        "evidence_lines": [4],
        "source": "import subprocess\n\ndef execute(command):\n    return subprocess.run(command, shell=True)\n",
        "expected": {"source_symbols": ["command"], "source_types": ["function_parameter"], "dependency": True, "guard_kinds": []},
    },
    {
        "id": "PY-02-assignment-chain",
        "language": "python",
        "evidence_lines": [6],
        "source": "import subprocess\n\ndef execute(request):\n    command = request.get('command')\n    args = ['bash', '-lc', command]\n    return subprocess.run(args)\n",
        "expected": {"source_symbols": ["request"], "source_types": ["function_parameter"], "dependency": True, "guard_kinds": []},
    },
    {
        "id": "PY-03-source-api",
        "language": "python",
        "evidence_lines": [6],
        "source": "import os\nimport subprocess\n\ndef execute():\n    command = os.getenv('TASK')\n    return subprocess.run(command)\n",
        "expected": {"source_symbols": ["command"], "source_types": ["source_api"], "dependency": True, "guard_kinds": []},
    },
    {
        "id": "PY-04-constant-negative",
        "language": "python",
        "evidence_lines": [4],
        "source": "import subprocess\n\ndef healthcheck():\n    command = ['echo', 'ok']\n    return subprocess.run(command)\n",
        "expected": {"source_symbols": [], "source_types": [], "dependency": False, "guard_kinds": []},
    },
    {
        "id": "PY-05-tool-entrypoint",
        "language": "python",
        "symbol": "shell_exec",
        "evidence_lines": [5],
        "source": "import subprocess\n\n@mcp.tool()\ndef shell_exec(command: str):\n    return subprocess.Popen(command, shell=True)\n",
        "expected": {"source_symbols": ["command"], "source_types": ["agent_tool_parameter"], "dependency": True, "guard_kinds": []},
    },
    {
        "id": "PY-06-dominating-guard",
        "language": "python",
        "evidence_lines": [5],
        "source": "import subprocess\n\ndef execute(command):\n    if command:\n        return subprocess.run(command)\n    return None\n",
        "expected": {"source_symbols": ["command"], "source_types": ["function_parameter"], "dependency": True, "guard_kinds": ["dominating_if"]},
    },
    {
        "id": "PY-07-unrelated-guard-negative",
        "language": "python",
        "evidence_lines": [8],
        "source": "import subprocess\n\ndef execute(command, approved):\n    if approved:\n        print('audit')\n    else:\n        print('not approved')\n    return subprocess.run(command)\n",
        "expected": {"source_symbols": ["command"], "source_types": ["function_parameter"], "dependency": True, "guard_kinds": []},
    },
    {
        "id": "PY-08-related-assert",
        "language": "python",
        "evidence_lines": [5],
        "source": "import subprocess\n\ndef execute(command):\n    assert command\n    return subprocess.run(command)\n",
        "expected": {"source_symbols": ["command"], "source_types": ["function_parameter"], "dependency": True, "guard_kinds": ["preceding_assert"]},
    },
    {
        "id": "TS-01-direct-parameter",
        "language": "typescript",
        "evidence_lines": [2],
        "source": "function execute(command: string) {\n  return spawn('sh', [command]);\n}\n",
        "expected": {"source_symbols": ["command"], "source_types": ["function_parameter"], "dependency": True, "guard_kinds": []},
    },
    {
        "id": "TS-02-assignment-chain",
        "language": "typescript",
        "evidence_lines": [4],
        "source": "function execute(request: string) {\n  const command = request;\n  const args = ['-c', command];\n  return spawn('sh', args);\n}\n",
        "expected": {"source_symbols": ["request"], "source_types": ["function_parameter"], "dependency": True, "guard_kinds": []},
    },
    {
        "id": "TS-03-constant-negative",
        "language": "typescript",
        "evidence_lines": [3],
        "source": "function healthcheck() {\n  const args = ['echo', 'ok'];\n  return spawn('sh', args);\n}\n",
        "expected": {"source_symbols": [], "source_types": [], "dependency": False, "guard_kinds": []},
    },
    {
        "id": "TS-04-source-api",
        "language": "typescript",
        "evidence_lines": [3],
        "source": "function execute() {\n  const command = request.json();\n  return spawn('sh', [command]);\n}\n",
        "expected": {"source_symbols": ["command"], "source_types": ["source_api"], "dependency": True, "guard_kinds": []},
    },
    {
        "id": "TS-05-related-guard",
        "language": "typescript",
        "evidence_lines": [3],
        "source": "function execute(command: string) {\n  if (command) {\n    return spawn('sh', [command]);\n  }\n}\n",
        "expected": {"source_symbols": ["command"], "source_types": ["function_parameter"], "dependency": True, "guard_kinds": ["preceding_related_if"]},
    },
    {
        "id": "TS-06-unrelated-guard-negative",
        "language": "typescript",
        "evidence_lines": [5],
        "source": "function execute(command: string, approved: boolean) {\n  if (approved) {\n    console.log('audit');\n  }\n  return spawn('sh', [command]);\n}\n",
        "expected": {"source_symbols": ["command"], "source_types": ["function_parameter"], "dependency": True, "guard_kinds": []},
    },
    {
        "id": "TS-07-source-api-chain",
        "language": "typescript",
        "evidence_lines": [4],
        "source": "function execute() {\n  const payload = request.json();\n  const args = ['-c', payload];\n  return spawn('sh', args);\n}\n",
        "expected": {"source_symbols": ["payload"], "source_types": ["source_api"], "dependency": True, "guard_kinds": []},
    },
    {
        "id": "TS-08-related-guard-chain",
        "language": "typescript",
        "evidence_lines": [4],
        "source": "function execute(command: string) {\n  const args = ['-c', command];\n  if (command) {\n    return spawn('sh', args);\n  }\n}\n",
        "expected": {"source_symbols": ["command"], "source_types": ["function_parameter"], "dependency": True, "guard_kinds": ["preceding_related_if"]},
    },
    {
        "id": "TS-L01-template-interpolation",
        "language": "typescript",
        "evidence_lines": [3],
        "known_limitation": "template interpolation is outside the lexical TypeScript contract",
        "source": "function execute(command: string) {\n  const shell = `echo ${command}`;\n  return spawn('sh', [shell]);\n}\n",
        "expected": {"source_symbols": ["command"], "source_types": ["function_parameter"], "dependency": True, "guard_kinds": []},
    },
    {
        "id": "PY-L02-interprocedural-return",
        "language": "python",
        "evidence_lines": [8],
        "known_limitation": "interprocedural return flow is outside the local def-use contract",
        "source": "import subprocess\n\ndef build(command):\n    return command\n\ndef execute(request):\n    command = build(request)\n    return subprocess.run(command)\n",
        "expected": {"source_symbols": ["request"], "source_types": ["function_parameter"], "dependency": True, "guard_kinds": []},
    },
]
