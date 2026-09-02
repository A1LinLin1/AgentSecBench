"""Held-out mechanism probes for Security-ADG after v2.2 development.

These fixtures are intentionally distinct from v1.  They evaluate local
def-use behavior, not real-world vulnerability discovery.  Cases marked as a
known limitation document unsupported constructs and are excluded from the
primary mechanism score.
"""

CASES = [
    {
        "id": "PY-H01-keyword-argument",
        "language": "python",
        "evidence_lines": [3],
        "source": "import subprocess\ndef execute(command):\n    return subprocess.run(args=[command])\n",
        "expected": {"source_symbols": ["command"], "source_types": ["function_parameter"], "dependency": True, "guard_kinds": []},
    },
    {
        "id": "PY-H02-three-hop-chain",
        "language": "python",
        "evidence_lines": [6],
        "source": "import subprocess\ndef execute(request):\n    first = request['command']\n    second = first\n    args = ['-c', second]\n    return subprocess.run(args)\n",
        "expected": {"source_symbols": ["request"], "source_types": ["function_parameter"], "dependency": True, "guard_kinds": []},
    },
    {
        "id": "PY-H03-subscript-extraction",
        "language": "python",
        "evidence_lines": [4],
        "source": "import subprocess\ndef execute(request):\n    command = request['command']\n    return subprocess.run(command)\n",
        "expected": {"source_symbols": ["request"], "source_types": ["function_parameter"], "dependency": True, "guard_kinds": []},
    },
    {
        "id": "PY-H04-fstring-propagation",
        "language": "python",
        "evidence_lines": [4],
        "source": "import subprocess\ndef execute(command):\n    shell = f'echo {command}'\n    return subprocess.run(shell, shell=True)\n",
        "expected": {"source_symbols": ["command"], "source_types": ["function_parameter"], "dependency": True, "guard_kinds": []},
    },
    {
        "id": "PY-H05-overwrite-negative",
        "language": "python",
        "evidence_lines": [4],
        "source": "import subprocess\ndef execute(command):\n    command = 'echo safe'\n    return subprocess.run(command, shell=True)\n",
        "expected": {"source_symbols": [], "source_types": [], "dependency": False, "guard_kinds": []},
    },
    {
        "id": "PY-H06-shadowed-inner-parameter",
        "language": "python",
        "symbol": "inner",
        "evidence_lines": [4],
        "source": "import subprocess\ndef outer(command):\n    def inner(command):\n        return subprocess.run(command)\n    return inner(command)\n",
        "expected": {"source_symbols": ["command"], "source_types": ["function_parameter"], "dependency": True, "guard_kinds": []},
    },
    {
        "id": "PY-H07-unrelated-assert-negative",
        "language": "python",
        "evidence_lines": [5],
        "source": "import subprocess\ndef execute(command, authenticated):\n    assert authenticated\n    value = command\n    return subprocess.run(value)\n",
        "expected": {"source_symbols": ["command"], "source_types": ["function_parameter"], "dependency": True, "guard_kinds": []},
    },
    {
        "id": "PY-H08-attribute-tool-decorator",
        "language": "python",
        "symbol": "execute",
        "evidence_lines": [5],
        "source": "import subprocess\n\n@server.tool\ndef execute(command):\n    return subprocess.run(command)\n",
        "expected": {"source_symbols": ["command"], "source_types": ["agent_tool_parameter"], "dependency": True, "guard_kinds": []},
    },
    {
        "id": "TS-H01-three-hop-chain",
        "language": "typescript",
        "evidence_lines": [5],
        "source": "function execute(request: string) {\n  const first = request;\n  const second = first;\n  const args = ['-c', second];\n  return spawn('sh', args);\n}\n",
        "expected": {"source_symbols": ["request"], "source_types": ["function_parameter"], "dependency": True, "guard_kinds": []},
    },
    {
        "id": "TS-H02-parameter-extractor-precedence",
        "language": "typescript",
        "evidence_lines": [3],
        "source": "function execute(request: any) {\n  const command = request.get('command');\n  return spawn('sh', [command]);\n}\n",
        "expected": {"source_symbols": ["request"], "source_types": ["function_parameter"], "dependency": True, "guard_kinds": []},
    },
    {
        "id": "TS-H03-overwrite-negative",
        "language": "typescript",
        "evidence_lines": [3],
        "source": "function execute(command: string) {\n  command = 'echo safe';\n  return spawn('sh', [command]);\n}\n",
        "expected": {"source_symbols": [], "source_types": [], "dependency": False, "guard_kinds": []},
    },
    {
        "id": "TS-H04-default-parameter",
        "language": "typescript",
        "evidence_lines": [2],
        "source": "function execute(command = 'echo safe') {\n  return spawn('sh', [command]);\n}\n",
        "expected": {"source_symbols": ["command"], "source_types": ["function_parameter"], "dependency": True, "guard_kinds": []},
    },
    {
        "id": "TS-H05-guard-after-chain",
        "language": "typescript",
        "evidence_lines": [4],
        "source": "function execute(command: string) {\n  const args = ['-c', command];\n  if (command) {\n    return spawn('sh', args);\n  }\n}\n",
        "expected": {"source_symbols": ["command"], "source_types": ["function_parameter"], "dependency": True, "guard_kinds": ["preceding_related_if"]},
    },
    {
        "id": "TS-H06-global-json-source",
        "language": "typescript",
        "evidence_lines": [3],
        "source": "function execute() {\n  const command = request.json();\n  return spawn('sh', [command]);\n}\n",
        "expected": {"source_symbols": ["command"], "source_types": ["source_api"], "dependency": True, "guard_kinds": []},
    },
    {
        "id": "TS-L01-arrow-function",
        "language": "typescript",
        "evidence_lines": [2],
        "known_limitation": "arrow-function parameter parsing is outside the lexical TypeScript contract",
        "source": "const execute = (command: string) => {\n  return spawn('sh', [command]);\n};\n",
        "expected": {"source_symbols": ["command"], "source_types": ["function_parameter"], "dependency": True, "guard_kinds": []},
    },
    {
        "id": "TS-L02-destructuring",
        "language": "typescript",
        "evidence_lines": [3],
        "known_limitation": "object-destructuring assignment is outside the lexical TypeScript contract",
        "source": "function execute(request: any) {\n  const { command } = request;\n  return spawn('sh', [command]);\n}\n",
        "expected": {"source_symbols": ["request"], "source_types": ["function_parameter"], "dependency": True, "guard_kinds": []},
    },
    {
        "id": "TS-L03-typed-assignment",
        "language": "typescript",
        "evidence_lines": [3],
        "known_limitation": "typed local assignment is outside the lexical TypeScript assignment contract",
        "source": "function execute() {\n  const command: string = request.json();\n  return spawn('sh', [command]);\n}\n",
        "expected": {"source_symbols": ["command"], "source_types": ["source_api"], "dependency": True, "guard_kinds": []},
    },
]
