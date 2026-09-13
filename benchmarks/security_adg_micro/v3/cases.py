"""Framework-adaptive microbenchmark cases for Security-ADG v2.5.

These fixtures validate the framework normalization layer.  They are
mechanism tests, not vulnerability cases.
"""

CASES = [
    {
        "id": "FW-PY-01-mcp-tool",
        "language": "python",
        "symbol": "shell",
        "evidence_lines": [5],
        "source": "from mcp.server.fastmcp import FastMCP\nimport subprocess\nmcp = FastMCP('demo')\n@mcp.tool()\ndef shell(command: str):\n    return subprocess.run(command)\n",
        "expected": {"source_symbols": ["command"], "source_types": ["agent_tool_parameter"], "frameworks": ["MCP"], "dependency": True, "guard_kinds": []},
    },
    {
        "id": "FW-PY-02-langchain-tool",
        "language": "python",
        "symbol": "shell",
        "evidence_lines": [4],
        "source": "from langchain.tools import Tool\nimport subprocess\ndef shell(command: str):\n    return subprocess.run(command)\ntool = Tool(name='shell', func=shell)\n",
        "expected": {"source_symbols": ["command"], "source_types": ["agent_tool_parameter"], "frameworks": ["LangChain"], "dependency": True, "guard_kinds": []},
    },
    {
        "id": "FW-PY-03-crewai-basetool",
        "language": "python",
        "symbol": "_run",
        "evidence_lines": [5],
        "source": "from crewai.tools import BaseTool\nimport subprocess\nclass ShellTool(BaseTool):\n    def _run(self, command: str):\n        return subprocess.run(command)\n",
        "expected": {"source_symbols": ["command"], "source_types": ["agent_tool_parameter"], "frameworks": ["CrewAI"], "dependency": True, "guard_kinds": []},
    },
    {
        "id": "FW-PY-04-autogen-registration",
        "language": "python",
        "symbol": "run_code",
        "evidence_lines": [3],
        "source": "import subprocess\ndef run_code(code: str):\n    return subprocess.run(code)\nassistant.register_for_llm()(run_code)\nexecutor.register_for_execution()(run_code)\n",
        "expected": {"source_symbols": ["code"], "source_types": ["agent_tool_parameter"], "frameworks": ["AutoGen"], "dependency": True, "guard_kinds": []},
    },
    {
        "id": "FW-PY-05-openai-agents",
        "language": "python",
        "symbol": "write_file",
        "evidence_lines": [4],
        "source": "from agents import function_tool\nfrom pathlib import Path\n@function_tool\ndef write_file(path: str, content: str):\n    return Path(path).write_text(content)\n",
        "expected": {"source_symbols": ["content", "path"], "source_types": ["agent_tool_parameter"], "frameworks": ["OpenAI Agents SDK"], "dependency": True, "guard_kinds": []},
    },
    {
        "id": "FW-PY-06-semantic-kernel",
        "language": "python",
        "symbol": "fetch",
        "evidence_lines": [4],
        "source": "from semantic_kernel.functions import kernel_function\nimport requests\n@kernel_function\ndef fetch(url: str):\n    return requests.get(url)\n",
        "expected": {"source_symbols": ["url"], "source_types": ["agent_tool_parameter"], "frameworks": ["Semantic Kernel"], "dependency": True, "guard_kinds": []},
    },
    {
        "id": "FW-PY-07-llamaindex",
        "language": "python",
        "symbol": "read_file",
        "evidence_lines": [4],
        "source": "from llama_index.core.tools import FunctionTool\nfrom pathlib import Path\ndef read_file(path: str):\n    return Path(path).read_text()\ntool = FunctionTool.from_defaults(fn=read_file)\n",
        "expected": {"source_symbols": ["path"], "source_types": ["agent_tool_parameter"], "frameworks": ["LlamaIndex"], "dependency": True, "guard_kinds": []},
    },
    {
        "id": "FW-TS-01-mcp-server-tool",
        "language": "typescript",
        "symbol": "shell",
        "evidence_lines": [2],
        "source": "function shell(command: string) {\n  return spawn(command);\n}\nserver.tool('shell', shell);\n",
        "expected": {"source_symbols": ["command"], "source_types": ["agent_tool_parameter"], "frameworks": ["MCP"], "dependency": True, "guard_kinds": []},
    },
]
