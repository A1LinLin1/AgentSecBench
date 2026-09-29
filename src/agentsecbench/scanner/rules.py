"""Frozen lexical and AST-assisted candidate rules.

These rules intentionally mirror ``scripts/static_scan.py`` while the paper
artifact remains frozen. A contract test prevents silent drift until the
legacy script can become a thin package wrapper.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass

from agentsecbench.frameworks import FrameworkAdapter


SOURCE_EXTENSIONS = {
    ".c", ".cc", ".cpp", ".cs", ".go", ".java", ".js", ".jsx", ".kt",
    ".kts", ".mjs", ".php", ".py", ".rb", ".rs", ".scala", ".sh",
    ".swift", ".ts", ".tsx",
}


@dataclass(frozen=True)
class Rule:
    category: str
    detector: str
    pattern: re.Pattern[str]
    confidence: str
    evidence: str


def rule(category: str, detector: str, pattern: str, confidence: str, evidence: str) -> Rule:
    return Rule(category, detector, re.compile(pattern, re.IGNORECASE), confidence, evidence)


RULES = [
    rule("command_execution", "py_subprocess", r"\bsubprocess\.(run|Popen|call|check_call|check_output)\s*\(", "high", "Python subprocess invocation"),
    rule("command_execution", "py_os_system", r"\bos\.(system|popen|spawn[a-z_]*|exec[a-z_]*)\s*\(", "high", "Python operating-system process invocation"),
    rule("command_execution", "js_child_process", r"\b(exec|execFile|spawn|fork)(Sync)?\s*\(", "medium", "JavaScript or TypeScript process invocation candidate"),
    rule("command_execution", "rust_command", r"\b(Command|TokioCommand)::new\s*\(", "high", "Rust process invocation"),
    rule("command_execution", "go_exec_command", r"\bexec\.Command(Context)?\s*\(", "high", "Go process invocation"),
    rule("command_execution", "dotnet_process", r"\bProcess\.(Start|StartAsync)\s*\(", "high", ".NET process invocation"),
    rule("command_execution", "shell_interpreter", r"\b(powershell|pwsh|cmd\.exe|/bin/(ba)?sh|bash\s+-c|sh\s+-c)\b", "medium", "Shell interpreter reference"),
    rule("dynamic_code_execution", "py_eval_exec", r"(?<![\w.])(?<!def\s)(?<!class\s)(eval|exec|compile)\s*\(", "high", "Python dynamic code evaluation"),
    rule("dynamic_code_execution", "js_eval_function", r"(?<![\w.])(eval\s*\(|new\s+Function\s*\(|vm\.runIn)", "high", "JavaScript dynamic code evaluation"),
    rule("filesystem_read", "py_file_read", r"\b(read_text|read_bytes|open)\s*\([^\n]*(?:['\"]r[b+t]?['\"]|encoding\s*=)", "medium", "Python file-read operation"),
    rule("filesystem_read", "js_file_read", r"\b(readFile|readFileSync|createReadStream)\s*\(", "high", "JavaScript or TypeScript file-read operation"),
    rule("filesystem_write", "py_file_write", r"\b(write_text|write_bytes)\s*\(|\bopen\s*\([^\n]*['\"][wax][b+t]?['\"]", "high", "Python file-write operation"),
    rule("filesystem_write", "js_file_write", r"\b(writeFile|writeFileSync|appendFile|createWriteStream)\s*\(", "high", "JavaScript or TypeScript file-write operation"),
    rule("filesystem_delete", "py_file_delete", r"\b(os\.(remove|unlink|rmdir)|shutil\.rmtree|Path\([^\n]*\)\.(unlink|rmdir))\s*\(", "high", "Python filesystem deletion"),
    rule("filesystem_delete", "js_file_delete", r"\b(rm|rmSync|unlink|unlinkSync|rmdir|rmdirSync)\s*\(", "medium", "JavaScript or TypeScript filesystem deletion candidate"),
    rule("network_access", "py_http_client", r"\b(requests|httpx|aiohttp)\.(get|post|put|patch|delete|request|stream)\s*\(", "high", "Python HTTP client request"),
    rule("network_access", "js_http_client", r"\b(fetch|axios\.(get|post|put|patch|delete|request)|got\.(get|post|put|delete))\s*\(", "high", "JavaScript or TypeScript HTTP request"),
    rule("network_access", "socket_api", r"\b(socket\.(socket|create_connection)|TcpStream::connect|net\.connect)\s*\(", "high", "Direct socket connection"),
    rule("browser_control", "browser_framework", r"\b(playwright|selenium|puppeteer|chromium\.(launch|connect)|webdriver)\b", "medium", "Browser automation framework reference"),
    rule("database_access", "database_client", r"\b(sqlite3|sqlalchemy|psycopg|asyncpg|pymongo|mongoose|prisma|create_engine|execute_query)\b", "medium", "Database client or query API reference"),
    rule("credential_access", "environment_secret", r"\b(os\.(getenv|environ)|process\.env|Environment\.GetEnvironmentVariable)\b[^\n]*(key|token|secret|password|credential|auth)", "high", "Credential-like environment access"),
    rule("credential_access", "secret_store", r"\b(keyring|keychain|secretmanager|secretsmanager|vault)\b", "medium", "Secret-store access candidate"),
    rule("external_tool_invocation", "mcp_tool_definition", r"(@(?:mcp|server)\.tool|FastMCP\s*\(|\bTool\s*\(|registerTool\s*\(|\.tool\s*\()", "high", "MCP or agent tool definition"),
    rule("external_tool_invocation", "langchain_tool_definition", r"(@tool\b|\bTool\s*\(|\bStructuredTool\.from_function\s*\(|\bcreate_react_agent\s*\(|\binitialize_agent\s*\()", "high", "LangChain tool or agent-tool binding"),
    rule("external_tool_invocation", "crewai_tool_definition", r"(@tool\b|\bBaseTool\b|\bAgent\s*\([^)]*tools\s*=|\bCrew\s*\([^)]*agents\s*=)", "medium", "CrewAI tool or agent binding"),
    rule("external_tool_invocation", "autogen_tool_registration", r"\b(register_for_llm|register_for_execution|register_function)\s*\(", "high", "AutoGen tool registration"),
    rule("external_tool_invocation", "openai_agents_tool_definition", r"(@function_tool\b|\bfunction_tool\s*\(|\bAgent\s*\([^)]*tools\s*=|\bRunner\.run\s*\()", "high", "OpenAI Agents SDK tool or agent execution"),
    rule("external_tool_invocation", "semantic_kernel_tool_definition", r"(@kernel_function\b|\bkernel_function\s*\(|\badd_plugin\s*\(|\bKernelPlugin\b)", "high", "Semantic Kernel function or plugin registration"),
    rule("external_tool_invocation", "llamaindex_tool_definition", r"\bFunctionTool\.from_defaults\s*\(|\bQueryEngineTool\.from_defaults\s*\(|\bReActAgent\.from_tools\s*\(", "high", "LlamaIndex function tool or agent-tool binding"),
    rule("external_tool_invocation", "mcp_call_tool", r"\b(call_tool|callTool|invoke_tool|invokeTool)\s*\(", "high", "External tool dispatch"),
    rule("message_or_email_send", "message_send", r"\b(send_mail|send_email|sendEmail|send_message|sendMessage|smtp\.send|chat\.postMessage)\s*\(", "high", "Message or email send operation"),
    rule("permission_or_auth_change", "permission_change", r"\b(chmod|chown|setfacl|add_role|assign_role|grant_permission|set_permissions?)\s*\(", "medium", "Permission or authorization change candidate"),
]


SYMBOL_PATTERNS = [
    re.compile(r"^\s*(?:async\s+def|def|class)\s+([A-Za-z_][\w]*)"),
    re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)"),
    re.compile(r"^\s*(?:export\s+)?class\s+([A-Za-z_$][\w$]*)"),
    re.compile(r"^\s*(?:pub\s+)?fn\s+([A-Za-z_][\w]*)"),
    re.compile(r"^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_][\w]*)"),
]


def detector_applies_to_suffix(detector: str, suffix: str) -> bool:
    language_families = {
        "py_": {".py"},
        "js_": {".js", ".jsx", ".mjs", ".ts", ".tsx"},
        "rust_": {".rs"},
        "go_": {".go"},
        "dotnet_": {".cs"},
    }
    for prefix, allowed in language_families.items():
        if detector.startswith(prefix):
            return suffix in allowed
    return True


def python_dynamic_operation_lines(text: str) -> set[int]:
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return set()
    return {
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"eval", "exec", "compile"}
    }


def nearest_symbol(lines: list[str], line_index: int) -> str:
    lower = max(0, line_index - 30)
    for index in range(line_index, lower - 1, -1):
        for pattern in SYMBOL_PATTERNS:
            match = pattern.search(lines[index])
            if match:
                return match.group(1)
    return "<module>"


def rule_signature(rule_item: Rule) -> tuple[str, str, str, int, str, str]:
    """Return a comparable, serialization-safe rule identity."""

    return (
        rule_item.category,
        rule_item.detector,
        rule_item.pattern.pattern,
        rule_item.pattern.flags,
        rule_item.confidence,
        rule_item.evidence,
    )


def adapter_candidate_rules(adapters: tuple[FrameworkAdapter, ...]) -> tuple[Rule, ...]:
    """Compile explicit project adapters into additive entrypoint rules."""

    result = []
    for adapter in adapters:
        prefixes = []
        if "python" in adapter.languages:
            prefixes.append("py_")
        if "javascript_typescript" in adapter.languages:
            prefixes.append("js_")
        for prefix in prefixes:
            for index, pattern in enumerate(adapter.candidate_patterns, 1):
                result.append(
                    rule(
                        "external_tool_invocation",
                        f"{prefix}adapter_{adapter.adapter_id}_{index}",
                        pattern,
                        adapter.confidence,
                        f"{adapter.name} entrypoint matched by project adapter",
                    )
                )
    return tuple(result)
