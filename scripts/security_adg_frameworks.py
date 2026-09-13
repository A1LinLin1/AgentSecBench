"""Framework-adaptive normalization for Security-ADG construction.

The functions in this module do not create graph nodes directly.  They turn
framework-specific agent/tool idioms into a small, framework-agnostic semantic
record that the dataflow and graph builders can attach to sources and symbols.
"""

from __future__ import annotations

import ast
import re
import warnings
from dataclasses import dataclass, asdict


@dataclass(frozen=True)
class FrameworkEvidence:
    framework: str
    semantic_role: str
    symbol: str
    line: int
    confidence: str
    matched_pattern: str
    parameters: tuple[str, ...]

    def to_dict(self) -> dict:
        payload = asdict(self)
        payload["parameters"] = list(self.parameters)
        return payload


def parse_python_safely(text: str) -> ast.AST:
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", SyntaxWarning)
        return ast.parse(text)


def dotted_name(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return dotted_name(node.func)
    return ""


def call_names(tree: ast.AST) -> list[str]:
    return [dotted_name(node.func) for node in ast.walk(tree) if isinstance(node, ast.Call)]


def imported_names(tree: ast.AST) -> set[str]:
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                names.add(alias.name.split(".", 1)[0])
                if alias.asname:
                    names.add(alias.asname)
        elif isinstance(node, ast.ImportFrom):
            module = node.module or ""
            if module:
                names.add(module.split(".", 1)[0])
            for alias in node.names:
                names.add(alias.asname or alias.name)
    return names


def function_parameters(function: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, ...]:
    args = function.args
    params = [
        item.arg
        for item in [*args.posonlyargs, *args.args, *args.kwonlyargs]
        if item.arg not in {"self", "cls"}
    ]
    if args.vararg:
        params.append(args.vararg.arg)
    if args.kwarg:
        params.append(args.kwarg.arg)
    return tuple(params)


def decorator_names(function: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    return [dotted_name(decorator) for decorator in function.decorator_list]


def enclosing_class(tree: ast.AST, function: ast.FunctionDef | ast.AsyncFunctionDef) -> ast.ClassDef | None:
    return next(
        (
            node
            for node in ast.walk(tree)
            if isinstance(node, ast.ClassDef)
            and node.lineno <= function.lineno <= getattr(node, "end_lineno", node.lineno)
        ),
        None,
    )


def class_base_names(class_node: ast.ClassDef | None) -> set[str]:
    if class_node is None:
        return set()
    return {dotted_name(base) for base in class_node.bases}


def function_registered_by_call(tree: ast.AST, function_name: str, call_suffixes: tuple[str, ...]) -> tuple[str, int] | None:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = dotted_name(node.func)
        if not any(name.endswith(suffix) for suffix in call_suffixes):
            continue
        argument_names = {
            arg.id
            for arg in node.args
            if isinstance(arg, ast.Name)
        }
        argument_names.update(
            kw.value.id
            for kw in node.keywords
            if isinstance(kw.value, ast.Name)
        )
        if function_name in argument_names:
            return name, node.lineno
    return None


def function_referenced_by_factory(tree: ast.AST, function_name: str, factory_suffixes: tuple[str, ...]) -> tuple[str, int] | None:
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        name = dotted_name(node.func)
        if not any(name.endswith(suffix) for suffix in factory_suffixes):
            continue
        for keyword in node.keywords:
            if keyword.arg in {"fn", "func", "function"} and isinstance(keyword.value, ast.Name) and keyword.value.id == function_name:
                return name, node.lineno
        if any(isinstance(arg, ast.Name) and arg.id == function_name for arg in node.args):
            return name, node.lineno
    return None


def module_hint(imports: set[str], text: str, hints: tuple[str, ...]) -> bool:
    lowered = text.lower()
    return any(hint.lower() in lowered for hint in hints) or any(hint in imports for hint in hints)


def detect_python_frameworks(
    text: str,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    tree: ast.AST | None = None,
) -> list[FrameworkEvidence]:
    tree = tree or ast.parse(text)
    imports = imported_names(tree)
    decorators = decorator_names(function)
    params = function_parameters(function)
    evidence: list[FrameworkEvidence] = []

    def add(framework: str, role: str, confidence: str, pattern: str, line: int | None = None) -> None:
        candidate = FrameworkEvidence(
            framework=framework,
            semantic_role=role,
            symbol=function.name,
            line=line or function.lineno,
            confidence=confidence,
            matched_pattern=pattern,
            parameters=params,
        )
        if candidate not in evidence:
            evidence.append(candidate)

    for name in decorators:
        if name.endswith(".tool") or name == "tool":
            if module_hint(imports, text, ("mcp", "FastMCP", "modelcontextprotocol")):
                framework = "MCP"
            elif module_hint(imports, text, ("langchain", "langchain_core")):
                framework = "LangChain"
            elif module_hint(imports, text, ("crewai",)):
                framework = "CrewAI"
            else:
                framework = "GenericTool"
            add(framework, "tool_definition", "high" if framework != "GenericTool" else "medium", f"decorator:{name}")
        if name.endswith("function_tool") or name == "function_tool":
            add("OpenAI Agents SDK", "tool_definition", "high", f"decorator:{name}")
        if name.endswith("kernel_function") or name == "kernel_function":
            add("Semantic Kernel", "tool_definition", "high", f"decorator:{name}")

    cls = enclosing_class(tree, function)
    bases = class_base_names(cls)
    if function.name in {"_run", "run"} and any(base.endswith("BaseTool") for base in bases):
        add("CrewAI", "tool_definition", "high", f"class_base:{','.join(sorted(bases))}", line=cls.lineno if cls else function.lineno)

    registered = function_registered_by_call(tree, function.name, ("register_for_execution", "register_for_llm"))
    if registered:
        add("AutoGen", "tool_definition", "high", f"registration_call:{registered[0]}", line=registered[1])

    langchain_factory = function_referenced_by_factory(tree, function.name, ("Tool", "StructuredTool.from_function", "StructuredTool.from_function"))
    if langchain_factory or any(name.endswith("StructuredTool.from_function") for name in call_names(tree)):
        if langchain_factory:
            add("LangChain", "tool_definition", "high", f"factory_call:{langchain_factory[0]}", line=langchain_factory[1])

    llama_factory = function_referenced_by_factory(tree, function.name, ("FunctionTool.from_defaults", "QueryEngineTool.from_defaults"))
    if llama_factory:
        add("LlamaIndex", "tool_definition", "high", f"factory_call:{llama_factory[0]}", line=llama_factory[1])

    return evidence


TS_FUNCTION = re.compile(
    r"(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)|"
    r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*=>",
    re.MULTILINE,
)


def parse_ts_params(raw: str) -> tuple[str, ...]:
    params = []
    for part in raw.split(","):
        name = re.match(r"\s*(?:\{[^}]+\}|([A-Za-z_$][\w$]*))", part)
        if name and name.group(1) and name.group(1) not in {"this"}:
            params.append(name.group(1))
    return tuple(params)


def detect_typescript_frameworks(text: str, symbol: str | None, target_line: int) -> list[FrameworkEvidence]:
    lines = text.splitlines()
    evidence: list[FrameworkEvidence] = []
    functions = []
    for match in TS_FUNCTION.finditer(text):
        start_line = text[: match.start()].count("\n") + 1
        name = match.group(1) or match.group(3)
        raw_params = match.group(2) or match.group(4) or ""
        functions.append((start_line, name, parse_ts_params(raw_params)))
    candidates = [item for item in functions if item[0] <= target_line and (not symbol or item[1] == symbol)]
    start_line, name, params = max(candidates, default=(target_line, symbol or "<anonymous>", ()), key=lambda item: item[0])

    def add(framework: str, pattern: str, confidence: str = "high") -> None:
        candidate = FrameworkEvidence(framework, "tool_definition", name, start_line, confidence, pattern, params)
        if candidate not in evidence:
            evidence.append(candidate)

    if re.search(r"\b(registerTool|server\.tool|mcp\.tool)\s*\(", text):
        add("MCP", "registerTool/server.tool")
    if re.search(r"\btool\s*\(\s*" + re.escape(name) + r"\b|tools\s*:\s*\[[^\]]*\b" + re.escape(name) + r"\b", text, re.DOTALL):
        add("LangChain", "tool()/tools binding", "medium")
    if re.search(r"\bFunctionTool\.fromDefaults\s*\([^)]*\b" + re.escape(name) + r"\b", text, re.DOTALL):
        add("LlamaIndex", "FunctionTool.fromDefaults")
    return evidence


def detect_frameworks(text: str, file_name: str, symbol: str | None, target_line: int) -> list[dict]:
    suffix = file_name.lower()
    try:
        if suffix.endswith(".py"):
            tree = parse_python_safely(text)
            functions = [
                node
                for node in ast.walk(tree)
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                and node.lineno <= target_line <= getattr(node, "end_lineno", node.lineno)
            ]
            if not functions and symbol and symbol != "<module>":
                functions = [
                    node
                    for node in ast.walk(tree)
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
                    and node.name == symbol
                ]
            if not functions:
                return []
            function = min(functions, key=lambda node: getattr(node, "end_lineno", node.lineno) - node.lineno)
            return [item.to_dict() for item in detect_python_frameworks(text, function, tree)]
    except SyntaxError:
        return []
    if suffix.endswith((".ts", ".tsx", ".js", ".jsx")):
        return [item.to_dict() for item in detect_typescript_frameworks(text, symbol, target_line)]
    return []
