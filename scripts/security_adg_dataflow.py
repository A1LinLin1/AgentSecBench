"""Local, label-independent def-use analyses used by Security-ADG v2."""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass


SOURCE_CALLS = re.compile(
    r"(?:^|\.)(?:getenv|get|get_json|json|read|read_text|read_bytes|readFile|readFileSync|fetch|input|recv|receive)$",
    re.IGNORECASE,
)
IDENTIFIER = re.compile(r"\b[A-Za-z_$][\w$]*\b")
TS_SIGNATURE = re.compile(
    r"(?:async\s+)?(?:function\s+)?([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*(?::[^={]+)?(?:=>)?\s*\{"
)
TS_ASSIGNMENT = re.compile(r"^\s*(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=\s*(.+?);?\s*$")
TS_IF = re.compile(r"^\s*if\s*\((.+)\)")
RESERVED = {
    "await", "true", "false", "null", "undefined", "new", "return", "const", "let", "var",
    "self", "this", "str", "int", "dict", "list", "None", "True", "False",
}


@dataclass
class Analysis:
    engine: str
    operation_line: int
    sources: list[dict]
    guards: list[dict]
    dependency_paths: list[list[str]]
    limitations: list[str]


def dotted_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def loaded_names(node: ast.AST | None) -> set[str]:
    if node is None:
        return set()
    return {item.id for item in ast.walk(node) if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Load)}


def assigned_names(node: ast.AST) -> set[str]:
    targets: list[ast.AST] = []
    if isinstance(node, (ast.Assign, ast.AnnAssign)):
        targets = node.targets if isinstance(node, ast.Assign) else [node.target]
    result = set()
    for target in targets:
        result.update(item.id for item in ast.walk(target) if isinstance(item, ast.Name))
    return result


def call_is_source(node: ast.AST | None) -> tuple[bool, str]:
    if not isinstance(node, ast.Call):
        return False, ""
    name = dotted_name(node.func)
    return bool(SOURCE_CALLS.search(name)), name


def smallest_python_call(tree: ast.AST, evidence_lines: set[int]) -> ast.Call | None:
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and node.lineno in evidence_lines]
    return min(calls, key=lambda node: (getattr(node, "end_lineno", node.lineno) - node.lineno, node.col_offset), default=None)


def enclosing_function(tree: ast.AST, target: ast.AST) -> ast.AST:
    candidates = [
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.lineno <= target.lineno <= getattr(node, "end_lineno", node.lineno)
    ]
    return min(candidates, key=lambda node: getattr(node, "end_lineno", node.lineno) - node.lineno, default=tree)


def tool_decorator(function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    names = [dotted_name(decorator.func) if isinstance(decorator, ast.Call) else dotted_name(decorator) for decorator in function.decorator_list]
    return any(name.endswith(".tool") or name == "tool" for name in names)


def named_python_function(tree: ast.AST, symbol: str | None) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    if not symbol or symbol == "<module>":
        return None
    return next(
        (
            node for node in ast.walk(tree)
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == symbol
        ),
        None,
    )


def call_using_parameters(scope: ast.AST, params: set[str]) -> ast.Call | None:
    """Choose an operation in an MCP/agent tool body that consumes a parameter."""
    candidates = [
        node for node in ast.walk(scope)
        if isinstance(node, ast.Call)
    ]
    # Keep calls whose arguments, not merely callee expressions, consume a tool parameter.
    consuming = [
        node for node in candidates
        if set().union(*(loaded_names(arg) for arg in [*node.args, *(kw.value for kw in node.keywords)])) & params
    ]
    return max(consuming, key=lambda node: node.lineno, default=None)


def analyze_python(
    text: str,
    evidence_lines: list[int],
    symbol: str | None = None,
    prefer_parameter_sources: bool = False,
    respect_parameter_overwrites: bool = False,
    include_intrinsic_source_operation: bool = True,
) -> Analysis:
    try:
        tree = ast.parse(text)
    except SyntaxError as exc:
        return Analysis("python_ast_v1", min(evidence_lines), [], [], [], [f"parse_error:{exc.msg}"])
    call = smallest_python_call(tree, set(evidence_lines))
    if call is None:
        return Analysis("python_ast_v1", min(evidence_lines), [], [], [], ["no_call_on_evidence_line"])
    explicit_scope = named_python_function(tree, symbol)
    scope = explicit_scope or enclosing_function(tree, call)
    parents: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(scope):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent

    params: set[str] = set()
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        args = scope.args
        params = {
            item.arg for item in [*args.posonlyargs, *args.args, *args.kwonlyargs]
            if item.arg not in {"self", "cls"}
        }
        if args.vararg:
            params.add(args.vararg.arg)
        if args.kwarg:
            params.add(args.kwarg.arg)
        if explicit_scope is not None and tool_decorator(scope):
            operation_call = call_using_parameters(scope, params)
            if operation_call is not None:
                call = operation_call

    definitions: dict[str, tuple[ast.AST | None, int]] = {}
    for node in ast.walk(scope):
        if getattr(node, "lineno", call.lineno) >= call.lineno:
            continue
        if isinstance(node, ast.Assign):
            for name in assigned_names(node):
                previous = definitions.get(name)
                if previous is None or previous[1] < node.lineno:
                    definitions[name] = (node.value, node.lineno)
        elif isinstance(node, ast.AnnAssign):
            for name in assigned_names(node):
                previous = definitions.get(name)
                if previous is None or previous[1] < node.lineno:
                    definitions[name] = (node.value, node.lineno)

    target_names = set()
    for argument in [*call.args, *(keyword.value for keyword in call.keywords)]:
        target_names.update(loaded_names(argument))
    sources: list[dict] = []
    paths: list[list[str]] = []
    visited: set[str] = set()

    def trace(name: str, path: list[str]) -> None:
        if name in visited:
            return
        visited.add(name)
        current_path = [*path, name]
        definition = definitions.get(name)
        if name in params and (not respect_parameter_overwrites or definition is None):
            source_type = "agent_tool_parameter" if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)) and tool_decorator(scope) else "function_parameter"
            trust = "agent_or_external_caller" if source_type == "agent_tool_parameter" else "unknown"
            sources.append({"source_type": source_type, "symbol": name, "line": scope.lineno, "trust": trust})
            paths.append(current_path)
            return
        if definition is None:
            return
        value, line = definition
        is_source, api = call_is_source(value)
        dependencies = sorted(loaded_names(value))
        # A call such as request.get("command") is an extractor applied to an
        # already modelled parameter, not an independent second trust source.
        # v2.1 retains both candidates for reproducibility; v2.2 keeps the
        # parameter source when explicitly requested by the caller.
        parameter_backed = bool(set(dependencies) & params)
        if is_source and not (prefer_parameter_sources and parameter_backed):
            sources.append({"source_type": "source_api", "symbol": name, "api": api, "line": line, "trust": "less_trusted_or_unknown"})
            paths.append(current_path)
        # Preserve a parameter source for transformations such as
        # ``command = sanitize(command)`` while treating a constant overwrite
        # as a local value with no parameter dependency.
        if name in params and respect_parameter_overwrites and name in dependencies:
            source_type = "agent_tool_parameter" if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)) and tool_decorator(scope) else "function_parameter"
            trust = "agent_or_external_caller" if source_type == "agent_tool_parameter" else "unknown"
            sources.append({"source_type": source_type, "symbol": name, "line": scope.lineno, "trust": trust})
            paths.append(current_path)
        for dependency in dependencies:
            if dependency != name:
                trace(dependency, current_path)

    for name in sorted(target_names):
        trace(name, [dotted_name(call.func) or "operation"])
    intrinsic, intrinsic_api = call_is_source(call)
    if intrinsic and include_intrinsic_source_operation:
        sources.append({"source_type": "intrinsic_source_operation", "symbol": intrinsic_api, "line": call.lineno, "trust": "less_trusted_or_unknown"})
        paths.append([intrinsic_api])

    guards = []
    ancestor = call
    while ancestor in parents:
        ancestor = parents[ancestor]
        if isinstance(ancestor, ast.If):
            guards.append({
                "line": ancestor.lineno,
                "kind": "dominating_if",
                "symbols": sorted(loaded_names(ancestor.test)),
                "confidence": "structural",
            })
    relevant = visited | target_names
    for node in ast.walk(scope):
        if isinstance(node, ast.Assert) and node.lineno < call.lineno and loaded_names(node.test) & relevant:
            guards.append({
                "line": node.lineno,
                "kind": "preceding_assert",
                "symbols": sorted(loaded_names(node.test) & relevant),
                "confidence": "def_use_related",
            })
    unique_sources = list({(item["source_type"], item["symbol"], item["line"]): item for item in sources}.values())
    unique_guards = list({(item["kind"], item["line"]): item for item in guards}.values())
    return Analysis("python_ast_v1", call.lineno, unique_sources, unique_guards, paths, [])


def ts_function_start(lines: list[str], target_index: int) -> tuple[int, set[str]]:
    for index in range(target_index, max(-1, target_index - 120), -1):
        match = TS_SIGNATURE.search(lines[index])
        if match and match.group(1) not in {"if", "for", "while", "switch", "catch", "with"}:
            params = {
                IDENTIFIER.search(part.strip()).group(0)
                for part in match.group(2).split(",")
                if IDENTIFIER.search(part.strip())
            }
            return index, params - RESERVED
    return max(0, target_index - 80), set()


def identifiers(expression: str) -> set[str]:
    strings_removed = re.sub(r"(['\"`]).*?\1", "", expression)
    return {name for name in IDENTIFIER.findall(strings_removed) if name not in RESERVED and not name.isupper()}


def analyze_typescript(
    text: str,
    evidence_lines: list[int],
    prefer_parameter_sources: bool = False,
    respect_parameter_overwrites: bool = False,
) -> Analysis:
    lines = text.splitlines()
    target_index = min(evidence_lines) - 1
    start, params = ts_function_start(lines, target_index)
    target = " ".join(lines[index - 1] for index in evidence_lines if 1 <= index <= len(lines))
    opening = target.find("(")
    target_expression = target[opening + 1 :] if opening >= 0 else target
    target_names = identifiers(target_expression)
    definitions: dict[str, tuple[str, int]] = {}
    for index in range(start, target_index):
        match = TS_ASSIGNMENT.match(lines[index])
        if match:
            definitions[match.group(1)] = (match.group(2), index + 1)

    sources: list[dict] = []
    paths: list[list[str]] = []
    visited: set[str] = set()

    def trace(name: str, path: list[str]) -> None:
        if name in visited:
            return
        visited.add(name)
        current_path = [*path, name]
        definition = definitions.get(name)
        if name in params and (not respect_parameter_overwrites or definition is None):
            sources.append({"source_type": "function_parameter", "symbol": name, "line": start + 1, "trust": "unknown"})
            paths.append(current_path)
            return
        if definition is None:
            return
        expression, line = definition
        api_match = re.search(r"([\w$.]+)\s*\(", expression)
        dependencies = identifiers(expression) - {name}
        parameter_backed = bool(dependencies & params)
        if api_match and SOURCE_CALLS.search(api_match.group(1)) and not (prefer_parameter_sources and parameter_backed):
            sources.append({"source_type": "source_api", "symbol": name, "api": api_match.group(1), "line": line, "trust": "less_trusted_or_unknown"})
            paths.append(current_path)
        if name in params and respect_parameter_overwrites and name in dependencies:
            sources.append({"source_type": "function_parameter", "symbol": name, "line": start + 1, "trust": "unknown"})
            paths.append(current_path)
        for dependency in dependencies:
            trace(dependency, current_path)

    for name in sorted(target_names):
        trace(name, ["operation"])
    relevant = visited | target_names
    guards = []
    for index in range(max(start, target_index - 20), target_index):
        match = TS_IF.search(lines[index])
        if not match:
            continue
        overlap = identifiers(match.group(1)) & relevant
        if overlap:
            guards.append({
                "line": index + 1,
                "kind": "preceding_related_if",
                "symbols": sorted(overlap),
                "confidence": "lexical",
            })
    return Analysis(
        "typescript_backward_slice_v1",
        min(evidence_lines),
        list({(item["source_type"], item["symbol"], item["line"]): item for item in sources}.values()),
        guards,
        paths,
        ["lexical TypeScript analysis does not prove control-flow dominance or aliasing"],
    )


def analyze(
    text: str,
    file_name: str,
    evidence_lines: list[int],
    symbol: str | None = None,
    prefer_parameter_sources: bool = False,
    respect_parameter_overwrites: bool = False,
    include_intrinsic_source_operation: bool = True,
) -> Analysis:
    if file_name.lower().endswith(".py"):
        return analyze_python(
            text,
            evidence_lines,
            symbol=symbol,
            prefer_parameter_sources=prefer_parameter_sources,
            respect_parameter_overwrites=respect_parameter_overwrites,
            include_intrinsic_source_operation=include_intrinsic_source_operation,
        )
    if file_name.lower().endswith((".ts", ".tsx", ".js", ".jsx")):
        return analyze_typescript(
            text,
            evidence_lines,
            prefer_parameter_sources=prefer_parameter_sources,
            respect_parameter_overwrites=respect_parameter_overwrites,
        )
    return Analysis("unsupported", min(evidence_lines), [], [], [], ["unsupported language"])
