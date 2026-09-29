"""Conservative local dependency analysis used by the product graph builder.

The analysis never imports or executes target code.  Python is parsed with the
standard-library AST; JavaScript and TypeScript use a bounded lexical slice.
Every inferred relationship remains explicitly marked as a static candidate.
"""

from __future__ import annotations

import ast
import re
import warnings
from dataclasses import dataclass, field

from agentsecbench.frameworks import (
    BUILTIN_ADAPTERS,
    FrameworkAdapter,
    detect_python_frameworks,
    detect_typescript_frameworks,
)


SOURCE_NAMES = re.compile(
    r"(?:^|\.)(?:getenv|get|get_json|json|read|read_text|read_bytes|readFile|readFileSync|fetch|input|recv|receive)$",
    re.IGNORECASE,
)
IDENTIFIER = re.compile(r"\b[A-Za-z_$][\w$]*\b")
TS_FUNCTION = re.compile(
    r"(?:async\s+)?(?:function\s+)?([A-Za-z_$][\w$]*)\s*\(([^)]*)\)\s*(?::[^={]+)?(?:=>)?\s*\{"
)
TS_ASSIGNMENT = re.compile(r"^\s*(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=\s*(.+?);?\s*$")
TS_IF = re.compile(r"^\s*if\s*\((.+)\)")
RESERVED = {
    "await", "true", "false", "null", "undefined", "new", "return", "const", "let", "var",
    "self", "this", "str", "int", "dict", "list", "None", "True", "False", "string",
    "number", "boolean", "void", "Promise", "as", "type", "interface",
}


@dataclass(frozen=True)
class DependencyAnalysis:
    engine: str
    operation_line: int
    operation_name: str
    sources: tuple[dict, ...] = ()
    guards: tuple[dict, ...] = ()
    dependency_paths: tuple[tuple[str, ...], ...] = ()
    framework_evidence: tuple[dict, ...] = ()
    limitations: tuple[str, ...] = field(default_factory=tuple)


def _dotted(node: ast.AST | None) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        prefix = _dotted(node.value)
        return f"{prefix}.{node.attr}" if prefix else node.attr
    if isinstance(node, ast.Call):
        return _dotted(node.func)
    return ""


def _loads(node: ast.AST | None) -> set[str]:
    if node is None:
        return set()
    return {item.id for item in ast.walk(node) if isinstance(item, ast.Name) and isinstance(item.ctx, ast.Load)}


def _python_frameworks(
    text: str,
    function: ast.FunctionDef | ast.AsyncFunctionDef,
    adapters: tuple[FrameworkAdapter, ...],
) -> tuple[dict, ...]:
    args = function.args
    parameters = tuple(
        item.arg for item in [*args.posonlyargs, *args.args, *args.kwonlyargs]
        if item.arg not in {"self", "cls"}
    )
    if args.vararg:
        parameters = (*parameters, args.vararg.arg)
    if args.kwarg:
        parameters = (*parameters, args.kwarg.arg)
    return detect_python_frameworks(
        text, function.name, function.lineno,
        tuple(_dotted(item) for item in function.decorator_list), parameters, adapters,
    )


def analyze_python(
    text: str,
    evidence_lines: tuple[int, ...],
    symbol: str,
    adapters: tuple[FrameworkAdapter, ...] = BUILTIN_ADAPTERS,
) -> DependencyAnalysis:
    operation_line = min(evidence_lines)
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", SyntaxWarning)
            tree = ast.parse(text)
    except SyntaxError as error:
        return DependencyAnalysis("python_ast_v1", operation_line, "operation", limitations=(f"parse_error:{error.msg}",))
    calls = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and node.lineno in set(evidence_lines)]
    call = min(calls, key=lambda node: (getattr(node, "end_lineno", node.lineno) - node.lineno, node.col_offset), default=None)
    explicit_scope = None
    if call is not None:
        explicit_scope = next(
            (
                function for function in ast.walk(tree)
                if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef))
                and any(call is decorator or call in ast.walk(decorator) for decorator in function.decorator_list)
            ),
            None,
        )
    if call is None:
        explicit_scope = next(
            (
                function for function in ast.walk(tree)
                if isinstance(function, (ast.FunctionDef, ast.AsyncFunctionDef)) and function.name == symbol
            ),
            None,
        )
        if explicit_scope is not None:
            parameters = {
                item.arg
                for item in [*explicit_scope.args.posonlyargs, *explicit_scope.args.args, *explicit_scope.args.kwonlyargs]
                if item.arg not in {"self", "cls"}
            }
            consuming = [
                node for node in ast.walk(explicit_scope)
                if isinstance(node, ast.Call)
                and set().union(*(_loads(argument) for argument in [*node.args, *(item.value for item in node.keywords)])) & parameters
            ]
            call = max(consuming, key=lambda node: node.lineno, default=None)
        if call is None:
            return DependencyAnalysis("python_ast_v1", operation_line, symbol or "operation", limitations=("no_effectful_call_resolved_for_entrypoint",))
    functions = [
        node for node in ast.walk(tree)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
        and node.lineno <= call.lineno <= getattr(node, "end_lineno", node.lineno)
    ]
    scope: ast.AST = explicit_scope or min(functions, key=lambda node: getattr(node, "end_lineno", node.lineno) - node.lineno, default=tree)
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)) and any(
        call is decorator or call in ast.walk(decorator) for decorator in scope.decorator_list
    ):
        parameters_for_call = {
            item.arg
            for item in [*scope.args.posonlyargs, *scope.args.args, *scope.args.kwonlyargs]
            if item.arg not in {"self", "cls"}
        }
        consuming = [
            node for node in ast.walk(scope)
            if isinstance(node, ast.Call)
            and set().union(*(_loads(argument) for argument in [*node.args, *(item.value for item in node.keywords)])) & parameters_for_call
        ]
        call = max(consuming, key=lambda node: node.lineno, default=call)
    frameworks = _python_frameworks(text, scope, adapters) if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)) else ()
    parameters: set[str] = set()
    if isinstance(scope, (ast.FunctionDef, ast.AsyncFunctionDef)):
        args = scope.args
        parameters = {
            item.arg for item in [*args.posonlyargs, *args.args, *args.kwonlyargs]
            if item.arg not in {"self", "cls"}
        }
        if args.vararg:
            parameters.add(args.vararg.arg)
        if args.kwarg:
            parameters.add(args.kwarg.arg)

    definitions: dict[str, tuple[ast.AST | None, int]] = {}
    for node in ast.walk(scope):
        if getattr(node, "lineno", call.lineno) >= call.lineno:
            continue
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            targets = node.targets if isinstance(node, ast.Assign) else [node.target]
            value = node.value
            for target in targets:
                for name in (item.id for item in ast.walk(target) if isinstance(item, ast.Name)):
                    if name not in definitions or definitions[name][1] < node.lineno:
                        definitions[name] = (value, node.lineno)

    target_names: set[str] = set()
    if isinstance(call.func, ast.Attribute):
        target_names.update(_loads(call.func.value))
    for argument in [*call.args, *(item.value for item in call.keywords)]:
        target_names.update(_loads(argument))
    sources: list[dict] = []
    paths: list[tuple[str, ...]] = []
    visited: set[str] = set()

    def trace(name: str, path: tuple[str, ...]) -> None:
        if name in visited:
            return
        visited.add(name)
        current = (*path, name)
        if name in parameters:
            matching = [item for item in frameworks if name in item["parameters"]]
            source = {
                "source_type": "agent_tool_parameter" if matching else "function_parameter",
                "symbol": name,
                "line": getattr(scope, "lineno", operation_line),
                "trust": "agent_or_external_caller" if matching else "unknown",
            }
            if matching:
                source.update({"framework": matching[0]["framework"], "entrypoint_type": matching[0]["semantic_role"]})
            sources.append(source)
            paths.append(current)
            return
        definition = definitions.get(name)
        if definition is None:
            return
        value, line = definition
        api = _dotted(value.func) if isinstance(value, ast.Call) else ""
        dependencies = sorted(_loads(value) - {name})
        if SOURCE_NAMES.search(api):
            sources.append({"source_type": "source_api", "symbol": name, "api": api, "line": line, "trust": "less_trusted_or_unknown"})
            paths.append(current)
        for dependency in dependencies:
            trace(dependency, current)

    operation_name = _dotted(call.func) or "operation"
    for name in sorted(target_names):
        trace(name, (operation_name,))

    parents: dict[ast.AST, ast.AST] = {}
    for parent in ast.walk(scope):
        for child in ast.iter_child_nodes(parent):
            parents[child] = parent
    guards: list[dict] = []
    ancestor: ast.AST = call
    while ancestor in parents:
        ancestor = parents[ancestor]
        if isinstance(ancestor, ast.If):
            guards.append({"line": ancestor.lineno, "kind": "dominating_if", "symbols": sorted(_loads(ancestor.test)), "confidence": "structural"})
    relevant = visited | target_names
    for node in ast.walk(scope):
        if isinstance(node, ast.Assert) and node.lineno < call.lineno and _loads(node.test) & relevant:
            guards.append({"line": node.lineno, "kind": "preceding_related_assert", "symbols": sorted(_loads(node.test) & relevant), "confidence": "structural"})
    return DependencyAnalysis(
        "python_backward_slice_product_v1", call.lineno, operation_name,
        tuple(sources), tuple(guards), tuple(paths), frameworks,
        ("intraprocedural static slice; aliases and runtime dispatch may be incomplete",),
    )


def _identifiers(expression: str) -> set[str]:
    expression = re.sub(r"(['\"])(?:\\.|(?!\1).)*\1", "", expression)
    return {name for name in IDENTIFIER.findall(expression) if name not in RESERVED and not name.isupper()}


def analyze_typescript(
    text: str,
    evidence_lines: tuple[int, ...],
    symbol: str,
    adapters: tuple[FrameworkAdapter, ...] = BUILTIN_ADAPTERS,
) -> DependencyAnalysis:
    lines = text.splitlines()
    target = min(evidence_lines) - 1
    start = max(0, target - 120)
    parameters: set[str] = set()
    function_name = symbol
    for index in range(target, max(-1, target - 160), -1):
        match = TS_FUNCTION.search(lines[index])
        if match:
            start = index
            function_name = match.group(1)
            parameters = {
                name for part in match.group(2).split(",")
                if (found := IDENTIFIER.search(part)) and (name := found.group(0)) not in RESERVED
            }
            break
    target_line = lines[target] if 0 <= target < len(lines) else ""
    call_match = re.search(r"([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\((.*)", target_line)
    operation = call_match.group(1) if call_match else "operation"
    target_names = _identifiers(call_match.group(2) if call_match else target_line)
    definitions: dict[str, tuple[str, int]] = {}
    for index in range(start, target):
        match = TS_ASSIGNMENT.match(lines[index])
        if match:
            definitions[match.group(1)] = (match.group(2), index + 1)
    frameworks = detect_typescript_frameworks(
        text, function_name, start + 1, tuple(sorted(parameters)), adapters,
    )
    sources: list[dict] = []
    paths: list[tuple[str, ...]] = []
    visited: set[str] = set()

    def trace(name: str, path: tuple[str, ...]) -> None:
        if name in visited:
            return
        visited.add(name)
        current = (*path, name)
        if name in parameters:
            sources.append({"source_type": "agent_tool_parameter" if frameworks else "function_parameter", "symbol": name, "line": start + 1, "trust": "agent_or_external_caller" if frameworks else "unknown"})
            paths.append(current)
            return
        if name not in definitions:
            return
        expression, line = definitions[name]
        api = re.search(r"([\w$.]+)\s*\(", expression)
        if api and SOURCE_NAMES.search(api.group(1)):
            sources.append({"source_type": "source_api", "symbol": name, "api": api.group(1), "line": line, "trust": "less_trusted_or_unknown"})
            paths.append(current)
        for dependency in sorted(_identifiers(expression) - {name}):
            trace(dependency, current)

    for name in sorted(target_names):
        trace(name, (operation,))
    relevant = visited | target_names
    guards = []
    for index in range(max(start, target - 20), target):
        match = TS_IF.search(lines[index])
        overlap = _identifiers(match.group(1)) & relevant if match else set()
        if overlap:
            guards.append({"line": index + 1, "kind": "preceding_related_if", "symbols": sorted(overlap), "confidence": "lexical"})
    return DependencyAnalysis(
        "typescript_backward_slice_product_v1", target + 1, operation,
        tuple(sources), tuple(guards), tuple(paths), frameworks,
        ("bounded lexical slice; control flow, aliases, and runtime dispatch may be incomplete",),
    )


def analyze_source(
    text: str,
    path: str,
    evidence_lines: tuple[int, ...],
    symbol: str,
    adapters: tuple[FrameworkAdapter, ...] = BUILTIN_ADAPTERS,
) -> DependencyAnalysis:
    lower = path.lower()
    if lower.endswith(".py"):
        return analyze_python(text, evidence_lines, symbol, adapters)
    if lower.endswith((".js", ".jsx", ".ts", ".tsx")):
        return analyze_typescript(text, evidence_lines, symbol, adapters)
    return DependencyAnalysis("unsupported_language", min(evidence_lines), "operation", limitations=("dependency analysis is not yet available for this language",))
