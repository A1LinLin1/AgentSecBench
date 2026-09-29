"""Project-level Python call index and conservative backward propagation."""

from __future__ import annotations

import ast
from collections import defaultdict
from dataclasses import dataclass, replace
from pathlib import PurePosixPath

from agentsecbench.frameworks import FrameworkAdapter, detect_python_frameworks

from .analysis import DependencyAnalysis, _dotted, _loads


@dataclass(frozen=True)
class CallSite:
    caller: str
    callee: str
    line: int
    positional_names: tuple[tuple[str, ...], ...]
    keyword_names: tuple[tuple[str, tuple[str, ...]], ...]


@dataclass(frozen=True)
class FunctionInfo:
    key: str
    module: str
    file: str
    name: str
    qualified_name: str
    line: int
    parameters: tuple[str, ...]
    frameworks: tuple[dict, ...]
    calls: tuple[CallSite, ...]


class _CallCollector(ast.NodeVisitor):
    def __init__(self, root: ast.FunctionDef | ast.AsyncFunctionDef, caller: str) -> None:
        self.root = root
        self.caller = caller
        self.calls: list[CallSite] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if node is self.root:
            self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        if node is self.root:
            self.generic_visit(node)

    def visit_Lambda(self, node: ast.Lambda) -> None:
        return

    def visit_Call(self, node: ast.Call) -> None:
        self.calls.append(
            CallSite(
                caller=self.caller,
                callee=_dotted(node.func),
                line=node.lineno,
                positional_names=tuple(tuple(sorted(_loads(argument))) for argument in node.args),
                keyword_names=tuple(
                    (keyword.arg or "**", tuple(sorted(_loads(keyword.value))))
                    for keyword in node.keywords
                ),
            )
        )
        self.generic_visit(node)


def _module_name(path: str) -> str:
    pure = PurePosixPath(path)
    parts = list(pure.with_suffix("").parts)
    if parts and parts[-1] == "__init__":
        parts.pop()
    return ".".join(parts)


def _parameters(function: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, ...]:
    args = function.args
    result = [
        item.arg for item in [*args.posonlyargs, *args.args, *args.kwonlyargs]
        if item.arg not in {"self", "cls"}
    ]
    if args.vararg:
        result.append(args.vararg.arg)
    if args.kwarg:
        result.append(args.kwarg.arg)
    return tuple(result)


def _decorators(function: ast.FunctionDef | ast.AsyncFunctionDef) -> tuple[str, ...]:
    return tuple(_dotted(item) for item in function.decorator_list)


def _relative_module(current: str, imported: str | None, level: int) -> str:
    if level == 0:
        return imported or ""
    package = current.split(".")[:-1]
    keep = max(0, len(package) - level + 1)
    prefix = package[:keep]
    if imported:
        prefix.extend(imported.split("."))
    return ".".join(prefix)


@dataclass(frozen=True)
class PythonProjectIndex:
    functions: dict[str, FunctionInfo]
    reverse_calls: dict[str, tuple[CallSite, ...]]
    functions_by_file_and_name: dict[tuple[str, str], tuple[str, ...]]
    parse_failures: tuple[str, ...]
    source_file_count: int
    callsite_count: int

    def function_for_finding(self, file: str, symbol: str, line: int) -> FunctionInfo | None:
        candidates = [self.functions[key] for key in self.functions_by_file_and_name.get((file, symbol), ())]
        if not candidates:
            candidates = [
                item for item in self.functions.values()
                if item.file == file and item.line <= line
            ]
        return max(candidates, key=lambda item: item.line, default=None)


def build_python_project_index(
    source_texts: dict[str, str],
    adapters: tuple[FrameworkAdapter, ...],
) -> PythonProjectIndex:
    functions: dict[str, FunctionInfo] = {}
    imports_by_module: dict[str, dict[str, str]] = {}
    symbol_imports_by_module: dict[str, dict[str, tuple[str, str]]] = {}
    parse_failures: list[str] = []
    parsed: dict[str, tuple[str, ast.Module]] = {}
    for file, text in sorted(source_texts.items()):
        if not file.lower().endswith(".py"):
            continue
        module = _module_name(file)
        try:
            tree = ast.parse(text)
        except SyntaxError:
            parse_failures.append(file)
            continue
        parsed[file] = (module, tree)
        module_imports: dict[str, str] = {}
        symbol_imports: dict[str, tuple[str, str]] = {}
        for node in tree.body:
            if isinstance(node, ast.Import):
                for alias in node.names:
                    module_imports[alias.asname or alias.name.split(".")[0]] = alias.name
            elif isinstance(node, ast.ImportFrom):
                imported_module = _relative_module(module, node.module, node.level)
                for alias in node.names:
                    if alias.name != "*":
                        symbol_imports[alias.asname or alias.name] = (imported_module, alias.name)
        imports_by_module[module] = module_imports
        symbol_imports_by_module[module] = symbol_imports

        def add_function(function: ast.FunctionDef | ast.AsyncFunctionDef, qualified: str) -> None:
            key = f"{file}::{qualified}"
            params = _parameters(function)
            frameworks = detect_python_frameworks(
                text, function.name, function.lineno, _decorators(function), params, adapters,
            )
            collector = _CallCollector(function, key)
            collector.visit(function)
            functions[key] = FunctionInfo(
                key, module, file, function.name, qualified, function.lineno,
                params, frameworks, tuple(collector.calls),
            )

        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                add_function(node, node.name)
            elif isinstance(node, ast.ClassDef):
                for child in node.body:
                    if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        add_function(child, f"{node.name}.{child.name}")

    by_module_and_name: dict[tuple[str, str], list[str]] = defaultdict(list)
    by_file_and_name: dict[tuple[str, str], list[str]] = defaultdict(list)
    for key, function in functions.items():
        by_module_and_name[(function.module, function.name)].append(key)
        by_file_and_name[(function.file, function.name)].append(key)

    known_modules = {function.module for function in functions.values()}

    def resolve_local_module(current: str, imported: str) -> str:
        """Resolve script-style sibling imports without guessing across folders."""
        if imported in known_modules:
            return imported
        package = current.rpartition(".")[0]
        sibling = f"{package}.{imported}" if package else imported
        return sibling if sibling in known_modules else imported

    reverse: dict[str, list[CallSite]] = defaultdict(list)
    for function in functions.values():
        module_imports = imports_by_module.get(function.module, {})
        symbol_imports = symbol_imports_by_module.get(function.module, {})
        for site in function.calls:
            targets: list[str] = []
            parts = site.callee.split(".") if site.callee else []
            if len(parts) == 1:
                name = parts[0] if parts else ""
                targets.extend(by_module_and_name.get((function.module, name), ()))
                if name in symbol_imports:
                    imported_module, imported_name = symbol_imports[name]
                    imported_module = resolve_local_module(function.module, imported_module)
                    targets.extend(by_module_and_name.get((imported_module, imported_name), ()))
            elif parts:
                base, name = parts[0], parts[-1]
                if base in {"self", "cls"}:
                    targets.extend(by_module_and_name.get((function.module, name), ()))
                elif base in module_imports:
                    suffix = ".".join(parts[1:-1])
                    imported_module = module_imports[base] + (f".{suffix}" if suffix else "")
                    imported_module = resolve_local_module(function.module, imported_module)
                    targets.extend(by_module_and_name.get((imported_module, name), ()))
            for target in sorted(set(targets)):
                reverse[target].append(site)
    return PythonProjectIndex(
        functions=functions,
        reverse_calls={key: tuple(sorted(value, key=lambda item: (item.caller, item.line))) for key, value in reverse.items()},
        functions_by_file_and_name={key: tuple(sorted(value)) for key, value in by_file_and_name.items()},
        parse_failures=tuple(parse_failures),
        source_file_count=len(parsed),
        callsite_count=sum(len(item.calls) for item in functions.values()),
    )


def expand_interprocedural_sources(
    analysis: DependencyAnalysis,
    file: str,
    symbol: str,
    index: PythonProjectIndex,
    max_depth: int = 6,
) -> tuple[DependencyAnalysis, dict]:
    target = index.function_for_finding(file, symbol, analysis.operation_line)
    if target is None:
        return analysis, {"enabled": True, "expanded_sources": 0, "max_depth": max_depth, "reason": "containing_function_not_indexed"}
    expanded_sources: list[dict] = []
    expanded_paths: list[tuple[str, ...]] = []

    def incoming(function: FunctionInfo, parameter: str, path: tuple[str, ...], depth: int, visited: set[tuple[str, str]]) -> None:
        state = (function.key, parameter)
        if state in visited or depth > max_depth:
            return
        visited = {*visited, state}
        try:
            parameter_index = function.parameters.index(parameter)
        except ValueError:
            return
        for site in index.reverse_calls.get(function.key, ()):
            caller = index.functions[site.caller]
            names: set[str] = set()
            if parameter_index < len(site.positional_names):
                names.update(site.positional_names[parameter_index])
            names.update(dict(site.keyword_names).get(parameter, ()))
            for name in sorted(names & set(caller.parameters)):
                next_path = (*path, f"{caller.file}:{caller.qualified_name}", name)
                if caller.frameworks:
                    primary = caller.frameworks[0]
                    expanded_sources.append({
                        "source_type": "agent_tool_parameter",
                        "symbol": name,
                        "line": caller.line,
                        "file": caller.file,
                        "trust": "agent_or_external_caller",
                        "framework": primary["framework"],
                        "entrypoint_type": primary["semantic_role"],
                        "entrypoint_symbol": caller.qualified_name,
                        "adapter_id": primary.get("adapter_id"),
                        "interprocedural": True,
                        "call_depth": depth,
                        "via_call_line": site.line,
                        "dependency_path": list(next_path),
                    })
                    expanded_paths.append(next_path)
                else:
                    incoming(caller, name, next_path, depth + 1, visited)

    retained_sources: list[dict] = []
    replaced_paths: set[tuple[str, ...]] = set()
    for source in analysis.sources:
        if source.get("source_type") != "function_parameter":
            retained_sources.append(source)
            continue
        before = len(expanded_sources)
        base_paths = [path for path in analysis.dependency_paths if path and path[-1] == source.get("symbol")]
        base = base_paths[0] if base_paths else (analysis.operation_name, str(source.get("symbol")))
        incoming(target, str(source.get("symbol")), tuple(base), 1, set())
        if len(expanded_sources) == before:
            retained_sources.append(source)
        else:
            replaced_paths.update(tuple(path) for path in base_paths)
    all_sources = [*retained_sources, *expanded_sources]
    unique_sources = {
        (item.get("source_type"), item.get("file"), item.get("symbol"), item.get("line")): item
        for item in all_sources
    }
    all_paths = [
        *[path for path in analysis.dependency_paths if tuple(path) not in replaced_paths],
        *expanded_paths,
    ]
    unique_paths = tuple(dict.fromkeys(tuple(path) for path in all_paths))
    expanded = replace(
        analysis,
        engine=f"{analysis.engine}+python_interprocedural_v1" if expanded_sources else analysis.engine,
        sources=tuple(unique_sources.values()),
        dependency_paths=unique_paths,
        limitations=(*analysis.limitations, "project call propagation is Python-only and resolves direct local imports/calls"),
    )
    return expanded, {
        "enabled": True,
        "language": "python",
        "expanded_sources": len(expanded_sources),
        "max_depth": max_depth,
        "target_function": target.key,
        "python_files_indexed": index.source_file_count,
        "functions_indexed": len(index.functions),
        "callsites_indexed": index.callsite_count,
        "parse_failures": list(index.parse_failures),
        "frameworks": sorted({item.get("framework") for item in expanded_sources if item.get("framework")}),
    }
