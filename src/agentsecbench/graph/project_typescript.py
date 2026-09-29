"""Bounded JavaScript/TypeScript module call index and source propagation."""

from __future__ import annotations

import posixpath
import re
from collections import defaultdict
from dataclasses import dataclass, replace
from pathlib import PurePosixPath

from agentsecbench.frameworks import FrameworkAdapter, detect_typescript_frameworks

from .analysis import DependencyAnalysis, _identifiers


FUNCTION_DECL = re.compile(
    r"(?:export\s+)?(?:default\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)\s*\(([^)]*)\)[^{]*\{"
)
ARROW_DECL = re.compile(
    r"(?:export\s+)?(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*(?:async\s*)?\(([^)]*)\)\s*(?::[^=]+)?=>\s*\{"
)
NAMED_IMPORT = re.compile(r"import\s*\{([^}]+)\}\s*from\s*['\"]([^'\"]+)['\"]")
NAMESPACE_IMPORT = re.compile(r"import\s*\*\s*as\s*([A-Za-z_$][\w$]*)\s*from\s*['\"]([^'\"]+)['\"]")
REQUIRE_IMPORT = re.compile(r"(?:const|let|var)\s+([A-Za-z_$][\w$]*)\s*=\s*require\s*\(\s*['\"]([^'\"]+)['\"]\s*\)")
CALL_START = re.compile(r"([A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*)\s*\(")


@dataclass(frozen=True)
class TsCallSite:
    caller: str
    callee: str
    line: int
    positional_names: tuple[tuple[str, ...], ...]


@dataclass(frozen=True)
class TsFunctionInfo:
    key: str
    file: str
    name: str
    line: int
    parameters: tuple[str, ...]
    frameworks: tuple[dict, ...]
    calls: tuple[TsCallSite, ...]


@dataclass(frozen=True)
class TypeScriptProjectIndex:
    functions: dict[str, TsFunctionInfo]
    reverse_calls: dict[str, tuple[TsCallSite, ...]]
    functions_by_file_and_name: dict[tuple[str, str], tuple[str, ...]]
    source_file_count: int
    callsite_count: int

    def function_for_finding(self, file: str, symbol: str, line: int) -> TsFunctionInfo | None:
        candidates = [self.functions[key] for key in self.functions_by_file_and_name.get((file, symbol), ())]
        if not candidates:
            candidates = [item for item in self.functions.values() if item.file == file and item.line <= line]
        return max(candidates, key=lambda item: item.line, default=None)


def _parameters(raw: str) -> tuple[str, ...]:
    result = []
    for item in raw.split(","):
        cleaned = item.strip().lstrip("...")
        match = re.match(r"([A-Za-z_$][\w$]*)", cleaned)
        if match and match.group(1) not in {"this"}:
            result.append(match.group(1))
    return tuple(result)


def _body_end(lines: list[str], start: int) -> int:
    balance = 0
    opened = False
    for index in range(start, len(lines)):
        lexical = re.sub(r"(['\"`])(?:\\.|(?!\1).)*\1", "", lines[index])
        balance += lexical.count("{") - lexical.count("}")
        opened = opened or "{" in lexical
        if opened and balance <= 0:
            return index
    return len(lines) - 1


def _split_arguments(raw: str) -> tuple[str, ...]:
    arguments, current = [], []
    depth = 0
    quote = None
    escaped = False
    for char in raw:
        if quote:
            current.append(char)
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == quote:
                quote = None
            continue
        if char in "'\"`":
            quote = char
            current.append(char)
        elif char in "([{":
            depth += 1
            current.append(char)
        elif char in ")]}":
            depth = max(0, depth - 1)
            current.append(char)
        elif char == "," and depth == 0:
            arguments.append("".join(current).strip())
            current = []
        else:
            current.append(char)
    if current or raw.strip():
        arguments.append("".join(current).strip())
    return tuple(arguments)


def _calls_in_line(line: str, line_number: int, caller: str) -> list[TsCallSite]:
    calls = []
    for match in CALL_START.finditer(line):
        callee = match.group(1)
        prefix = line[: match.start()]
        if re.search(r"\b(?:function|if|for|while|switch|catch)\s*$", prefix):
            continue
        depth, quote, escaped, end = 1, None, False, None
        for index in range(match.end(), len(line)):
            char = line[index]
            if quote:
                if escaped:
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == quote:
                    quote = None
                continue
            if char in "'\"`":
                quote = char
            elif char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    end = index
                    break
        if end is None:
            continue
        raw_arguments = line[match.end() : end]
        calls.append(
            TsCallSite(
                caller,
                callee,
                line_number,
                tuple(tuple(sorted(_identifiers(argument))) for argument in _split_arguments(raw_arguments)),
            )
        )
    return calls


def _resolve_import(current_file: str, specifier: str, known_files: set[str]) -> str | None:
    if not specifier.startswith("."):
        return None
    base = posixpath.normpath(posixpath.join(str(PurePosixPath(current_file).parent), specifier))
    candidates = [
        base,
        *(base + suffix for suffix in (".ts", ".tsx", ".js", ".jsx", ".mjs")),
        *(f"{base}/index{suffix}" for suffix in (".ts", ".tsx", ".js", ".jsx")),
    ]
    return next((candidate for candidate in candidates if candidate in known_files), None)


def build_typescript_project_index(
    source_texts: dict[str, str],
    adapters: tuple[FrameworkAdapter, ...],
) -> TypeScriptProjectIndex:
    eligible = {
        file: text for file, text in source_texts.items()
        if file.lower().endswith((".js", ".jsx", ".mjs", ".ts", ".tsx"))
    }
    known_files = set(eligible)
    functions: dict[str, TsFunctionInfo] = {}
    symbol_imports: dict[str, dict[str, tuple[str, str]]] = {}
    namespace_imports: dict[str, dict[str, str]] = {}
    for file, text in sorted(eligible.items()):
        imports: dict[str, tuple[str, str]] = {}
        namespaces: dict[str, str] = {}
        for match in NAMED_IMPORT.finditer(text):
            target_file = _resolve_import(file, match.group(2), known_files)
            if not target_file:
                continue
            for raw in match.group(1).split(","):
                parts = re.split(r"\s+as\s+", raw.strip())
                if parts and parts[0]:
                    imports[parts[-1]] = (target_file, parts[0])
        for pattern in (NAMESPACE_IMPORT, REQUIRE_IMPORT):
            for match in pattern.finditer(text):
                target_file = _resolve_import(file, match.group(2), known_files)
                if target_file:
                    namespaces[match.group(1)] = target_file
        symbol_imports[file] = imports
        namespace_imports[file] = namespaces
        lines = text.splitlines()
        declarations: list[tuple[int, re.Match[str]]] = []
        for index, line in enumerate(lines):
            match = FUNCTION_DECL.search(line) or ARROW_DECL.search(line)
            if match:
                declarations.append((index, match))
        for start, match in declarations:
            name, params = match.group(1), _parameters(match.group(2))
            end = _body_end(lines, start)
            key = f"{file}::{name}"
            calls = []
            for line_index in range(start, end + 1):
                calls.extend(_calls_in_line(lines[line_index], line_index + 1, key))
            frameworks = detect_typescript_frameworks(text, name, start + 1, params, adapters)
            functions[key] = TsFunctionInfo(key, file, name, start + 1, params, frameworks, tuple(calls))

    by_file_name: dict[tuple[str, str], list[str]] = defaultdict(list)
    for key, function in functions.items():
        by_file_name[(function.file, function.name)].append(key)
    reverse: dict[str, list[TsCallSite]] = defaultdict(list)
    for function in functions.values():
        for site in function.calls:
            parts = site.callee.split(".")
            targets: list[str] = []
            if len(parts) == 1:
                name = parts[0]
                targets.extend(by_file_name.get((function.file, name), ()))
                imported = symbol_imports.get(function.file, {}).get(name)
                if imported:
                    targets.extend(by_file_name.get(imported, ()))
            elif parts[0] in namespace_imports.get(function.file, {}):
                targets.extend(by_file_name.get((namespace_imports[function.file][parts[0]], parts[-1]), ()))
            for target in sorted(set(targets)):
                reverse[target].append(site)
    return TypeScriptProjectIndex(
        functions,
        {key: tuple(sorted(value, key=lambda item: (item.caller, item.line))) for key, value in reverse.items()},
        {key: tuple(sorted(value)) for key, value in by_file_name.items()},
        len(eligible),
        sum(len(item.calls) for item in functions.values()),
    )


def expand_typescript_sources(
    analysis: DependencyAnalysis,
    file: str,
    symbol: str,
    index: TypeScriptProjectIndex,
    max_depth: int = 6,
) -> tuple[DependencyAnalysis, dict]:
    target = index.function_for_finding(file, symbol, analysis.operation_line)
    if target is None:
        return analysis, {"enabled": True, "language": "javascript_typescript", "expanded_sources": 0, "max_depth": max_depth, "reason": "containing_function_not_indexed"}
    expanded_sources: list[dict] = []
    expanded_paths: list[tuple[str, ...]] = []
    replaced_paths: set[tuple[str, ...]] = set()

    def incoming(function: TsFunctionInfo, parameter: str, path: tuple[str, ...], depth: int, visited: set[tuple[str, str]]) -> None:
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
            if parameter_index >= len(site.positional_names):
                continue
            for name in sorted(set(site.positional_names[parameter_index]) & set(caller.parameters)):
                next_path = (*path, f"{caller.file}:{caller.name}", name)
                if caller.frameworks:
                    primary = caller.frameworks[0]
                    expanded_sources.append({
                        "source_type": "agent_tool_parameter", "symbol": name,
                        "line": caller.line, "file": caller.file,
                        "trust": "agent_or_external_caller", "framework": primary["framework"],
                        "entrypoint_type": primary["semantic_role"], "entrypoint_symbol": caller.name,
                        "adapter_id": primary.get("adapter_id"), "interprocedural": True,
                        "call_depth": depth, "via_call_line": site.line,
                        "dependency_path": list(next_path),
                    })
                    expanded_paths.append(next_path)
                else:
                    incoming(caller, name, next_path, depth + 1, visited)

    retained_sources = []
    for source in analysis.sources:
        if source.get("source_type") != "function_parameter":
            retained_sources.append(source)
            continue
        base_paths = [path for path in analysis.dependency_paths if path and path[-1] == source.get("symbol")]
        base = tuple(base_paths[0]) if base_paths else (analysis.operation_name, str(source.get("symbol")))
        before = len(expanded_sources)
        incoming(target, str(source.get("symbol")), base, 1, set())
        if len(expanded_sources) == before:
            retained_sources.append(source)
        else:
            replaced_paths.update(tuple(path) for path in base_paths)
    unique_sources = {
        (item.get("source_type"), item.get("file"), item.get("symbol"), item.get("line")): item
        for item in [*retained_sources, *expanded_sources]
    }
    paths = tuple(dict.fromkeys([
        *[tuple(path) for path in analysis.dependency_paths if tuple(path) not in replaced_paths],
        *expanded_paths,
    ]))
    expanded = replace(
        analysis,
        engine=f"{analysis.engine}+typescript_interprocedural_v1" if expanded_sources else analysis.engine,
        sources=tuple(unique_sources.values()), dependency_paths=paths,
        limitations=(*analysis.limitations, "project call propagation resolves direct local ES/CommonJS imports and named functions; dynamic dispatch remains unresolved"),
    )
    return expanded, {
        "enabled": True, "language": "javascript_typescript",
        "expanded_sources": len(expanded_sources), "max_depth": max_depth,
        "target_function": target.key, "typescript_files_indexed": index.source_file_count,
        "functions_indexed": len(index.functions), "callsites_indexed": index.callsite_count,
        "frameworks": sorted({item.get("framework") for item in expanded_sources if item.get("framework")}),
    }
