"""Declarative framework-adapter registry for agent entrypoint discovery."""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class FrameworkAdapter:
    """Patterns that normalize a framework-specific tool entrypoint."""

    adapter_id: str
    name: str
    languages: tuple[str, ...] = ("python", "javascript_typescript")
    source_patterns: tuple[str, ...] = ()
    decorator_patterns: tuple[str, ...] = ()
    registration_patterns: tuple[str, ...] = ()
    candidate_patterns: tuple[str, ...] = ()
    confidence: str = "high"
    origin: str = "builtin"

    def validate(self) -> None:
        if not re.fullmatch(r"[a-z][a-z0-9_-]{1,63}", self.adapter_id):
            raise ValueError(f"invalid framework adapter id: {self.adapter_id!r}")
        if not self.name.strip():
            raise ValueError(f"framework adapter {self.adapter_id!r} requires a name")
        if not set(self.languages) <= {"python", "javascript_typescript"}:
            raise ValueError(f"unsupported language in framework adapter {self.adapter_id!r}")
        if self.confidence not in {"high", "medium"}:
            raise ValueError(f"invalid confidence in framework adapter {self.adapter_id!r}")
        patterns = (*self.source_patterns, *self.decorator_patterns, *self.registration_patterns, *self.candidate_patterns)
        if not patterns:
            raise ValueError(f"framework adapter {self.adapter_id!r} has no patterns")
        for pattern in patterns:
            try:
                re.compile(pattern, re.IGNORECASE)
            except re.error as error:
                raise ValueError(f"invalid regex in framework adapter {self.adapter_id!r}: {error}") from error


BUILTIN_ADAPTERS = (
    FrameworkAdapter(
        "mcp", "MCP",
        source_patterns=(r"modelcontextprotocol", r"fastmcp", r"(?:from|import)\s+mcp\b"),
        decorator_patterns=(r"(?:^|\.)tool$",),
        registration_patterns=(r"\b(?:registerTool|server\.tool|mcp\.tool)\s*\([^;]*\b{symbol}\b",),
        candidate_patterns=(r"@(?:mcp|server)\.tool", r"\bregisterTool\s*\(", r"\bFastMCP\s*\("),
    ),
    FrameworkAdapter(
        "langchain", "LangChain",
        source_patterns=(r"langchain",), decorator_patterns=(r"(?:^|\.)tool$",),
        registration_patterns=(r"\b(?:StructuredTool\.from_function|Tool)\s*\([^)]*\b{symbol}\b",),
        candidate_patterns=(r"@tool\b", r"\bStructuredTool\.from_function\s*\("),
    ),
    FrameworkAdapter(
        "crewai", "CrewAI",
        source_patterns=(r"crewai",), decorator_patterns=(r"(?:^|\.)tool$",),
        candidate_patterns=(r"@tool\b", r"\bBaseTool\b"), confidence="medium",
    ),
    FrameworkAdapter(
        "openai-agents", "OpenAI Agents SDK",
        decorator_patterns=(r"(?:^|\.)function_tool$",),
        candidate_patterns=(r"@function_tool\b", r"\bfunction_tool\s*\("),
    ),
    FrameworkAdapter(
        "semantic-kernel", "Semantic Kernel",
        decorator_patterns=(r"(?:^|\.)kernel_function$",),
        candidate_patterns=(r"@kernel_function\b", r"\bkernel_function\s*\("),
    ),
    FrameworkAdapter(
        "autogen", "AutoGen",
        registration_patterns=(r"\bregister_for_(?:execution|llm)\s*\([^)]*\b{symbol}\b",),
        candidate_patterns=(r"\bregister_for_(?:execution|llm)\s*\(",),
    ),
    FrameworkAdapter(
        "llamaindex", "LlamaIndex",
        registration_patterns=(r"\bFunctionTool\.from_defaults\s*\([^)]*\b{symbol}\b",),
        candidate_patterns=(r"\bFunctionTool\.from_defaults\s*\(",),
    ),
)


def adapter_registry(custom: tuple[FrameworkAdapter, ...] = ()) -> tuple[FrameworkAdapter, ...]:
    """Return built-ins plus custom adapters, rejecting identifier collisions."""

    result = [*BUILTIN_ADAPTERS]
    for item in result:
        item.validate()
    known = {item.adapter_id for item in result}
    for item in custom:
        item.validate()
        if item.adapter_id in known:
            raise ValueError(f"framework adapter id collides with a built-in or earlier adapter: {item.adapter_id}")
        known.add(item.adapter_id)
        result.append(item)
    return tuple(result)


def _matches_any(patterns: tuple[str, ...], value: str) -> bool:
    return any(re.search(pattern, value, re.IGNORECASE | re.MULTILINE) for pattern in patterns)


def detect_python_frameworks(
    text: str,
    symbol: str,
    line: int,
    decorators: tuple[str, ...],
    parameters: tuple[str, ...],
    adapters: tuple[FrameworkAdapter, ...],
) -> tuple[dict, ...]:
    evidence: list[dict] = []
    for adapter in adapters:
        if "python" not in adapter.languages:
            continue
        source_ok = not adapter.source_patterns or _matches_any(adapter.source_patterns, text)
        decorator = next(
            (name for name in decorators if _matches_any(adapter.decorator_patterns, name)), None
        ) if adapter.decorator_patterns else None
        registrations = tuple(pattern.replace("{symbol}", re.escape(symbol)) for pattern in adapter.registration_patterns)
        registration = next((pattern for pattern in registrations if re.search(pattern, text, re.IGNORECASE | re.DOTALL)), None)
        if not ((decorator and source_ok) or registration):
            continue
        evidence.append({
            "adapter_id": adapter.adapter_id,
            "adapter_origin": adapter.origin,
            "framework": adapter.name,
            "semantic_role": "tool_definition",
            "symbol": symbol,
            "line": line,
            "confidence": adapter.confidence,
            "matched_pattern": f"decorator:{decorator}" if decorator else f"registration:{registration}",
            "parameters": list(parameters),
        })
    if not evidence and any(name.endswith(".tool") or name == "tool" for name in decorators):
        evidence.append({
            "adapter_id": "generic-tool", "adapter_origin": "fallback", "framework": "GenericTool",
            "semantic_role": "tool_definition", "symbol": symbol, "line": line, "confidence": "medium",
            "matched_pattern": "decorator:tool", "parameters": list(parameters),
        })
    return tuple(evidence)


def detect_typescript_frameworks(
    text: str,
    symbol: str,
    line: int,
    parameters: tuple[str, ...],
    adapters: tuple[FrameworkAdapter, ...],
) -> tuple[dict, ...]:
    evidence: list[dict] = []
    for adapter in adapters:
        if "javascript_typescript" not in adapter.languages:
            continue
        registrations = tuple(pattern.replace("{symbol}", re.escape(symbol)) for pattern in adapter.registration_patterns)
        registration = next((pattern for pattern in registrations if re.search(pattern, text, re.IGNORECASE | re.DOTALL)), None)
        if registration is None:
            continue
        evidence.append({
            "adapter_id": adapter.adapter_id, "adapter_origin": adapter.origin,
            "framework": adapter.name, "semantic_role": "tool_definition", "symbol": symbol,
            "line": line, "confidence": adapter.confidence,
            "matched_pattern": f"registration:{registration}", "parameters": list(parameters),
        })
    return tuple(evidence)
