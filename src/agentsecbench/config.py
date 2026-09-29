"""Strict project configuration loading for AgentSecBench."""

from __future__ import annotations

import tomllib
from dataclasses import dataclass
from pathlib import Path

from .frameworks import FrameworkAdapter


CONFIG_NAME = ".agentsecbench.toml"


class ConfigError(ValueError):
    """Raised when a project configuration is invalid."""


@dataclass(frozen=True)
class ProjectConfig:
    path: Path | None = None
    granularity: str = "line"
    max_file_bytes: int = 2_000_000
    include: tuple[str, ...] = ()
    exclude: tuple[str, ...] = ()
    framework_adapters: tuple[FrameworkAdapter, ...] = ()
    interprocedural: bool = True
    baseline_path: Path | None = None
    suppressions_path: Path | None = None
    blocking_categories: tuple[str, ...] = ()
    minimum_confidence: str = "medium"


def _strings(value: object, field: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(item, str) and item for item in value):
        raise ConfigError(f"{field} must be an array of non-empty strings")
    return tuple(value)


def load_project_config(repository: Path, explicit_path: Path | None = None) -> ProjectConfig:
    path = explicit_path.expanduser().resolve() if explicit_path else repository / CONFIG_NAME
    if not path.exists():
        if explicit_path:
            raise ConfigError(f"configuration file does not exist: {path}")
        return ProjectConfig()
    try:
        payload = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise ConfigError(f"cannot read configuration {path}: {error}") from error
    allowed_root = {"scan", "analysis", "policy", "framework_adapters"}
    unknown = sorted(set(payload) - allowed_root)
    if unknown:
        raise ConfigError(f"unknown top-level configuration keys: {', '.join(unknown)}")
    scan = payload.get("scan", {})
    if not isinstance(scan, dict):
        raise ConfigError("scan must be a TOML table")
    allowed_scan = {"granularity", "max_file_bytes", "include", "exclude"}
    unknown_scan = sorted(set(scan) - allowed_scan)
    if unknown_scan:
        raise ConfigError(f"unknown scan keys: {', '.join(unknown_scan)}")
    granularity = scan.get("granularity", "line")
    if granularity not in {"line", "symbol"}:
        raise ConfigError("scan.granularity must be 'line' or 'symbol'")
    max_file_bytes = scan.get("max_file_bytes", 2_000_000)
    if not isinstance(max_file_bytes, int) or isinstance(max_file_bytes, bool) or max_file_bytes <= 0:
        raise ConfigError("scan.max_file_bytes must be a positive integer")
    analysis = payload.get("analysis", {})
    if not isinstance(analysis, dict):
        raise ConfigError("analysis must be a TOML table")
    unknown_analysis = sorted(set(analysis) - {"interprocedural"})
    if unknown_analysis:
        raise ConfigError(f"unknown analysis keys: {', '.join(unknown_analysis)}")
    interprocedural = analysis.get("interprocedural", True)
    if not isinstance(interprocedural, bool):
        raise ConfigError("analysis.interprocedural must be a boolean")
    policy = payload.get("policy", {})
    if not isinstance(policy, dict):
        raise ConfigError("policy must be a TOML table")
    unknown_policy = sorted(
        set(policy) - {"baseline", "suppressions", "blocking_categories", "minimum_confidence"}
    )
    if unknown_policy:
        raise ConfigError(f"unknown policy keys: {', '.join(unknown_policy)}")

    def policy_path(key: str) -> Path | None:
        value = policy.get(key)
        if value is None:
            return None
        if not isinstance(value, str) or not value.strip():
            raise ConfigError(f"policy.{key} must be a non-empty path string")
        candidate = Path(value).expanduser()
        return candidate.resolve() if candidate.is_absolute() else (path.parent / candidate).resolve()

    baseline_path = policy_path("baseline")
    suppressions_path = policy_path("suppressions")
    blocking_categories = _strings(policy.get("blocking_categories"), "policy.blocking_categories")
    minimum_confidence = policy.get("minimum_confidence", "medium")
    if minimum_confidence not in {"medium", "high"}:
        raise ConfigError("policy.minimum_confidence must be 'medium' or 'high'")
    raw_adapters = payload.get("framework_adapters", [])
    if not isinstance(raw_adapters, list):
        raise ConfigError("framework_adapters must use [[framework_adapters]] tables")
    adapters = []
    allowed_adapter = {"id", "name", "languages", "source_patterns", "decorator_patterns", "registration_patterns", "candidate_patterns", "confidence"}
    for index, item in enumerate(raw_adapters, 1):
        if not isinstance(item, dict):
            raise ConfigError(f"framework_adapters[{index}] must be a table")
        unknown_adapter = sorted(set(item) - allowed_adapter)
        if unknown_adapter:
            raise ConfigError(f"unknown keys in framework_adapters[{index}]: {', '.join(unknown_adapter)}")
        if not isinstance(item.get("id"), str) or not isinstance(item.get("name"), str):
            raise ConfigError(f"framework_adapters[{index}] requires string id and name")
        adapter = FrameworkAdapter(
            adapter_id=item["id"], name=item["name"],
            languages=_strings(item.get("languages", ["python", "javascript_typescript"]), f"framework_adapters[{index}].languages"),
            source_patterns=_strings(item.get("source_patterns"), f"framework_adapters[{index}].source_patterns"),
            decorator_patterns=_strings(item.get("decorator_patterns"), f"framework_adapters[{index}].decorator_patterns"),
            registration_patterns=_strings(item.get("registration_patterns"), f"framework_adapters[{index}].registration_patterns"),
            candidate_patterns=_strings(item.get("candidate_patterns"), f"framework_adapters[{index}].candidate_patterns"),
            confidence=item.get("confidence", "high"), origin="project_config",
        )
        try:
            adapter.validate()
        except ValueError as error:
            raise ConfigError(str(error)) from error
        adapters.append(adapter)
    identifiers = [item.adapter_id for item in adapters]
    if len(identifiers) != len(set(identifiers)):
        raise ConfigError("framework adapter ids must be unique")
    return ProjectConfig(
        path=path, granularity=granularity, max_file_bytes=max_file_bytes,
        include=_strings(scan.get("include"), "scan.include"),
        exclude=_strings(scan.get("exclude"), "scan.exclude"),
        framework_adapters=tuple(adapters),
        interprocedural=interprocedural,
        baseline_path=baseline_path,
        suppressions_path=suppressions_path,
        blocking_categories=blocking_categories,
        minimum_confidence=minimum_confidence,
    )
