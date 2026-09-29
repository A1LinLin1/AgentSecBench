"""Safe first-run project initialization for the public CLI."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path

from .config import CONFIG_NAME, ConfigError, load_project_config


DEFAULT_CONFIG_TEXT = """\
# AgentSecBench project configuration.
# Static candidates are review targets, not vulnerability claims.

[scan]
granularity = "line"
max_file_bytes = 2000000
exclude = [
  ".git/**",
  ".venv/**",
  "node_modules/**",
  "dist/**",
  "build/**",
  "coverage/**",
  "**/*.min.js",
]

[analysis]
interprocedural = true

# Uncomment after creating a baseline or suppression file:
# [policy]
# baseline = ".agentsecbench-baseline.json"
# suppressions = ".agentsecbench-suppressions.toml"
# blocking_categories = ["command_execution", "file_write", "dynamic_code_execution"]
# minimum_confidence = "high"

# Add project-specific [[framework_adapters]] entries when a framework is not
# covered by the built-in adapter registry. See agentsecbench.example.toml.
"""


@dataclass(frozen=True)
class InitResult:
    schema_version: str
    status: str
    project_root: str
    config_file: str
    overwritten: bool
    next_command: str

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def initialize_project(path: str | Path, *, force: bool = False) -> InitResult:
    """Create a validated default config without overwriting by default."""

    root = Path(path).expanduser().resolve()
    if not root.exists():
        raise ConfigError(f"project path does not exist: {root}")
    if not root.is_dir():
        raise ConfigError(f"project path is not a directory: {root}")
    config_path = root / CONFIG_NAME
    existed = config_path.exists()
    if existed and not force:
        raise ConfigError(
            f"configuration already exists: {config_path}; use --force to replace it"
        )
    temporary = config_path.with_name(config_path.name + ".tmp")
    temporary.write_text(DEFAULT_CONFIG_TEXT, encoding="utf-8", newline="\n")
    temporary.replace(config_path)
    load_project_config(root, config_path)
    return InitResult(
        schema_version="1.0",
        status="initialized",
        project_root=str(root),
        config_file=str(config_path),
        overwritten=existed,
        next_command=f'agentsecbench analyze "{root}" --output agentsecbench-results',
    )
