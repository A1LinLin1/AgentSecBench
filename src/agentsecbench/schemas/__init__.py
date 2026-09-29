"""Versioned public JSON schemas shipped with AgentSecBench."""

from __future__ import annotations

import json
from importlib.resources import files
from typing import Any


SCHEMA_NAMES = (
    "finding",
    "framework-coverage",
    "policy",
    "report-manifest",
    "review-export",
    "security-adg",
    "summary",
)


def read_schema(name: str) -> dict[str, Any]:
    """Return one bundled schema by its stable public name."""

    if name not in SCHEMA_NAMES:
        raise ValueError(f"unknown schema {name!r}; choose from {', '.join(SCHEMA_NAMES)}")
    text = files(__package__).joinpath(f"{name}.schema.json").read_text(encoding="utf-8")
    return json.loads(text)


__all__ = ["SCHEMA_NAMES", "read_schema"]
