"""Run the five-provider blinded model annotation panel with budget controls."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import os
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


BASE_DIR = Path(__file__).resolve().parent.parent
PACKAGE_DIR = BASE_DIR / "annotations" / "model_annotation"
INPUTS = PACKAGE_DIR / "inputs" / "model_tasks_blinded.jsonl"
SCHEMA_PATH = PACKAGE_DIR / "output_schema.json"
SYSTEM_PROMPT_PATH = PACKAGE_DIR / "system_prompt.md"
GUIDE_PATH = PACKAGE_DIR / "model_annotation_guide.md"
USER_TEMPLATE_PATH = PACKAGE_DIR / "user_prompt_template.md"
SECRETS_PATH = BASE_DIR / ".secrets" / "model_annotation.env"
RUNS_DIR = PACKAGE_DIR / "runs"

PROTOCOL_VERSION = "hybrid-model-panel-v3"
DEFAULT_BUDGET_USD = 20.0
BUDGET_RESERVE_USD = 0.25
PRICE_SAFETY_FACTOR = 1.25
DEFAULT_MAX_OUTPUT_TOKENS = 3000
HTTP_TIMEOUT_SECONDS = 240
MAX_ATTEMPTS = 3

# One documented resume-only exception: OpenRouter rejected the original
# 3,000-token reservation for the final Claude call because the remaining
# account credit could reserve only 2,586 tokens.  Prior successful Claude
# responses used at most 1,095 output tokens, so this does not constrain the
# observed annotation format.
MAX_OUTPUT_TOKEN_OVERRIDES = {
    ("anthropic", "AT-0150"): 1800,
}

LABEL_ENUMS = {
    "behavior_confirmed": {"true", "false", "uncertain"},
    "agent_relevant": {"true", "false", "uncertain"},
    "source_type": {
        "user_prompt", "web_content", "file_content", "tool_output",
        "message_email", "database", "environment_config", "internal_constant",
        "unknown", "none",
    },
    "source_external": {"true", "false", "unknown"},
    "dependency_confirmed": {"true", "false", "partial", "unknown"},
    "trust_boundary_crossed": {"true", "false", "unknown"},
    "effect_type": {
        "command_execution", "dynamic_code_execution", "filesystem_read",
        "filesystem_write", "filesystem_delete", "browser_control",
        "network_access", "credential_access", "database_access",
        "external_tool_invocation", "other", "none",
    },
    "guard_present": {"true", "false", "unknown"},
    "guard_effective": {"yes", "no", "partial", "unknown", "not_applicable"},
    "weakness_present": {"true", "false", "uncertain"},
    "vulnerability_status": {"not_assessed", "candidate", "confirmed", "rejected"},
    "label_confidence": {"high", "medium", "low"},
}
GUARD_TYPES = {
    "allowlist", "schema_validation", "canonicalization", "authorization",
    "user_confirmation", "sandbox", "escaping", "least_privilege",
    "destination_restriction", "secret_redaction", "other",
}

PROVIDERS = {
    "openai": {
        "model": "openai/gpt-5-mini",
        "key": "OPENROUTER_API_KEY",
        "url": "https://openrouter.ai/api/v1/chat/completions",
        "kind": "openrouter",
        "reasoning_effort": "medium",
        "max_output_tokens": DEFAULT_MAX_OUTPUT_TOKENS,
        "input_usd_per_million": 0.25,
        "output_usd_per_million": 2.0,
    },
    "anthropic": {
        "model": "anthropic/claude-sonnet-4.6",
        "key": "OPENROUTER_API_KEY",
        "url": "https://openrouter.ai/api/v1/chat/completions",
        "kind": "openrouter",
        "reasoning_effort": "medium",
        "max_output_tokens": DEFAULT_MAX_OUTPUT_TOKENS,
        "input_usd_per_million": 3.0,
        "output_usd_per_million": 15.0,
    },
    "gemini": {
        "model": "google/gemini-3.5-flash-lite",
        "key": "OPENROUTER_API_KEY",
        "url": "https://openrouter.ai/api/v1/chat/completions",
        "kind": "openrouter",
        "reasoning_effort": "medium",
        "max_output_tokens": DEFAULT_MAX_OUTPUT_TOKENS,
        "input_usd_per_million": 0.3,
        "output_usd_per_million": 2.5,
    },
    "qwen": {
        "model": "qwen/qwen3-max",
        "key": "OPENROUTER_API_KEY",
        "url": "https://openrouter.ai/api/v1/chat/completions",
        "kind": "openrouter",
        "reasoning_effort": None,
        "max_output_tokens": DEFAULT_MAX_OUTPUT_TOKENS,
        "input_usd_per_million": 0.78,
        "output_usd_per_million": 3.9,
    },
    "deepseek": {
        "model": "deepseek-v4-pro",
        "key": "DEEPSEEK_API_KEY",
        "url": "https://api.deepseek.com/chat/completions",
        "kind": "deepseek_official",
        "reasoning_effort": "high",
        "max_output_tokens": 6000,
        "input_usd_per_million": 0.435,
        "cache_hit_input_usd_per_million": 0.003625,
        "output_usd_per_million": 0.87,
    },
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    temporary.replace(path)


def append_jsonl(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(value, ensure_ascii=False, sort_keys=True) + "\n")


def load_secrets(path: Path) -> dict[str, str]:
    if not path.exists():
        raise RuntimeError(
            f"missing secrets file: {path}\n"
            "Copy .secrets/model_annotation.env.example to model_annotation.env "
            "and fill it locally. Do not paste keys into chat."
        )
    secrets: dict[str, str] = {}
    for number, raw in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise RuntimeError(f"invalid secrets line {number}: expected KEY=VALUE")
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if value.startswith(('"', "'")) and value.endswith(value[0]):
            value = value[1:-1]
        if not value or value == "replace_me":
            raise RuntimeError(f"secret {key} is empty or still a placeholder")
        secrets[key] = value
    missing = sorted({cfg["key"] for cfg in PROVIDERS.values() if cfg["key"] not in secrets})
    if missing:
        raise RuntimeError(f"missing required secret names: {', '.join(missing)}")
    return secrets


def load_inputs() -> list[dict]:
    with INPUTS.open("r", encoding="utf-8") as handle:
        rows = [json.loads(line) for line in handle if line.strip()]
    if len(rows) != 150 or len({row["task_id"] for row in rows}) != 150:
        raise RuntimeError("expected 150 unique blinded model inputs")
    return rows


def prompt_material(task: dict) -> tuple[str, str]:
    system = SYSTEM_PROMPT_PATH.read_text(encoding="utf-8").strip()
    guide = GUIDE_PATH.read_text(encoding="utf-8").strip()
    schema_text = json.dumps(
        json.loads(SCHEMA_PATH.read_text(encoding="utf-8")),
        ensure_ascii=False,
        separators=(",", ":"),
    )
    template = USER_TEMPLATE_PATH.read_text(encoding="utf-8").strip()
    task_json = json.dumps(task, ensure_ascii=False, indent=2, sort_keys=True)
    user = template.replace("{{TASK_JSON}}", task_json)
    return system, f"{guide}\n\n---\n\nOUTPUT JSON SCHEMA:\n{schema_text}\n\n---\n\n{user}"


def provider_schema(schema: dict) -> dict:
    """Remove metadata keywords rejected by some provider schema subsets."""
    unsupported = {
        "$schema", "$id", "title", "pattern", "minLength", "maxLength",
        "uniqueItems", "minimum",
    }

    def clean(value: Any) -> Any:
        if isinstance(value, dict):
            return {key: clean(item) for key, item in value.items() if key not in unsupported}
        if isinstance(value, list):
            return [clean(item) for item in value]
        return value

    return clean(schema)


def build_request(
    provider: str,
    task: dict,
    schema: dict,
    enforce_zdr: bool,
) -> tuple[dict, str, str]:
    cfg = PROVIDERS[provider]
    max_output_tokens = MAX_OUTPUT_TOKEN_OVERRIDES.get(
        (provider, task["task_id"]), cfg["max_output_tokens"]
    )
    system, user = prompt_material(task)
    clean_schema = provider_schema(schema)
    if cfg["kind"] == "openrouter":
        body = {
            "model": cfg["model"],
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "max_tokens": max_output_tokens,
            "session_id": f"agentsecbench-{PROTOCOL_VERSION}-{provider}",
            "metadata": {
                "protocol": PROTOCOL_VERSION,
                "rater": provider,
                "task_id": task["task_id"],
            },
            "provider": {
                "allow_fallbacks": False,
                "require_parameters": True,
                "data_collection": "deny",
            },
            "response_format": {
                "type": "json_schema",
                "json_schema": {
                    "name": "agentsecbench_annotation",
                    "strict": True,
                    "schema": clean_schema,
                },
            },
        }
        if enforce_zdr:
            body["provider"]["zdr"] = True
        if cfg["reasoning_effort"]:
            body["reasoning"] = {
                "effort": cfg["reasoning_effort"],
                "exclude": True,
            }
    elif cfg["kind"] == "deepseek_official":
        body = {
            "model": cfg["model"],
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "max_tokens": max_output_tokens,
            "thinking": {"type": "enabled"},
            "reasoning_effort": cfg["reasoning_effort"],
            "response_format": {"type": "json_object"},
            "user_id": f"agentsecbench-{PROTOCOL_VERSION}-{provider}",
        }
    else:
        raise AssertionError(cfg["kind"])
    return body, system, user


def request_headers(provider: str, secret: str) -> dict[str, str]:
    kind = PROVIDERS[provider]["kind"]
    headers = {
        "Content-Type": "application/json",
        "User-Agent": "AgentSecBench/1.0",
        "X-OpenRouter-Metadata": "enabled",
        "X-Title": "AgentSecBench Model Annotation",
    }
    if kind in {"openrouter", "deepseek_official"}:
        headers["Authorization"] = f"Bearer {secret}"
        if kind == "deepseek_official":
            headers.pop("X-OpenRouter-Metadata", None)
            headers.pop("X-Title", None)
    else:
        raise AssertionError(kind)
    return headers


def http_post(provider: str, body: dict, secret: str) -> tuple[int, dict, dict[str, str]]:
    encoded = json.dumps(body, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(
        PROVIDERS[provider]["url"],
        data=encoded,
        headers=request_headers(provider, secret),
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            payload = json.loads(response.read().decode("utf-8", errors="replace"))
            safe_headers = {
                key.lower(): value
                for key, value in response.headers.items()
                if key.lower() in {
                    "x-request-id", "request-id", "retry-after", "x-generation-id"
                }
            }
            return response.status, payload, safe_headers
    except urllib.error.HTTPError as error:
        raw = error.read().decode("utf-8", errors="replace")
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = {"error_text": raw[:4000]}
        raise RuntimeError(f"HTTP {error.code}: {json.dumps(payload, ensure_ascii=False)[:4000]}") from None


def extract_response(provider: str, payload: dict) -> tuple[Any, dict, dict]:
    kind = PROVIDERS[provider]["kind"]
    if kind == "openrouter":
        content = payload["choices"][0]["message"].get("content")
        usage = payload.get("usage") or {}
        prompt_tokens = usage.get("prompt_tokens", usage.get("input_tokens", 0)) or 0
        completion_tokens = usage.get("completion_tokens", usage.get("output_tokens", 0)) or 0
        openrouter_metadata = payload.get("openrouter_metadata") or {}
        nested_provider = openrouter_metadata.get("provider")
        if isinstance(nested_provider, dict):
            nested_provider = nested_provider.get("name") or nested_provider.get("provider_name")
        upstream_provider = (
            payload.get("provider")
            or openrouter_metadata.get("provider_name")
            or nested_provider
        )
        metadata = {
            "response_id": payload.get("id") or payload.get("request_id"),
            "returned_model": payload.get("model"),
            "finish_reason": payload["choices"][0].get("finish_reason"),
            "system_fingerprint": payload.get("system_fingerprint"),
            "upstream_provider": upstream_provider,
            "reported_cost_usd": usage.get("cost"),
            "cost_details": usage.get("cost_details"),
        }
    elif kind == "deepseek_official":
        content = payload["choices"][0]["message"].get("content")
        usage = payload.get("usage") or {}
        prompt_tokens = usage.get("prompt_tokens", 0) or 0
        completion_tokens = usage.get("completion_tokens", 0) or 0
        metadata = {
            "response_id": payload.get("id"),
            "returned_model": payload.get("model"),
            "finish_reason": payload["choices"][0].get("finish_reason"),
            "system_fingerprint": payload.get("system_fingerprint"),
            "upstream_provider": "DeepSeek Official",
            "reported_cost_usd": None,
            "cost_details": {
                "prompt_cache_hit_tokens": usage.get("prompt_cache_hit_tokens"),
                "prompt_cache_miss_tokens": usage.get("prompt_cache_miss_tokens"),
                "source": "locally estimated from official list price",
            },
        }
    else:
        raise AssertionError(kind)
    return content, {
        "input_tokens": int(prompt_tokens),
        "output_tokens": int(completion_tokens),
    }, metadata


def redact_reasoning(value: Any) -> Any:
    """Retain audit metadata without persisting provider reasoning traces."""
    if isinstance(value, list):
        return [redact_reasoning(item) for item in value]
    if not isinstance(value, dict):
        return value
    result = {}
    for key, item in value.items():
        if key in {"reasoning_content", "thinking"} and isinstance(item, str):
            result[key] = {
                "redacted": True,
                "character_count": len(item),
                "sha256": sha256_bytes(item.encode("utf-8")),
            }
        else:
            result[key] = redact_reasoning(item)
    return result


def validate_annotation(value: Any, task: dict, schema: dict) -> list[str]:
    errors: list[str] = []
    if not isinstance(value, dict):
        return ["output is not a JSON object"]
    expected_fields = set(schema["properties"])
    actual_fields = set(value)
    if actual_fields != expected_fields:
        errors.append(
            f"field mismatch; missing={sorted(expected_fields - actual_fields)} "
            f"extra={sorted(actual_fields - expected_fields)}"
        )
    if value.get("task_id") != task["task_id"]:
        errors.append("task_id mismatch")
    if value.get("candidate_id") != task["candidate_id"]:
        errors.append("candidate_id mismatch")
    for field, allowed in LABEL_ENUMS.items():
        if value.get(field) not in allowed:
            errors.append(f"invalid {field}: {value.get(field)!r}")
    guards = value.get("guard_types")
    if not isinstance(guards, list) or len(guards) != len(set(guards)) or any(g not in GUARD_TYPES for g in guards):
        errors.append("invalid guard_types")
    evidence = value.get("evidence_line_numbers")
    if not isinstance(evidence, list) or any(not isinstance(n, int) or n < 1 for n in evidence):
        errors.append("invalid evidence_line_numbers")
    elif any(not task["context_start_line"] <= n <= task["context_end_line"] for n in evidence):
        errors.append("evidence line outside supplied context")
    for field, limit in (("effect_target", 300), ("missing_context", 500), ("rationale", 1000)):
        if not isinstance(value.get(field), str) or len(value[field]) > limit:
            errors.append(f"invalid {field}")
    if isinstance(value.get("rationale"), str) and not value["rationale"].strip():
        errors.append("empty rationale")
    if value.get("behavior_confirmed") == "false" and value.get("effect_type") != "none":
        errors.append("behavior_confirmed=false requires effect_type=none")
    if value.get("dependency_confirmed") == "false" and value.get("trust_boundary_crossed") != "false":
        errors.append("dependency_confirmed=false requires trust_boundary_crossed=false")
    if value.get("guard_present") == "false":
        if guards:
            errors.append("guard_present=false requires empty guard_types")
        if value.get("guard_effective") != "not_applicable":
            errors.append("guard_present=false requires guard_effective=not_applicable")
    if value.get("guard_present") == "true" and not guards:
        errors.append("guard_present=true requires at least one guard_type")
    if value.get("vulnerability_status") == "confirmed" and (
        value.get("weakness_present") != "true"
        or value.get("dependency_confirmed") != "true"
        or value.get("trust_boundary_crossed") != "true"
    ):
        errors.append(
            "vulnerability_status=confirmed requires weakness, dependency, and boundary=true"
        )
    return errors


def conservative_cost(provider: str, usage: dict, prompt_chars: int = 0) -> float:
    cfg = PROVIDERS[provider]
    input_tokens = usage.get("input_tokens", 0) or (prompt_chars + 2) // 3
    output_tokens = usage.get("output_tokens", 0) or cfg["max_output_tokens"]
    list_price = (
        input_tokens * cfg["input_usd_per_million"] / 1_000_000
        + output_tokens * cfg["output_usd_per_million"] / 1_000_000
    )
    return list_price * PRICE_SAFETY_FACTOR


def response_accounted_cost(provider: str, payload: dict) -> float:
    """Account for every billed HTTP 200 response, including failed validation retries."""
    cfg = PROVIDERS[provider]
    usage = payload.get("usage") or {}
    reported = float(usage.get("cost") or 0.0)
    if cfg["kind"] == "openrouter" and reported > 0:
        return reported
    input_tokens = int(usage.get("prompt_tokens", usage.get("input_tokens", 0)) or 0)
    output_tokens = int(usage.get("completion_tokens", usage.get("output_tokens", 0)) or 0)
    if cfg["kind"] == "deepseek_official":
        cache_hit = int(usage.get("prompt_cache_hit_tokens") or 0)
        cache_miss = int(usage.get("prompt_cache_miss_tokens") or 0)
        if cache_hit or cache_miss:
            return (
                cache_hit * cfg["cache_hit_input_usd_per_million"] / 1_000_000
                + cache_miss * cfg["input_usd_per_million"] / 1_000_000
                + output_tokens * cfg["output_usd_per_million"] / 1_000_000
            )
    conservative = conservative_cost(
        provider,
        {"input_tokens": input_tokens, "output_tokens": output_tokens}
    ) if input_tokens or output_tokens else 0.0
    return max(reported, conservative)


def run_one(
    provider: str,
    task: dict,
    schema: dict,
    secret: str,
    run_dir: Path,
    enforce_zdr: bool,
) -> dict:
    body, system, user = build_request(provider, task, schema, enforce_zdr)
    request_hash = sha256_bytes(json.dumps(body, ensure_ascii=False, sort_keys=True).encode("utf-8"))
    attempts: list[dict] = []
    started = utc_now()
    for attempt_number in range(1, MAX_ATTEMPTS + 1):
        attempt_started = time.monotonic()
        try:
            status, payload, safe_headers = http_post(provider, body, secret)
            content, usage, metadata = extract_response(provider, payload)
            if not isinstance(content, str) or not content.strip():
                annotation = None
                validation_errors = [
                    "empty response content "
                    f"(finish_reason={metadata.get('finish_reason')!r})"
                ]
            else:
                try:
                    annotation = json.loads(content)
                    validation_errors = validate_annotation(annotation, task, schema)
                except json.JSONDecodeError as error:
                    annotation = None
                    validation_errors = [f"invalid JSON: {error}"]
            attempts.append(
                {
                    "attempt": attempt_number,
                    "http_status": status,
                    "duration_seconds": round(time.monotonic() - attempt_started, 3),
                    "safe_response_headers": safe_headers,
                    "response": redact_reasoning(payload),
                    "validation_errors": validation_errors,
                }
            )
            if not validation_errors:
                result = {
                    "protocol_version": PROTOCOL_VERSION,
                    "provider": provider,
                    "configured_model": PROVIDERS[provider]["model"],
                    "task_id": task["task_id"],
                    "candidate_id": task["candidate_id"],
                    "input_sha256": task["input_sha256"],
                    "request_sha256": request_hash,
                    "started_at_utc": started,
                    "completed_at_utc": utc_now(),
                    "attempt_count": attempt_number,
                    "usage": usage,
                    "conservative_cost_upper_usd": round(
                        conservative_cost(provider, usage, len(system) + len(user)), 8
                    ),
                    "response_metadata": metadata,
                    "annotation": annotation,
                    "attempts": attempts,
                    "status": "completed",
                }
                atomic_json(run_dir / "raw" / provider / f"{task['task_id']}.json", result)
                prior_failure = run_dir / "failures" / provider / f"{task['task_id']}.json"
                if prior_failure.exists():
                    history = run_dir / "failure_history" / provider / prior_failure.name
                    history.parent.mkdir(parents=True, exist_ok=True)
                    prior_failure.replace(history)
                return result
        except Exception as error:  # transport/provider failures are recorded and retried
            attempts.append(
                {
                    "attempt": attempt_number,
                    "duration_seconds": round(time.monotonic() - attempt_started, 3),
                    "error_type": type(error).__name__,
                    "error": str(error)[:4000],
                }
            )
        if attempt_number < MAX_ATTEMPTS:
            time.sleep(2 ** attempt_number)

    failure = {
        "protocol_version": PROTOCOL_VERSION,
        "provider": provider,
        "configured_model": PROVIDERS[provider]["model"],
        "task_id": task["task_id"],
        "candidate_id": task["candidate_id"],
        "input_sha256": task["input_sha256"],
        "request_sha256": request_hash,
        "started_at_utc": started,
        "completed_at_utc": utc_now(),
        "attempt_count": len(attempts),
        "attempts": attempts,
        "status": "failed",
    }
    atomic_json(run_dir / "failures" / provider / f"{task['task_id']}.json", failure)
    return failure


def completed_result(run_dir: Path, provider: str, task_id: str) -> dict | None:
    path = run_dir / "raw" / provider / f"{task_id}.json"
    if not path.exists():
        return None
    value = json.loads(path.read_text(encoding="utf-8"))
    return value if value.get("status") == "completed" else None


def current_cost(run_dir: Path) -> float:
    total = 0.0
    paths = []
    for category in ("raw", "failures", "failure_history"):
        directory = run_dir / category
        if directory.exists():
            paths.extend(directory.glob("*/*.json"))
    for path in paths:
        value = json.loads(path.read_text(encoding="utf-8"))
        attempt_responses = [
            attempt["response"]
            for attempt in value.get("attempts", [])
            if isinstance(attempt.get("response"), dict)
        ]
        if attempt_responses:
            provider = value["provider"]
            total += sum(response_accounted_cost(provider, payload) for payload in attempt_responses)
        elif value.get("status") == "completed":
            total += float(value.get("conservative_cost_upper_usd", 0.0))
    manifest_path = run_dir / "run_manifest.json"
    if manifest_path.exists():
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        total += float(manifest.get("sunk_cost_adjustment_usd", 0.0))
    return total


def projected_full_cost(run_dir: Path, total_tasks: int) -> float:
    """Project completion from final valid-response costs plus all spend to date.

    Scaling current_cost directly would multiply one-off smoke retries across the
    entire corpus.  Keep those retries in sunk spend, then estimate only the
    unfinished calls from each provider's valid-response mean.
    """
    projection = current_cost(run_dir)
    for provider in PROVIDERS:
        costs = []
        source = run_dir / "raw" / provider
        if source.exists():
            for path in source.glob("AT-*.json"):
                value = json.loads(path.read_text(encoding="utf-8"))
                final_response = next(
                    (
                        attempt["response"]
                        for attempt in reversed(value.get("attempts", []))
                        if isinstance(attempt.get("response"), dict)
                        and not attempt.get("validation_errors")
                    ),
                    None,
                )
                costs.append(
                    response_accounted_cost(provider, final_response)
                    if final_response is not None
                    else float(value.get("conservative_cost_upper_usd", 0.0))
                )
        if not costs:
            raise RuntimeError(f"cannot project full cost without a valid {provider} sample")
        remaining = max(total_tasks - len(costs), 0)
        projection += (sum(costs) / len(costs)) * remaining
    return projection


def round_reservation(task: dict, incomplete_providers: list[str]) -> float:
    system, user = prompt_material(task)
    estimated_input = (len(system) + len(user) + 2) // 3
    return sum(
        conservative_cost(
            provider,
            {
                "input_tokens": estimated_input,
                "output_tokens": MAX_OUTPUT_TOKEN_OVERRIDES.get(
                    (provider, task["task_id"]),
                    PROVIDERS[provider]["max_output_tokens"],
                ),
            },
        )
        for provider in incomplete_providers
    )


def write_run_manifest(run_dir: Path, budget: float, enforce_zdr: bool) -> None:
    files = [SYSTEM_PROMPT_PATH, GUIDE_PATH, USER_TEMPLATE_PATH, SCHEMA_PATH, INPUTS]
    manifest = {
        "protocol_version": PROTOCOL_VERSION,
        "created_at_utc": utc_now(),
        "budget_usd": budget,
        "budget_method": "conservative upper estimate; provider dashboards are authoritative",
        "price_safety_factor": PRICE_SAFETY_FACTOR,
        "privacy": {
            "openrouter": {
                "data_collection": "deny",
                "zdr_enforced": enforce_zdr,
            },
            "deepseek_official": {
                "openrouter_policy_not_applicable": True,
                "public_repository_code_only": True,
            },
        },
        "providers": {
            name: {
                "model": cfg["model"],
                "endpoint": cfg["url"],
                "kind": cfg["kind"],
                "max_output_tokens": cfg["max_output_tokens"],
                "input_usd_per_million": cfg["input_usd_per_million"],
                "output_usd_per_million": cfg["output_usd_per_million"],
            }
            for name, cfg in PROVIDERS.items()
        },
        "file_sha256": {
            path.relative_to(BASE_DIR).as_posix(): sha256_bytes(path.read_bytes()) for path in files
        },
    }
    destination = run_dir / "run_manifest.json"
    if destination.exists():
        existing = json.loads(destination.read_text(encoding="utf-8"))
        for key in ("protocol_version", "budget_usd", "privacy", "providers", "file_sha256"):
            if existing[key] != manifest[key]:
                raise RuntimeError(f"existing run manifest differs at {key}; use a new --run-id")
    else:
        atomic_json(destination, manifest)


def rebuild_normalized(run_dir: Path) -> None:
    for provider in PROVIDERS:
        rows = []
        source = run_dir / "raw" / provider
        if source.exists():
            for path in sorted(source.glob("AT-*.json")):
                value = json.loads(path.read_text(encoding="utf-8"))
                if value.get("status") == "completed":
                    rows.append(
                        {
                            "provider": provider,
                            "configured_model": value["configured_model"],
                            "returned_model": value["response_metadata"].get("returned_model"),
                            "task_id": value["task_id"],
                            "candidate_id": value["candidate_id"],
                            "input_sha256": value["input_sha256"],
                            "usage": value["usage"],
                            "upstream_provider": value["response_metadata"].get("upstream_provider"),
                            "reported_cost_usd": value["response_metadata"].get("reported_cost_usd"),
                            "conservative_cost_upper_usd": value["conservative_cost_upper_usd"],
                            "annotation": value["annotation"],
                        }
                    )
        destination = run_dir / "normalized" / f"{provider}.jsonl"
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_suffix(destination.suffix + ".tmp")
        with temporary.open("w", encoding="utf-8") as handle:
            for row in rows:
                handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
        temporary.replace(destination)


def summarize(run_dir: Path, total_tasks: int) -> dict:
    completed = {}
    failed = {}
    for provider in PROVIDERS:
        completed[provider] = len(list((run_dir / "raw" / provider).glob("AT-*.json")))
        failed[provider] = len(list((run_dir / "failures" / provider).glob("AT-*.json")))
    upstream_providers = {}
    for provider in PROVIDERS:
        names = set()
        source = run_dir / "raw" / provider
        if source.exists():
            for path in source.glob("AT-*.json"):
                value = json.loads(path.read_text(encoding="utf-8"))
                name = (value.get("response_metadata") or {}).get("upstream_provider")
                if name:
                    names.add(name)
        upstream_providers[provider] = sorted(names)
    accounted_cost = round(current_cost(run_dir), 6)
    summary = {
        "updated_at_utc": utc_now(),
        "tasks_per_provider": total_tasks,
        "completed": completed,
        "failed_files": failed,
        "completed_calls": sum(completed.values()),
        "target_calls": total_tasks * len(PROVIDERS),
        "budget_accounted_cost_usd": accounted_cost,
        "conservative_cost_upper_usd": accounted_cost,
        "upstream_providers": upstream_providers,
        "provider_consistency": all(len(names) <= 1 for names in upstream_providers.values()),
    }
    atomic_json(run_dir / "summary.json", summary)
    return summary


def run_phase(args: argparse.Namespace) -> int:
    tasks = load_inputs()
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    if args.phase == "dry-run":
        total_chars = sum(len(prompt_material(task)[0]) + len(prompt_material(task)[1]) for task in tasks)
        print("Dry run: PASS")
        print(f"Tasks: {len(tasks)}; providers: {len(PROVIDERS)}; target calls: {len(tasks) * len(PROVIDERS)}")
        print(f"Prompt characters per provider: {total_chars}")
        print(f"Secrets file expected at: {SECRETS_PATH}")
        return 0

    secrets = load_secrets(args.secrets)
    run_dir = RUNS_DIR / args.run_id
    enforce_zdr = not args.allow_non_zdr
    write_run_manifest(run_dir, args.budget_usd, enforce_zdr)
    if args.phase == "smoke" and args.task_id:
        by_id = {task["task_id"]: task for task in tasks}
        unknown = [task_id for task_id in args.task_id if task_id not in by_id]
        if unknown:
            raise RuntimeError(f"unknown --task-id values: {unknown}")
        selected_tasks = [by_id[task_id] for task_id in args.task_id]
    else:
        selected_tasks = tasks[: args.smoke_tasks] if args.phase == "smoke" else tasks

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(PROVIDERS)) as executor:
        for index, task in enumerate(selected_tasks, start=1):
            incomplete = [
                provider for provider in PROVIDERS
                if completed_result(run_dir, provider, task["task_id"]) is None
            ]
            if not incomplete:
                continue
            spent = current_cost(run_dir)
            reservation = round_reservation(task, incomplete)
            if spent + reservation + BUDGET_RESERVE_USD > args.budget_usd:
                print(
                    f"Budget stop before {task['task_id']}: upper={spent:.4f}, "
                    f"reservation={reservation:.4f}, reserve={BUDGET_RESERVE_USD:.2f}",
                    file=sys.stderr,
                )
                rebuild_normalized(run_dir)
                summarize(run_dir, len(tasks))
                return 4
            futures = {
                executor.submit(
                    run_one,
                    provider,
                    task,
                    schema,
                    secrets[PROVIDERS[provider]["key"]],
                    run_dir,
                    enforce_zdr,
                ): provider
                for provider in incomplete
            }
            statuses = {}
            for future, provider in futures.items():
                result = future.result()
                statuses[provider] = result["status"]
                append_jsonl(
                    run_dir / "events.jsonl",
                    {
                        "at_utc": utc_now(),
                        "task_id": task["task_id"],
                        "provider": provider,
                        "status": result["status"],
                        "attempt_count": result["attempt_count"],
                    },
                )
            consistency_check = summarize(run_dir, len(tasks))
            if not consistency_check["provider_consistency"]:
                print("Provider drift detected; stopping run.", file=sys.stderr)
                rebuild_normalized(run_dir)
                return 6
            spent = current_cost(run_dir)
            print(
                f"[{index}/{len(selected_tasks)}] {task['task_id']} "
                f"{statuses} upper_budget=${spent:.4f}",
                flush=True,
            )

    rebuild_normalized(run_dir)
    summary = summarize(run_dir, len(tasks))
    if args.phase == "smoke":
        projection = projected_full_cost(run_dir, len(tasks))
        summary["projected_full_budget_accounted_usd"] = round(projection, 4)
        summary["projected_full_upper_usd_from_smoke"] = round(projection, 4)
        atomic_json(run_dir / "summary.json", summary)
        missing_provider = [
            provider for provider, names in summary["upstream_providers"].items()
            if len(names) != 1
        ]
        if missing_provider:
            print(
                "Full run not started: upstream provider identity was not uniquely "
                f"observed for {missing_provider}.",
                file=sys.stderr,
            )
            return 7
        print(f"Projected full budget-accounted cost: ${projection:.4f}")
        if projection + BUDGET_RESERVE_USD > args.budget_usd:
            print("Full run not started: smoke projection exceeds approved budget.", file=sys.stderr)
            return 5
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if not any(summary["failed_files"].values()) else 2


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--phase", choices=("dry-run", "smoke", "full"), default="dry-run")
    parser.add_argument("--run-id", default="panel_v3_hybrid")
    parser.add_argument("--smoke-tasks", type=int, default=3)
    parser.add_argument(
        "--task-id",
        action="append",
        default=[],
        help="specific smoke task ID; repeat for a stratified smoke set",
    )
    parser.add_argument("--budget-usd", type=float, default=DEFAULT_BUDGET_USD)
    parser.add_argument("--secrets", type=Path, default=SECRETS_PATH)
    parser.add_argument(
        "--allow-non-zdr",
        action="store_true",
        help=(
            "allow endpoints that may retain prompts while still requiring "
            "provider.data_collection=deny; this choice is recorded in the manifest"
        ),
    )
    args = parser.parse_args()
    if not 1 <= args.smoke_tasks <= 20:
        parser.error("--smoke-tasks must be between 1 and 20")
    if args.task_id and args.phase != "smoke":
        parser.error("--task-id is only valid with --phase smoke")
    if len(args.task_id) != len(set(args.task_id)):
        parser.error("--task-id values must be unique")
    if not 0 < args.budget_usd <= DEFAULT_BUDGET_USD:
        parser.error(f"--budget-usd must be > 0 and <= approved ${DEFAULT_BUDGET_USD:.2f}")
    return args


if __name__ == "__main__":
    raise SystemExit(run_phase(parse_args()))
