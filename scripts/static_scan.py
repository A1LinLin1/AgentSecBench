"""Read-only static behavior scan over frozen Git commit trees.

Repository files are streamed from ``git archive`` and are never imported,
executed, installed, or extracted into the working directory.
"""

from __future__ import annotations

import argparse
import ast
import csv
import hashlib
import io
import json
import re
import subprocess
import sys
import tarfile
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent
DEFAULT_MANIFEST = BASE_DIR / "dataset" / "pilot_manifest.csv"
DEFAULT_OUTPUT = BASE_DIR / "analysis" / "raw_findings.jsonl"
DEFAULT_SUMMARY = BASE_DIR / "analysis" / "pilot_static_scan_summary.csv"
MAX_SOURCE_BYTES = 2_000_000

SOURCE_EXTENSIONS = {
    ".c",
    ".cc",
    ".cpp",
    ".cs",
    ".go",
    ".java",
    ".js",
    ".jsx",
    ".kt",
    ".kts",
    ".mjs",
    ".php",
    ".py",
    ".rb",
    ".rs",
    ".scala",
    ".sh",
    ".swift",
    ".ts",
    ".tsx",
}


@dataclass(frozen=True)
class Rule:
    category: str
    detector: str
    pattern: re.Pattern[str]
    confidence: str
    evidence: str


def rule(
    category: str,
    detector: str,
    pattern: str,
    confidence: str,
    evidence: str,
) -> Rule:
    return Rule(category, detector, re.compile(pattern, re.IGNORECASE), confidence, evidence)


RULES = [
    rule("command_execution", "py_subprocess", r"\bsubprocess\.(run|Popen|call|check_call|check_output)\s*\(", "high", "Python subprocess invocation"),
    rule("command_execution", "py_os_system", r"\bos\.(system|popen|spawn[a-z_]*|exec[a-z_]*)\s*\(", "high", "Python operating-system process invocation"),
    rule("command_execution", "js_child_process", r"\b(exec|execFile|spawn|fork)(Sync)?\s*\(", "medium", "JavaScript or TypeScript process invocation candidate"),
    rule("command_execution", "rust_command", r"\b(Command|TokioCommand)::new\s*\(", "high", "Rust process invocation"),
    rule("command_execution", "go_exec_command", r"\bexec\.Command(Context)?\s*\(", "high", "Go process invocation"),
    rule("command_execution", "dotnet_process", r"\bProcess\.(Start|StartAsync)\s*\(", "high", ".NET process invocation"),
    rule("command_execution", "shell_interpreter", r"\b(powershell|pwsh|cmd\.exe|/bin/(ba)?sh|bash\s+-c|sh\s+-c)\b", "medium", "Shell interpreter reference"),
    rule("dynamic_code_execution", "py_eval_exec", r"(?<![\w.])(?<!def\s)(?<!class\s)(eval|exec|compile)\s*\(", "high", "Python dynamic code evaluation"),
    rule("dynamic_code_execution", "js_eval_function", r"(?<![\w.])(eval\s*\(|new\s+Function\s*\(|vm\.runIn)", "high", "JavaScript dynamic code evaluation"),
    rule("filesystem_read", "py_file_read", r"\b(read_text|read_bytes|open)\s*\([^\n]*(?:['\"]r[b+t]?['\"]|encoding\s*=)", "medium", "Python file-read operation"),
    rule("filesystem_read", "js_file_read", r"\b(readFile|readFileSync|createReadStream)\s*\(", "high", "JavaScript or TypeScript file-read operation"),
    rule("filesystem_write", "py_file_write", r"\b(write_text|write_bytes)\s*\(|\bopen\s*\([^\n]*['\"][wax][b+t]?['\"]", "high", "Python file-write operation"),
    rule("filesystem_write", "js_file_write", r"\b(writeFile|writeFileSync|appendFile|createWriteStream)\s*\(", "high", "JavaScript or TypeScript file-write operation"),
    rule("filesystem_delete", "py_file_delete", r"\b(os\.(remove|unlink|rmdir)|shutil\.rmtree|Path\([^\n]*\)\.(unlink|rmdir))\s*\(", "high", "Python filesystem deletion"),
    rule("filesystem_delete", "js_file_delete", r"\b(rm|rmSync|unlink|unlinkSync|rmdir|rmdirSync)\s*\(", "medium", "JavaScript or TypeScript filesystem deletion candidate"),
    rule("network_access", "py_http_client", r"\b(requests|httpx|aiohttp)\.(get|post|put|patch|delete|request|stream)\s*\(", "high", "Python HTTP client request"),
    rule("network_access", "js_http_client", r"\b(fetch|axios\.(get|post|put|patch|delete|request)|got\.(get|post|put|delete))\s*\(", "high", "JavaScript or TypeScript HTTP request"),
    rule("network_access", "socket_api", r"\b(socket\.(socket|create_connection)|TcpStream::connect|net\.connect)\s*\(", "high", "Direct socket connection"),
    rule("browser_control", "browser_framework", r"\b(playwright|selenium|puppeteer|chromium\.(launch|connect)|webdriver)\b", "medium", "Browser automation framework reference"),
    rule("database_access", "database_client", r"\b(sqlite3|sqlalchemy|psycopg|asyncpg|pymongo|mongoose|prisma|create_engine|execute_query)\b", "medium", "Database client or query API reference"),
    rule("credential_access", "environment_secret", r"\b(os\.(getenv|environ)|process\.env|Environment\.GetEnvironmentVariable)\b[^\n]*(key|token|secret|password|credential|auth)", "high", "Credential-like environment access"),
    rule("credential_access", "secret_store", r"\b(keyring|keychain|secretmanager|secretsmanager|vault)\b", "medium", "Secret-store access candidate"),
    rule("external_tool_invocation", "mcp_tool_definition", r"(@(?:mcp|server)\.tool|FastMCP\s*\(|\bTool\s*\(|registerTool\s*\(|\.tool\s*\()", "high", "MCP or agent tool definition"),
    rule("external_tool_invocation", "langchain_tool_definition", r"(@tool\b|\bTool\s*\(|\bStructuredTool\.from_function\s*\(|\bcreate_react_agent\s*\(|\binitialize_agent\s*\()", "high", "LangChain tool or agent-tool binding"),
    rule("external_tool_invocation", "crewai_tool_definition", r"(@tool\b|\bBaseTool\b|\bAgent\s*\([^)]*tools\s*=|\bCrew\s*\([^)]*agents\s*=)", "medium", "CrewAI tool or agent binding"),
    rule("external_tool_invocation", "autogen_tool_registration", r"\b(register_for_llm|register_for_execution|register_function)\s*\(", "high", "AutoGen tool registration"),
    rule("external_tool_invocation", "openai_agents_tool_definition", r"(@function_tool\b|\bfunction_tool\s*\(|\bAgent\s*\([^)]*tools\s*=|\bRunner\.run\s*\()", "high", "OpenAI Agents SDK tool or agent execution"),
    rule("external_tool_invocation", "semantic_kernel_tool_definition", r"(@kernel_function\b|\bkernel_function\s*\(|\badd_plugin\s*\(|\bKernelPlugin\b)", "high", "Semantic Kernel function or plugin registration"),
    rule("external_tool_invocation", "llamaindex_tool_definition", r"\bFunctionTool\.from_defaults\s*\(|\bQueryEngineTool\.from_defaults\s*\(|\bReActAgent\.from_tools\s*\(", "high", "LlamaIndex function tool or agent-tool binding"),
    rule("external_tool_invocation", "mcp_call_tool", r"\b(call_tool|callTool|invoke_tool|invokeTool)\s*\(", "high", "External tool dispatch"),
    rule("message_or_email_send", "message_send", r"\b(send_mail|send_email|sendEmail|send_message|sendMessage|smtp\.send|chat\.postMessage)\s*\(", "high", "Message or email send operation"),
    rule("permission_or_auth_change", "permission_change", r"\b(chmod|chown|setfacl|add_role|assign_role|grant_permission|set_permissions?)\s*\(", "medium", "Permission or authorization change candidate"),
]

SYMBOL_PATTERNS = [
    re.compile(r"^\s*(?:async\s+def|def|class)\s+([A-Za-z_][\w]*)"),
    re.compile(r"^\s*(?:export\s+)?(?:async\s+)?function\s+([A-Za-z_$][\w$]*)"),
    re.compile(r"^\s*(?:export\s+)?class\s+([A-Za-z_$][\w$]*)"),
    re.compile(r"^\s*(?:pub\s+)?fn\s+([A-Za-z_][\w]*)"),
    re.compile(r"^\s*func\s+(?:\([^)]*\)\s*)?([A-Za-z_][\w]*)"),
]


def detector_applies_to_suffix(detector: str, suffix: str) -> bool:
    """Prevent language-specific regexes from inflating cross-language hits."""
    language_families = {
        "py_": {".py"},
        "js_": {".js", ".jsx", ".mjs", ".ts", ".tsx"},
        "rust_": {".rs"},
        "go_": {".go"},
        "dotnet_": {".cs"},
    }
    for prefix, allowed in language_families.items():
        if detector.startswith(prefix):
            return suffix in allowed
    return True


def python_dynamic_operation_lines(text: str) -> set[int]:
    """Return real Python ``eval``/``exec``/``compile`` call lines via AST.

    This deliberately rejects matches in comments, docstrings, string literals,
    and function declarations that a lexical regex cannot distinguish.
    """
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return set()
    return {
        node.lineno
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in {"eval", "exec", "compile"}
    }


def nearest_symbol(lines: list[str], line_index: int) -> str:
    lower = max(0, line_index - 30)
    for index in range(line_index, lower - 1, -1):
        for pattern in SYMBOL_PATTERNS:
            match = pattern.search(lines[index])
            if match:
                return match.group(1)
    return "<module>"


def iter_commit_files(repo_path: Path, commit: str):
    command = [
        "git",
        "-c",
        f"safe.directory={repo_path.as_posix()}",
        "-C",
        str(repo_path),
        "archive",
        "--format=tar",
        commit,
    ]
    # Stream mode occasionally presents an empty pipe on this Windows setup.
    # Capture the finite Git archive first, then safely iterate in memory.
    process = subprocess.run(command, capture_output=True, check=False)
    if not process.returncode and process.stdout:
        with tarfile.open(fileobj=io.BytesIO(process.stdout), mode="r:") as archive:
            for member in archive:
                if not member.isfile() or member.size > MAX_SOURCE_BYTES:
                    continue
                suffix = Path(member.name).suffix.lower()
                if suffix not in SOURCE_EXTENSIONS:
                    continue
                extracted = archive.extractfile(member)
                if extracted is None:
                    continue
                content = extracted.read()
                if b"\0" in content[:8192]:
                    continue
                yield member.name, content.decode("utf-8", errors="replace")
        return

    # A Git tree can contain names Windows cannot materialize (for example an
    # NTFS Zone.Identifier alternate-data-stream name).  `git archive` then
    # fails before yielding any valid source, even though Git can still read
    # individual blobs.  Fall back to a read-only tree listing and `git show`;
    # unsafe/non-source names are never materialized locally.
    listing = subprocess.run(
        [
            "git", "-c", f"safe.directory={repo_path.as_posix()}", "-C", str(repo_path),
            "ls-tree", "-r", "-z", "--name-only", commit,
        ],
        capture_output=True,
        check=False,
    )
    if listing.returncode:
        archive_error = process.stderr.decode("utf-8", errors="replace").strip()
        listing_error = listing.stderr.decode("utf-8", errors="replace").strip()
        raise RuntimeError(
            f"git archive and fallback tree listing failed for {repo_path}: "
            f"archive={archive_error}; ls-tree={listing_error}"
        )
    for encoded_path in listing.stdout.split(b"\0"):
        if not encoded_path:
            continue
        relative_path = encoded_path.decode("utf-8", errors="surrogateescape")
        suffix = Path(relative_path).suffix.lower()
        if suffix not in SOURCE_EXTENSIONS:
            continue
        blob = subprocess.run(
            [
                "git", "-c", f"safe.directory={repo_path.as_posix()}", "-C", str(repo_path),
                "show", f"{commit}:{relative_path}",
            ],
            capture_output=True,
            check=False,
        )
        if blob.returncode:
            continue
        content = blob.stdout
        if len(content) > MAX_SOURCE_BYTES or b"\0" in content[:8192]:
            continue
        yield relative_path, content.decode("utf-8", errors="replace")


def scan_repository(row: dict[str, str], scanned_at: str, granularity: str = "symbol") -> list[dict]:
    repo_path = (BASE_DIR / row["repository_path"]).resolve()
    grouped: dict[tuple[str, str, str], dict] = {}

    for relative_path, text in iter_commit_files(repo_path, row["git_commit"]):
        suffix = Path(relative_path).suffix.lower()
        lines = text.splitlines()
        python_dynamic_lines = python_dynamic_operation_lines(text) if suffix == ".py" else set()
        for line_index, source_line in enumerate(lines):
            if len(source_line) > 2_000:
                continue
            # Line-level regex matching must not classify prose, comments, or
            # the declaration ``def exec(...)`` as a dynamic operation.
            stripped = source_line.lstrip()
            if stripped.startswith(("#", "//", "/*", "*", '\"\"\"', "'''")):
                continue
            for detector_rule in RULES:
                if not detector_applies_to_suffix(detector_rule.detector, suffix):
                    continue
                if detector_rule.detector == "py_eval_exec" and line_index + 1 not in python_dynamic_lines:
                    continue
                if not detector_rule.pattern.search(source_line):
                    continue
                symbol = nearest_symbol(lines, line_index)
                # Symbol-level aggregation is compact for corpus overview, but
                # it can incorrectly join separate effectful calls in a long
                # function or module.  Line-level records are required before
                # any def-use / Security-ADG analysis.
                key_symbol = symbol if granularity == "symbol" else f"{symbol}@{line_index + 1}"
                key = (detector_rule.category, relative_path, key_symbol)
                normalized_line = source_line.strip().encode("utf-8", errors="replace")
                item = grouped.setdefault(
                    key,
                    {
                        "lines": set(),
                        "hashes": {},
                        "detectors": set(),
                        "evidence": set(),
                        "confidences": set(),
                        "symbol": symbol,
                    },
                )
                line_number = line_index + 1
                item["lines"].add(line_number)
                item["hashes"][line_number] = hashlib.sha256(normalized_line).hexdigest()
                item["detectors"].add(detector_rule.detector)
                item["evidence"].add(detector_rule.evidence)
                item["confidences"].add(detector_rule.confidence)

    findings: list[dict] = []
    for sequence, (key, item) in enumerate(sorted(grouped.items()), start=1):
        category, relative_path, _ = key
        symbol = item["symbol"]
        evidence_lines = sorted(item["lines"])
        persisted_lines = evidence_lines[:50]
        confidence = "high" if "high" in item["confidences"] else "medium"
        findings.append(
            {
                "annotation_id": f"SB-{row['sample_id']}-{sequence:05d}",
                "sample_id": row["sample_id"],
                "repo": row["repo"],
                "git_commit": row["git_commit"],
                "category": category,
                "file": relative_path,
                "line_start": evidence_lines[0],
                "line_end": evidence_lines[-1],
                "evidence_lines": persisted_lines,
                "evidence_line_sha256": [item["hashes"][line] for line in persisted_lines],
                "match_count": len(evidence_lines),
                "symbol": symbol,
                "evidence": "; ".join(sorted(item["evidence"])),
                "input_origin": "unknown",
                "guard": "unknown",
                "detector": ";".join(sorted(item["detectors"])),
                "confidence": confidence,
                "review_status": "candidate",
                "annotator": "static_scan_v1",
                "notes": "",
                "scanned_at_utc": scanned_at,
            }
        )
    return findings


def write_summary(findings: list[dict], manifest_rows: list[dict], output: Path) -> None:
    counts = Counter((item["repo"], item["category"]) for item in findings)
    categories = sorted({rule_item.category for rule_item in RULES})
    fields = ["sample_id", "repo", "total_candidates", *categories]
    with output.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for row in manifest_rows:
            category_counts = {category: counts[(row["repo"], category)] for category in categories}
            writer.writerow(
                {
                    "sample_id": row["sample_id"],
                    "repo": row["repo"],
                    "total_candidates": sum(category_counts.values()),
                    **category_counts,
                }
            )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--summary", type=Path, default=DEFAULT_SUMMARY)
    parser.add_argument("--skip-sample-id", action="append", default=[], help="Explicitly skip a corpus row that Git cannot archive on this platform.")
    parser.add_argument("--continue-on-error", action="store_true", help="Record repository scan failures and continue the remaining frozen repositories.")
    parser.add_argument(
        "--granularity",
        choices=("symbol", "line"),
        default="symbol",
        help="Use one candidate per symbol (overview) or per matched source line (dataflow-safe).",
    )
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    with args.manifest.open("r", encoding="utf-8-sig", newline="") as handle:
        manifest_rows = list(csv.DictReader(handle))

    scanned_at = datetime.now(timezone.utc).isoformat()
    findings: list[dict] = []
    skipped: list[dict] = []
    failures: list[dict] = []
    skipped_ids = set(args.skip_sample_id)
    for index, row in enumerate(manifest_rows, start=1):
        if row["sample_id"] in skipped_ids:
            print(f"[{index}/{len(manifest_rows)}] Skipping {row['repo']} (explicit platform exclusion)", flush=True)
            skipped.append({
                "sample_id": row["sample_id"],
                "repo": row["repo"],
                "reason": "explicit_platform_incompatible_git_archive",
            })
            continue
        print(f"[{index}/{len(manifest_rows)}] Scanning {row['repo']}", flush=True)
        try:
            findings.extend(scan_repository(row, scanned_at, args.granularity))
        except RuntimeError as error:
            if not args.continue_on_error:
                raise
            print(f"  Scan failed: {error}", file=sys.stderr, flush=True)
            failures.append({
                "sample_id": row["sample_id"],
                "repo": row["repo"],
                "reason": str(error),
            })

    args.output.parent.mkdir(parents=True, exist_ok=True)
    temporary = args.output.with_suffix(args.output.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        for finding in findings:
            handle.write(json.dumps(finding, ensure_ascii=False, sort_keys=True) + "\n")
    temporary.replace(args.output)
    write_summary(findings, manifest_rows, args.summary)
    run_manifest = {
        "manifest": str(args.manifest),
        "scanned_at_utc": scanned_at,
        "manifest_repositories": len(manifest_rows),
        "scanned_repositories": len(manifest_rows) - len(skipped) - len(failures),
        "skipped": skipped,
        "failures": failures,
        "candidate_count": len(findings),
        "candidate_granularity": args.granularity,
        "frozen_corpus_modified": False,
    }
    args.output.with_suffix(".run.json").write_text(json.dumps(run_manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")

    print(f"Candidate behaviors: {len(findings)}")
    print(f"Findings: {args.output}")
    print(f"Summary: {args.summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
