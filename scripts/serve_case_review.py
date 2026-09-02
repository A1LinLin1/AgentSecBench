"""Serve an intuitive case-level security review UI for assisted findings."""

from __future__ import annotations

import argparse
import csv
import json
import secrets
import socket
import subprocess
import threading
import webbrowser
from http.server import ThreadingHTTPServer
from pathlib import Path

from serve_human_annotation import (
    AnnotationHub,
    BASE_DIR,
    LOCK,
    MANIFEST,
    atomic_jsonl,
    make_handler,
    normalize_annotator_id,
    read_jsonl,
    utc_now,
)


QUEUE_PATH = BASE_DIR / "analysis" / "case_review" / "vulnerability_case_queue.jsonl"
RESULT_DIR = BASE_DIR / "analysis" / "case_review" / "reviews"
UI_DIR = BASE_DIR / "annotations" / "case_review_ui"
INVITATIONS_PATH = BASE_DIR / "analysis" / "case_review" / "invitations.local.json"

ENUMS = {
    "reachability": {"documented_default", "conditional", "not_reachable", "unknown"},
    "caller_trust": {"untrusted_or_model", "trusted_only", "unknown"},
    "access_control": {"absent", "present_ineffective", "present_effective", "unknown"},
    "case_relation": {"new_case", "merge_existing", "not_security_case", "unknown"},
    "final_case_label": {
        "confirmed_vulnerability", "vulnerability_candidate", "unsafe_capability",
        "rejected", "insufficient_context",
    },
}
IMPACTS = {
    "command_execution", "file_read", "file_write", "credential_access", "network_access",
    "browser_control", "availability", "other", "none",
}

REPOSITORY_EVIDENCE = {
    "AT-0032": {
        "proposed_case_id": "ASB-CASE-0001",
        "proposed_title": "Exposed ManusMCP host-control tools",
        "items": [
            "docker-compose.yml lines 13-21 publish container port 8000 as host port 8002.",
            "Dockerfile lines 22-23 start supergateway over the TypeScript MCP server without an authentication option.",
            ".runtime/index.ts lines 110-120 expose caller-controlled shell_exec.",
            ".runtime/src/services/shellService.ts lines 12-25 pass the command to spawn with shell=true.",
            "flow.json enables the shell MCP actions through http://localhost:8002/sse.",
        ],
    },
    "AT-0049": {
        "proposed_case_id": "ASB-CASE-0001",
        "proposed_title": "Exposed ManusMCP host-control tools",
        "items": [
            "docker-compose.yml lines 13-21 publish container port 8000 as host port 8002.",
            "Dockerfile lines 22-23 start supergateway over the TypeScript MCP server without an authentication option.",
            ".runtime/index.ts lines 20-31 expose caller-controlled file_read.",
            ".runtime/src/services/fileService.ts lines 17-29 read the caller-provided path directly.",
            "flow.json enables the file MCP actions through http://localhost:8002/sse.",
        ],
    },
}


def result_path(reviewer: str) -> Path:
    return RESULT_DIR / f"reviewer_{reviewer.lower()}.jsonl"


def blank_review(packet: dict, reviewer: str) -> dict:
    hint = REPOSITORY_EVIDENCE.get(packet["task_id"], {})
    return {
        "task_id": packet["task_id"],
        "candidate_id": packet["candidate_id"],
        "reviewer": reviewer,
        "review_type": "case_level_security_review",
        "reachability": None,
        "caller_trust": None,
        "access_control": None,
        "impacts": [],
        "case_relation": None,
        "case_id": "",
        "case_title": "",
        "merge_into_case_id": "",
        "root_cause": "",
        "final_case_label": None,
        "evidence_refs": "",
        "rationale": "",
        "missing_context": "",
        "proposed_case_id": hint.get("proposed_case_id"),
    }


def validate_review(review: dict, complete: bool) -> list[str]:
    errors = []
    for field, allowed in ENUMS.items():
        value = review.get(field)
        if value is None and not complete:
            continue
        if value not in allowed:
            errors.append(f"{field} 尚未选择")
    impacts = review.get("impacts", [])
    if not isinstance(impacts, list) or any(value not in IMPACTS for value in impacts):
        errors.append("impacts 包含非法值")
    if "none" in impacts and len(impacts) > 1:
        errors.append("选择“无直接影响”时不能同时选择其他影响")
    if complete:
        if not impacts:
            errors.append("至少选择一个安全影响；没有影响请选择“无直接影响”")
        for field in ("root_cause", "evidence_refs", "rationale"):
            if not str(review.get(field, "")).strip():
                errors.append(f"{field} 尚未填写")
        relation = review.get("case_relation")
        if relation == "new_case" and not str(review.get("case_id", "")).strip():
            errors.append("新案例必须填写案例编号")
        if relation == "merge_existing" and not str(review.get("merge_into_case_id", "")).strip():
            errors.append("合并已有案例必须填写目标案例编号")
        if review.get("final_case_label") == "confirmed_vulnerability" and (
            review.get("reachability") not in {"documented_default", "conditional"}
            or review.get("caller_trust") != "untrusted_or_model"
            or review.get("access_control") == "present_effective"
            or "none" in impacts
        ):
            errors.append("确认漏洞要求行为可达、不可信或模型输入可控、无有效访问控制且存在安全影响")
        if review.get("final_case_label") == "insufficient_context" and not str(
            review.get("missing_context", "")
        ).strip():
            errors.append("上下文不足时必须说明缺少什么证据")
    return errors


def load_invitations(reviewers: list[str]) -> dict[str, str]:
    existing = {}
    if INVITATIONS_PATH.exists():
        existing = json.loads(INVITATIONS_PATH.read_text(encoding="utf-8"))
    changed = False
    for reviewer in reviewers:
        if reviewer not in existing:
            existing[reviewer] = secrets.token_urlsafe(24)
            changed = True
    if changed:
        INVITATIONS_PATH.parent.mkdir(parents=True, exist_ok=True)
        temporary = INVITATIONS_PATH.with_suffix(".tmp")
        temporary.write_text(json.dumps(existing, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        temporary.replace(INVITATIONS_PATH)
    return {existing[reviewer]: reviewer for reviewer in reviewers}


class CaseReviewApp:
    def __init__(self, reviewer: str, source_reviewer: str | None = None):
        self.annotator = normalize_annotator_id(reviewer)
        self.source_reviewer = normalize_annotator_id(source_reviewer) if source_reviewer else None
        self.tasks = read_jsonl(QUEUE_PATH)
        self.by_id = {row["task_id"]: row for row in self.tasks}
        self.path = result_path(self.annotator)
        if self.path.exists():
            rows = read_jsonl(self.path)
        else:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            rows = [blank_review(task, self.annotator) for task in self.tasks]
            atomic_jsonl(self.path, rows)
        self.annotations = {row["task_id"]: row for row in rows}
        if set(self.annotations) != set(self.by_id):
            raise RuntimeError("case-review result file and queue have different task IDs")
        self.source_annotations: dict[str, dict] = {}
        if self.source_reviewer:
            source_path = result_path(self.source_reviewer)
            if not source_path.exists():
                raise FileNotFoundError(f"source reviewer result does not exist: {source_path}")
            self.source_annotations = {row["task_id"]: row for row in read_jsonl(source_path)}
            if set(self.source_annotations) != set(self.by_id):
                raise RuntimeError("source-review result file and queue have different task IDs")
        with MANIFEST.open(encoding="utf-8-sig", newline="") as handle:
            self.repositories = {
                row["repo"]: BASE_DIR / row["repository_path"] for row in csv.DictReader(handle)
            }

    def task_index(self) -> list[dict]:
        return [
            {
                "task_id": task["task_id"],
                "candidate_id": task["candidate_id"],
                "repository": task["repository"],
                "file": task["file"],
                "candidate_behavior": task["candidate_behavior"],
                "assisted_status": task["assisted_status"],
                "status": self.annotations[task["task_id"]].get("_status", "draft"),
                "final_case_label": self.annotations[task["task_id"]].get("final_case_label"),
                "case_id": self.annotations[task["task_id"]].get("case_id"),
                "merge_into_case_id": self.annotations[task["task_id"]].get("merge_into_case_id"),
            }
            for task in self.tasks
        ]

    def get_task(self, task_id: str) -> dict:
        if task_id not in self.by_id:
            raise KeyError(task_id)
        return {
            "task": self.by_id[task_id],
            "annotation": self.annotations[task_id],
            "annotator": self.annotator,
            "repository_evidence": REPOSITORY_EVIDENCE.get(task_id),
            "source_reviewer": self.source_reviewer,
            "source_review": self.source_annotations.get(task_id),
        }

    def save(self, task_id: str, annotation: dict, complete: bool) -> dict:
        if task_id not in self.by_id:
            raise KeyError(task_id)
        if annotation.get("task_id") != task_id:
            raise ValueError("task_id 不匹配")
        if annotation.get("candidate_id") != self.by_id[task_id]["candidate_id"]:
            raise ValueError("candidate_id 不匹配")
        errors = validate_review(annotation, complete)
        if errors:
            return {"ok": False, "errors": errors}
        saved = {
            **annotation,
            "reviewer": self.annotator,
            "review_type": "case_level_security_review",
            "_status": "completed" if complete else "draft",
            "_saved_at_utc": utc_now(),
        }
        if complete:
            saved["_completed_at_utc"] = utc_now()
        else:
            saved.pop("_completed_at_utc", None)
        with LOCK:
            self.annotations[task_id] = saved
            atomic_jsonl(self.path, [self.annotations[task["task_id"]] for task in self.tasks])
        return {"ok": True, "status": saved["_status"]}

    def full_source(self, task_id: str) -> dict:
        if task_id not in self.by_id:
            raise KeyError(task_id)
        task = self.by_id[task_id]
        repository = self.repositories[task["repository"]]
        result = subprocess.run(
            [
                "git", "-c", f"safe.directory={repository.as_posix()}",
                "-C", str(repository), "show", f"{task['git_commit']}:{task['file']}",
            ],
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=30,
        )
        text = result.stdout.decode("utf-8", errors="replace")
        numbered = "\n".join(
            f"{number:6d} | {line}" for number, line in enumerate(text.splitlines(), 1)
        )
        return {"task_id": task_id, "source_context": numbered, "full_file": True}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reviewer", action="append", required=True)
    parser.add_argument("--source-reviewer", help="show another completed review as an adjudication proposal")
    parser.add_argument("--port", type=int, default=8767)
    parser.add_argument("--share", action="store_true")
    parser.add_argument("--bind", choices=("127.0.0.1", "0.0.0.0"))
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    reviewers = [normalize_annotator_id(value) for value in args.reviewer]
    source_reviewer = normalize_annotator_id(args.source_reviewer) if args.source_reviewer else None
    if len(set(value.lower() for value in reviewers)) != len(reviewers):
        parser.error("duplicate reviewer IDs")
    shared = args.share or len(reviewers) > 1
    if shared:
        token_to_id = load_invitations(reviewers)
        hub = AnnotationHub({
            token: CaseReviewApp(reviewer, source_reviewer) for token, reviewer in token_to_id.items()
        })
        bind = args.bind or "0.0.0.0"
        display_host = bind
        if bind == "0.0.0.0":
            try:
                display_host = socket.gethostbyname(socket.gethostname())
            except OSError:
                display_host = "<local-network-IP>"
        urls = {
            reviewer: f"http://{display_host}:{args.port}/#invite={token}"
            for token, reviewer in token_to_id.items()
        }
    else:
        if args.bind and args.bind != "127.0.0.1":
            parser.error("non-local --bind requires --share")
        if source_reviewer and source_reviewer.lower() == reviewers[0].lower():
            parser.error("reviewer and source reviewer must be different")
        app = CaseReviewApp(reviewers[0], source_reviewer)
        hub = AnnotationHub({None: app})
        bind = args.bind or "127.0.0.1"
        urls = {reviewers[0]: f"http://127.0.0.1:{args.port}/"}
    server = ThreadingHTTPServer((bind, args.port), make_handler(hub, UI_DIR))
    print("AgentSecBench case-level security review")
    for reviewer, url in urls.items():
        print(f"[{reviewer}] {url}")
    print("Finding count is not vulnerability count. Cluster by root cause before counting cases.")
    print("Press Ctrl+C to stop.")
    if not args.no_browser and not shared:
        threading.Timer(0.5, lambda: webbrowser.open(next(iter(urls.values())))).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
