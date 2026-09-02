"""Serve a separate model-assisted human audit interface for AgentSecBench."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import secrets
import socket
import threading
import webbrowser
from http.server import ThreadingHTTPServer
from pathlib import Path

from serve_human_annotation import (
    AnnotationApp,
    AnnotationHub,
    BASE_DIR,
    ENUMS,
    INPUTS,
    LOCK,
    MANIFEST,
    atomic_jsonl,
    make_handler,
    normalize_annotator_id,
    read_jsonl,
    utc_now,
    validate,
)


RUN_ID = "panel_v3_hybrid"
RUN_DIR = BASE_DIR / "annotations" / "model_annotation" / "runs" / RUN_ID
QUEUE_PATH = RUN_DIR / "analysis" / "model_disagreement_queue.jsonl"
AUDIT_DIR = BASE_DIR / "annotations" / "model_audit"
AUDIT_UI_DIR = BASE_DIR / "annotations" / "model_audit_ui"
INVITATIONS_PATH = AUDIT_DIR / "invitations.local.json"
PROVIDERS = ("openai", "anthropic", "gemini", "qwen", "deepseek")
VOTE_FIELDS = tuple(ENUMS)


def audit_path(reviewer: str) -> Path:
    return AUDIT_DIR / "reviewers" / f"reviewer_{reviewer.lower()}.jsonl"


def blank_audit(task: dict, reviewer: str) -> dict:
    row = {
        field: None
        for field in ENUMS
    }
    row.update(
        {
            "audit_note": "",
            "candidate_id": task["candidate_id"],
            "effect_target": "",
            "guard_types": [],
            "model_panel_run_id": RUN_ID,
            "rationale": "",
            "review_type": "model_assisted_audit",
            "reviewer": reviewer,
            "task_id": task["task_id"],
        }
    )
    return row


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
        temporary.write_text(
            json.dumps(existing, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
        )
        temporary.replace(INVITATIONS_PATH)
    return {existing[reviewer]: reviewer for reviewer in reviewers}


class ModelAuditApp(AnnotationApp):
    def __init__(self, reviewer: str):
        self.annotator = normalize_annotator_id(reviewer)
        source_tasks = {row["task_id"]: row for row in read_jsonl(INPUTS)}
        self.queue = read_jsonl(QUEUE_PATH)
        self.tasks = [source_tasks[row["task_id"]] for row in self.queue]
        self.by_id = {row["task_id"]: row for row in self.tasks}
        self.queue_by_id = {row["task_id"]: row for row in self.queue}
        self.model_annotations: dict[str, dict[str, dict]] = {}
        for provider in PROVIDERS:
            rows = read_jsonl(RUN_DIR / "normalized" / f"{provider}.jsonl")
            for row in rows:
                self.model_annotations.setdefault(row["task_id"], {})[provider] = row["annotation"]
        if any(set(value) != set(PROVIDERS) for value in self.model_annotations.values()):
            raise RuntimeError("model panel is incomplete")
        self.path = audit_path(self.annotator)
        if self.path.exists():
            rows = read_jsonl(self.path)
        else:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            rows = [blank_audit(task, self.annotator) for task in self.tasks]
            atomic_jsonl(self.path, rows)
        self.annotations = {row["task_id"]: row for row in rows}
        with MANIFEST.open(encoding="utf-8-sig", newline="") as handle:
            self.repositories = {
                row["repo"]: BASE_DIR / row["repository_path"] for row in csv.DictReader(handle)
            }
        if set(self.annotations) != set(self.by_id):
            raise RuntimeError("audit result file and task bundle have different task IDs")

    def task_index(self) -> list[dict]:
        rows = []
        for task in self.tasks:
            panel = self.queue_by_id[task["task_id"]]
            rows.append(
                {
                    "task_id": task["task_id"],
                    "candidate_id": task["candidate_id"],
                    "repository": task["repository"],
                    "file": task["file"],
                    "candidate_behavior": task["candidate_behavior"],
                    "priority": panel["priority"],
                    "disagreement_score": panel["disagreement_score"],
                    "disagreement_fields": panel["disagreement_fields"],
                    "status": self.annotations[task["task_id"]].get("_status", "draft"),
                }
            )
        return rows

    def get_task(self, task_id: str) -> dict:
        if task_id not in self.by_id:
            raise KeyError(task_id)
        panel = self.queue_by_id[task_id]
        return {
            "task": self.by_id[task_id],
            "annotation": self.annotations[task_id],
            "annotator": self.annotator,
            "audit_mode": "model_assisted_audit",
            "panel": {
                "run_id": RUN_ID,
                "providers": list(PROVIDERS),
                "priority": panel["priority"],
                "disagreement_score": panel["disagreement_score"],
                "disagreement_fields": panel["disagreement_fields"],
                "votes": panel["votes"],
                "annotations": self.model_annotations[task_id],
            },
        }

    def save(self, task_id: str, annotation: dict, complete: bool) -> dict:
        if task_id not in self.by_id:
            raise KeyError(task_id)
        if annotation.get("task_id") != task_id:
            raise ValueError("task_id mismatch")
        if annotation.get("candidate_id") != self.by_id[task_id]["candidate_id"]:
            raise ValueError("candidate_id mismatch")
        errors = validate(annotation, complete)
        if complete and not str(annotation.get("audit_note", "")).strip():
            errors.append("audit_note 尚未填写：请说明接受或修改模型意见的依据")
        if errors:
            return {"ok": False, "errors": errors}
        panel = self.queue_by_id[task_id]
        overridden = []
        tied = []
        plurality = {}
        for field in VOTE_FIELDS:
            vote = panel["votes"][field]
            plurality[field] = vote["plurality_label"]
            if vote["tie"]:
                tied.append(field)
            elif annotation.get(field) != vote["plurality_label"]:
                overridden.append(field)
        snapshot = {
            "run_id": RUN_ID,
            "task_id": task_id,
            "votes": panel["votes"],
        }
        saved = {
            **annotation,
            "reviewer": self.annotator,
            "review_type": "model_assisted_audit",
            "model_panel_run_id": RUN_ID,
            "panel_plurality": plurality,
            "panel_tied_fields": tied,
            "overridden_plurality_fields": overridden,
            "panel_alignment": (
                "modified_plurality"
                if overridden
                else "resolved_ties_only"
                if tied
                else "accepted_plurality"
            ),
            "panel_snapshot_sha256": hashlib.sha256(
                json.dumps(snapshot, sort_keys=True).encode("utf-8")
            ).hexdigest(),
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
        return {
            "ok": True,
            "status": saved["_status"],
            "panel_alignment": saved["panel_alignment"],
            "overridden_fields": overridden,
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reviewer", action="append", required=True)
    parser.add_argument("--port", type=int, default=8766)
    parser.add_argument("--share", action="store_true")
    parser.add_argument("--bind", choices=("127.0.0.1", "0.0.0.0"))
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    reviewers = [normalize_annotator_id(value) for value in args.reviewer]
    if len(set(value.lower() for value in reviewers)) != len(reviewers):
        parser.error("duplicate reviewer IDs")
    shared = args.share or len(reviewers) > 1
    if shared:
        token_to_id = load_invitations(reviewers)
        hub = AnnotationHub(
            {token: ModelAuditApp(reviewer) for token, reviewer in token_to_id.items()}
        )
        bind = args.bind or "0.0.0.0"
        if bind == "127.0.0.1":
            display_host = bind
        else:
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
        app = ModelAuditApp(reviewers[0])
        hub = AnnotationHub({None: app})
        bind = args.bind or "127.0.0.1"
        urls = {reviewers[0]: f"http://127.0.0.1:{args.port}/"}
    server = ThreadingHTTPServer((bind, args.port), make_handler(hub, AUDIT_UI_DIR))
    print("AgentSecBench model-assisted audit")
    for reviewer, url in urls.items():
        print(f"[{reviewer}] {url}")
    print("This mode exposes model votes and must not be used as independent blind annotation.")
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
