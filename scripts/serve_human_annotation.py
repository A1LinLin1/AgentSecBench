"""Serve a local, blinded web UI for AgentSecBench human annotation."""

from __future__ import annotations

import argparse
import csv
import json
import re
import secrets
import socket
import subprocess
import threading
import webbrowser
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse


BASE_DIR = Path(__file__).resolve().parent.parent
INPUTS = BASE_DIR / "annotations" / "model_annotation" / "inputs" / "model_tasks_blinded.jsonl"
MANIFEST = BASE_DIR / "dataset" / "pilot_manifest.csv"
ANNOTATOR_DIR = BASE_DIR / "annotations" / "annotator"
UI_DIR = BASE_DIR / "annotations" / "human_annotation_ui"
LOCK = threading.Lock()
INVITATIONS_PATH = ANNOTATOR_DIR / "invitations.local.json"

ENUMS = {
    "behavior_confirmed": {"true", "false", "uncertain"},
    "agent_relevant": {"true", "false", "uncertain"},
    "source_type": {
        "user_prompt", "web_content", "file_content", "tool_output", "message_email",
        "database", "environment_config", "internal_constant", "unknown", "none",
    },
    "source_external": {"true", "false", "unknown"},
    "dependency_confirmed": {"true", "false", "partial", "unknown"},
    "trust_boundary_crossed": {"true", "false", "unknown"},
    "effect_type": {
        "command_execution", "dynamic_code_execution", "filesystem_read", "filesystem_write",
        "filesystem_delete", "browser_control", "network_access", "credential_access",
        "database_access", "external_tool_invocation", "other", "none",
    },
    "guard_present": {"true", "false", "unknown"},
    "guard_effective": {"yes", "no", "partial", "unknown", "not_applicable"},
    "weakness_present": {"true", "false", "uncertain"},
    "vulnerability_status": {"not_assessed", "candidate", "confirmed", "rejected"},
    "label_confidence": {"high", "medium", "low"},
}
GUARDS = {
    "allowlist", "schema_validation", "canonicalization", "authorization",
    "user_confirmation", "sandbox", "escaping", "least_privilege",
    "destination_restriction", "secret_redaction", "other",
}
REQUIRED = tuple(ENUMS) + ("effect_target", "rationale")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def read_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as handle:
        return [json.loads(line) for line in handle if line.strip()]


def atomic_jsonl(path: Path, rows: list[dict]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, ensure_ascii=False, sort_keys=True) + "\n")
    temporary.replace(path)


def normalize_annotator_id(annotator: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", annotator):
        raise ValueError("annotator ID 只能包含英文字母、数字、下划线和连字符，最长 40 位")
    return annotator


def annotation_path(annotator: str) -> Path:
    if annotator.upper() in {"A", "B"}:
        return ANNOTATOR_DIR / f"annotator_{annotator.lower()}.jsonl"
    return ANNOTATOR_DIR / "participants" / f"annotator_{annotator.lower()}.jsonl"


def blank_annotation(task: dict, annotator: str) -> dict:
    return {
        "agent_relevant": None,
        "annotator": annotator,
        "behavior_confirmed": None,
        "candidate_id": task["candidate_id"],
        "dependency_confirmed": None,
        "effect_target": None,
        "effect_type": None,
        "guard_effective": None,
        "guard_present": None,
        "guard_types": [],
        "label_confidence": None,
        "rationale": "",
        "source_external": None,
        "source_type": None,
        "task_id": task["task_id"],
        "trust_boundary_crossed": None,
        "vulnerability_status": "not_assessed",
        "weakness_present": None,
    }


def load_invitations(annotators: list[str]) -> dict[str, str]:
    existing = {}
    if INVITATIONS_PATH.exists():
        existing = json.loads(INVITATIONS_PATH.read_text(encoding="utf-8"))
    changed = False
    for annotator in annotators:
        if annotator not in existing:
            existing[annotator] = secrets.token_urlsafe(24)
            changed = True
    if changed:
        INVITATIONS_PATH.parent.mkdir(parents=True, exist_ok=True)
        temporary = INVITATIONS_PATH.with_suffix(".tmp")
        temporary.write_text(json.dumps(existing, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        temporary.replace(INVITATIONS_PATH)
    return {existing[annotator]: annotator for annotator in annotators}


def validate(annotation: dict, complete: bool) -> list[str]:
    errors = []
    for field, allowed in ENUMS.items():
        value = annotation.get(field)
        if value is None and not complete:
            continue
        if value not in allowed:
            errors.append(f"{field} 必须选择一个值")
    guards = annotation.get("guard_types", [])
    if not isinstance(guards, list) or any(value not in GUARDS for value in guards):
        errors.append("guard_types 包含非法值")
    if complete:
        for field in REQUIRED:
            value = annotation.get(field)
            if value is None or (field == "rationale" and not str(value).strip()):
                errors.append(f"{field} 尚未填写")
    if annotation.get("source_type") == "none" and annotation.get("source_external") != "false":
        errors.append("source_type=none 时 source_external 必须为 false")
    if annotation.get("dependency_confirmed") == "false" and annotation.get("trust_boundary_crossed") != "false":
        errors.append("dependency=false 时 trust_boundary 必须为 false")
    if annotation.get("guard_present") == "false":
        if guards:
            errors.append("guard_present=false 时不能选择 guard_types")
        if annotation.get("guard_effective") != "not_applicable":
            errors.append("guard_present=false 时 guard_effective 必须为 not_applicable")
    if annotation.get("vulnerability_status") == "confirmed" and not (
        annotation.get("weakness_present") == "true"
        and annotation.get("dependency_confirmed") == "true"
        and annotation.get("trust_boundary_crossed") == "true"
    ):
        errors.append("confirmed vulnerability 要求 weakness、dependency、boundary 全部为 true")
    return errors


class AnnotationApp:
    def __init__(self, annotator: str):
        self.annotator = normalize_annotator_id(annotator)
        self.tasks = read_jsonl(INPUTS)
        self.by_id = {row["task_id"]: row for row in self.tasks}
        self.path = annotation_path(self.annotator)
        if self.path.exists():
            rows = read_jsonl(self.path)
        else:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            rows = [blank_annotation(task, self.annotator) for task in self.tasks]
            atomic_jsonl(self.path, rows)
        self.annotations = {row["task_id"]: row for row in rows}
        with MANIFEST.open(encoding="utf-8-sig", newline="") as handle:
            self.repositories = {row["repo"]: BASE_DIR / row["repository_path"] for row in csv.DictReader(handle)}
        if set(self.annotations) != set(self.by_id):
            raise RuntimeError("annotator template and task bundle have different task IDs")

    def task_index(self) -> list[dict]:
        return [
            {
                "task_id": task["task_id"],
                "candidate_id": task["candidate_id"],
                "repository": task["repository"],
                "file": task["file"],
                "candidate_behavior": task["candidate_behavior"],
                "status": self.annotations[task["task_id"]].get("_status", "draft"),
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
        }

    def save(self, task_id: str, annotation: dict, complete: bool) -> dict:
        if task_id not in self.by_id:
            raise KeyError(task_id)
        if annotation.get("task_id") != task_id:
            raise ValueError("task_id 不匹配")
        if annotation.get("candidate_id") != self.by_id[task_id]["candidate_id"]:
            raise ValueError("candidate_id 不匹配")
        errors = validate(annotation, complete)
        if errors:
            return {"ok": False, "errors": errors}
        saved = {**annotation, "annotator": self.annotator}
        saved["_status"] = "completed" if complete else "draft"
        saved["_saved_at_utc"] = utc_now()
        if complete:
            saved["_completed_at_utc"] = utc_now()
        else:
            saved.pop("_completed_at_utc", None)
        with LOCK:
            self.annotations[task_id] = saved
            rows = [self.annotations[task["task_id"]] for task in self.tasks]
            atomic_jsonl(self.path, rows)
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
        numbered = "\n".join(f"{number:6d} | {line}" for number, line in enumerate(text.splitlines(), 1))
        return {"task_id": task_id, "source_context": numbered, "full_file": True}


class AnnotationHub:
    def __init__(self, apps: dict[str | None, AnnotationApp]):
        self.apps = apps

    def resolve(self, invite: str | None) -> AnnotationApp | None:
        if None in self.apps and len(self.apps) == 1:
            return self.apps[None]
        return self.apps.get(invite)


def make_handler(hub: AnnotationHub, ui_dir: Path = UI_DIR):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args) -> None:
            return

        def send_bytes(self, data: bytes, content_type: str, status: int = 200) -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(data)

        def send_json(self, value: object, status: int = 200) -> None:
            self.send_bytes(
                json.dumps(value, ensure_ascii=False).encode("utf-8"),
                "application/json; charset=utf-8",
                status,
            )

        def annotation_app(self, parsed) -> AnnotationApp | None:
            invite = self.headers.get("X-Annotation-Invite")
            if not invite:
                invite = parse_qs(parsed.query).get("invite", [None])[0]
            app = hub.resolve(invite)
            if app is None:
                self.send_json(
                    {"error": "邀请链接无效，请使用研究负责人发送的完整链接。"},
                    HTTPStatus.UNAUTHORIZED,
                )
            return app

        def do_GET(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path == "/api/tasks":
                app = self.annotation_app(parsed)
                if app is None:
                    return
                self.send_json({"annotator": app.annotator, "tasks": app.task_index()})
                return
            if parsed.path == "/api/task":
                app = self.annotation_app(parsed)
                if app is None:
                    return
                task_id = parse_qs(parsed.query).get("id", [""])[0]
                try:
                    self.send_json(app.get_task(task_id))
                except KeyError:
                    self.send_json({"error": "unknown task"}, HTTPStatus.NOT_FOUND)
                return
            if parsed.path == "/api/full-source":
                app = self.annotation_app(parsed)
                if app is None:
                    return
                task_id = parse_qs(parsed.query).get("id", [""])[0]
                try:
                    self.send_json(app.full_source(task_id))
                except KeyError:
                    self.send_json({"error": "unknown task"}, HTTPStatus.NOT_FOUND)
                except (subprocess.SubprocessError, OSError) as error:
                    self.send_json({"error": str(error)}, HTTPStatus.INTERNAL_SERVER_ERROR)
                return
            static = {
                "/": ("index.html", "text/html; charset=utf-8"),
                "/app.js": ("app.js", "text/javascript; charset=utf-8"),
                "/style.css": ("style.css", "text/css; charset=utf-8"),
            }
            if parsed.path == "/base.css":
                self.send_bytes((UI_DIR / "style.css").read_bytes(), "text/css; charset=utf-8")
                return
            if parsed.path in static:
                name, content_type = static[parsed.path]
                self.send_bytes((ui_dir / name).read_bytes(), content_type)
                return
            self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

        def do_POST(self) -> None:
            parsed = urlparse(self.path)
            if parsed.path != "/api/save":
                self.send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)
                return
            app = self.annotation_app(parsed)
            if app is None:
                return
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > 1_000_000:
                self.send_json({"error": "invalid body size"}, HTTPStatus.BAD_REQUEST)
                return
            try:
                body = json.loads(self.rfile.read(length))
                result = app.save(
                    body["task_id"], body["annotation"], bool(body.get("complete"))
                )
                self.send_json(result, 200 if result["ok"] else 422)
            except (KeyError, ValueError, json.JSONDecodeError) as error:
                self.send_json({"ok": False, "errors": [str(error)]}, HTTPStatus.BAD_REQUEST)

    return Handler


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--annotator",
        action="append",
        required=True,
        help="annotator ID; repeat to create separate invitation links",
    )
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument(
        "--share",
        action="store_true",
        help="listen on the local network and require per-annotator invitation links",
    )
    parser.add_argument(
        "--bind",
        choices=("127.0.0.1", "0.0.0.0"),
        help="override listen address; use 127.0.0.1 behind an HTTPS tunnel",
    )
    parser.add_argument("--no-browser", action="store_true")
    args = parser.parse_args()
    annotators = [normalize_annotator_id(value) for value in args.annotator]
    if len(set(value.lower() for value in annotators)) != len(annotators):
        parser.error("duplicate --annotator IDs")
    shared = args.share or len(annotators) > 1
    if shared:
        token_to_id = load_invitations(annotators)
        hub = AnnotationHub(
            {token: AnnotationApp(annotator) for token, annotator in token_to_id.items()}
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
            annotator: f"http://{display_host}:{args.port}/#invite={token}"
            for token, annotator in token_to_id.items()
        }
    else:
        if args.bind and args.bind != "127.0.0.1":
            parser.error("non-local --bind requires --share so invitation authentication is enabled")
        app = AnnotationApp(annotators[0])
        hub = AnnotationHub({None: app})
        bind = args.bind or "127.0.0.1"
        urls = {annotators[0]: f"http://127.0.0.1:{args.port}/"}
    server = ThreadingHTTPServer((bind, args.port), make_handler(hub))
    print("AgentSecBench blinded human annotation")
    for annotator, url in urls.items():
        print(f"[{annotator}] {url}")
    print("Only local frozen source context is shown; model votes remain hidden.")
    if shared:
        print("Keep this terminal running. Send each participant only their own URL.")
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
