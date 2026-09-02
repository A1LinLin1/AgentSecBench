"""Smoke-test the case-review server and static UI without opening a browser."""

from __future__ import annotations

import json
import threading
import urllib.request
from http.server import ThreadingHTTPServer

from serve_case_review import CaseReviewApp, UI_DIR, result_path
from serve_human_annotation import AnnotationHub, make_handler


def get_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=5) as response:
        return json.loads(response.read())


def main() -> int:
    reviewer = "qa_case_review_smoke"
    path = result_path(reviewer)
    path.unlink(missing_ok=True)
    app = CaseReviewApp(reviewer)
    server = ThreadingHTTPServer(("127.0.0.1", 0), make_handler(AnnotationHub({None: app}), UI_DIR))
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address
    base = f"http://{host}:{port}"
    try:
        tasks = get_json(base + "/api/tasks")
        assert len(tasks["tasks"]) == 19
        first = tasks["tasks"][0]["task_id"]
        task = get_json(base + f"/api/task?id={first}")
        assert len(task["task"]["model_annotations"]) == 5
        with urllib.request.urlopen(base + "/", timeout=5) as response:
            html = response.read().decode("utf-8")
        with urllib.request.urlopen(base + "/app.js", timeout=5) as response:
            javascript = response.read().decode("utf-8")
        assert "最终案例标签" in html
        assert "case_relation" in javascript
        print(json.dumps({
            "ok": True,
            "tasks": len(tasks["tasks"]),
            "first_task": first,
            "model_annotations": len(task["task"]["model_annotations"]),
        }, ensure_ascii=False))
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
        path.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
