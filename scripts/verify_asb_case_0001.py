#!/usr/bin/env python3
"""Local-only verifier for ASB-CASE-0001.

This script talks to the ManusMCP SSE endpoint directly, lists tools, and then
runs a harmless shell command through shell_exec.
"""

from __future__ import annotations

import argparse
import json
import queue
import re
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse, urlunparse


@dataclass
class RpcResult:
    raw: dict[str, Any]

    @property
    def result(self) -> Any:
        return self.raw.get("result")


class SseSession:
    def __init__(self, sse_url: str, timeout: float) -> None:
        self.sse_url = sse_url
        self.timeout = timeout
        parsed = urlparse(sse_url)
        self.message_url = urlunparse(
            (parsed.scheme, parsed.netloc, "/message", "", "", "")
        )
        self.session_id: str | None = None
        self._events: "queue.Queue[dict[str, Any]]" = queue.Queue()
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def __enter__(self) -> "SseSession":
        request = urllib.request.Request(
            self.sse_url,
            headers={"Accept": "text/event-stream"},
            method="GET",
        )
        self._response = urllib.request.urlopen(request, timeout=self.timeout)
        self._thread = threading.Thread(target=self._read_stream, daemon=True)
        self._thread.start()

        deadline = time.time() + self.timeout
        while self.session_id is None:
            if time.time() >= deadline:
                raise TimeoutError("Timed out waiting for SSE session id")
            time.sleep(0.05)

        return self

    def __exit__(self, exc_type, exc, tb) -> None:
        self._stop.set()
        try:
            self._response.close()
        except Exception:
            pass

    def _read_stream(self) -> None:
        data_lines: list[str] = []
        try:
            while not self._stop.is_set():
                raw = self._response.readline()
                if raw == b"":
                    break
                line = raw.decode("utf-8", errors="replace").rstrip("\r\n")
                if not line:
                    if data_lines:
                        payload = "\n".join(data_lines)
                        self._handle_payload(payload)
                        data_lines = []
                    continue
                if line.startswith("data:"):
                    data_lines.append(line[5:].lstrip())
        except Exception as exc:
            if not self._stop.is_set():
                self._events.put({"error": str(exc)})

    def _handle_payload(self, data: str) -> None:
        if self.session_id is None and data.startswith("/message?sessionId="):
            match = re.search(r"sessionId=([^&\s]+)", data)
            if match:
                self.session_id = match.group(1)
                print(f"session_id: {self.session_id}")
                return

        try:
            message = json.loads(data)
        except json.JSONDecodeError:
            return
        self._events.put(message)

    def post_rpc(self, session_id: str, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        request = urllib.request.Request(
            f"{self.message_url}?sessionId={session_id}",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(request, timeout=self.timeout) as response:
            response.read()

    def notify(self, method: str, params: dict[str, Any] | None) -> None:
        if self.session_id is None:
            raise RuntimeError("SSE session id not initialized")

        self.post_rpc(
            self.session_id,
            {
                "jsonrpc": "2.0",
                "method": method,
                "params": params or {},
            },
        )

    def rpc(self, method: str, params: dict[str, Any] | None, request_id: int) -> Any:
        if self.session_id is None:
            raise RuntimeError("SSE session id not initialized")

        self.post_rpc(
            self.session_id,
            {
                "jsonrpc": "2.0",
                "id": request_id,
                "method": method,
                "params": params or {},
            },
        )

        deadline = time.time() + self.timeout
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                raise TimeoutError(f"Timed out waiting for RPC response: {method}")

            try:
                message = self._events.get(timeout=remaining)
            except queue.Empty as exc:
                raise TimeoutError(f"Timed out waiting for RPC response: {method}") from exc

            if isinstance(message, dict) and message.get("id") == request_id:
                return RpcResult(message).result


def main() -> int:
    parser = argparse.ArgumentParser(description="Verify ASB-CASE-0001 locally")
    parser.add_argument(
        "--sse-url",
        default="http://127.0.0.1:8002/sse",
        help="MCP SSE endpoint URL",
    )
    parser.add_argument(
        "--command",
        default="whoami",
        help="Harmless shell command to run through shell_exec",
    )
    parser.add_argument("--timeout", type=float, default=30.0)
    args = parser.parse_args()

    with SseSession(args.sse_url, args.timeout) as session:
        initialize = session.rpc(
            "initialize",
            {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "asb-local-verifier", "version": "1.0"},
            },
            request_id=1,
        )
        print("initialize:", json.dumps(initialize, ensure_ascii=False))

        session.notify("notifications/initialized", {})

        tools = session.rpc("tools/list", {}, request_id=3)
        print("tools:", json.dumps(tools, ensure_ascii=False))

        call_result = session.rpc(
            "tools/call",
            {
                "name": "shell_exec",
                "arguments": {
                    "id": "asb-local-1",
                    "execDir": ".",
                    "command": args.command,
                },
            },
            request_id=4,
        )
        print("shell_exec:", json.dumps(call_result, ensure_ascii=False))
        return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except urllib.error.URLError as exc:
        print(f"Network error: {exc}", file=sys.stderr)
        raise SystemExit(1)
