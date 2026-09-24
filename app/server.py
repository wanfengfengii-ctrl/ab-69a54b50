"""HTTP service for offline recovery-card key reconstruction.

Endpoints
---------
GET  /                          operator input page
GET  /healthz                   liveness/readiness probe
POST /api/recovery/reconstruct  validate shares and reconstruct the key

The server uses only the Python standard library so the image builds
fully offline with no package downloads.
"""

from __future__ import annotations

import json
import os
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .reconstruct import Status, analyze

STATIC_DIR = Path(__file__).resolve().parent / "static"
MAX_BODY_BYTES = 64 * 1024


class RecoveryHandler(BaseHTTPRequestHandler):
    server_version = "RecoveryCard/1.0"

    # ---- helpers -------------------------------------------------------------
    def _send_json(self, status: int, payload: dict) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def _send_static(self, filename: str, content_type: str) -> None:
        path = STATIC_DIR / filename
        try:
            body = path.read_bytes()
        except OSError:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args) -> None:  # noqa: D401
        # Keep stderr concise; container logs stay readable.
        print(f"[{self.log_date_time_string()}] {fmt % args}", flush=True)

    # ---- routing -------------------------------------------------------------
    def do_GET(self) -> None:  # noqa: N802 (stdlib naming)
        path = self.path.split("?", 1)[0]
        if path in ("/", "/index.html"):
            self._send_static("index.html", "text/html; charset=utf-8")
        elif path in ("/healthz", "/health"):
            self._send_json(
                HTTPStatus.OK, {"status": "ok", "service": "recovery-card"}
            )
        else:
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path != "/api/recovery/reconstruct":
            self._send_json(HTTPStatus.NOT_FOUND, {"error": "not found"})
            return

        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {
                    "ok": False,
                    "errors": [
                        {"field": "payload", "index": None,
                         "message": "Content-Length 头非法"}
                    ],
                },
            )
            return
        if length <= 0:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {
                    "ok": False,
                    "errors": [
                        {"field": "payload", "index": None, "message": "请求体为空"}
                    ],
                },
            )
            return
        if length > MAX_BODY_BYTES:
            self._send_json(
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                {
                    "ok": False,
                    "errors": [
                        {"field": "payload", "index": None, "message": "请求体过大"}
                    ],
                },
            )
            return

        raw = self.rfile.read(length)
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {
                    "ok": False,
                    "errors": [
                        {
                            "field": "payload",
                            "index": None,
                            "message": "请求体不是合法的 UTF-8 JSON",
                        }
                    ],
                },
            )
            return

        validation, reconstruction = analyze(payload)
        if not validation.ok:
            self._send_json(
                HTTPStatus.BAD_REQUEST,
                {"ok": False, "errors": [e.to_dict() for e in validation.errors]},
            )
            return

        r = reconstruction
        response: dict = {"ok": True, "status": r.status.value}
        if r.status in (Status.CONSISTENT, Status.RECOVERED):
            # Key is disclosed only when the analysis uniquely identifies it.
            response["key"] = r.key_hex
        if r.status is Status.RECOVERED:
            response["bad_card"] = r.bad_card
        self._send_json(HTTPStatus.OK, response)


def create_server(port: int) -> ThreadingHTTPServer:
    server = ThreadingHTTPServer(("0.0.0.0", port), RecoveryHandler)
    server.daemon_threads = True
    return server


def main() -> None:
    port = int(os.environ.get("PORT", "8080"))
    server = create_server(port)
    print(f"recovery-card service listening on 0.0.0.0:{port}", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
