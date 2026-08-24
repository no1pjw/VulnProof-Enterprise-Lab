"""Deterministic local fixture. It is not a real vulnerable product or CVE."""

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._reply(200, {"status": "ok"})
        elif self.path == "/debug/config" and os.getenv("LAB_MODE") == "vulnerable":
            self._reply(200, {"marker": "VULNPROOF_LAB_MARKER"})
        else:
            self._reply(404, {"error": "not found"})

    def _reply(self, status: int, payload: dict[str, str]) -> None:
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, message: str, *args: object) -> None:
        print(f"validation-fixture: {message % args}", flush=True)


port = int(os.getenv("PORT", "8080"))
ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
