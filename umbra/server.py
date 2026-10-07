"""Local HTTP server for the UI.

Threat model: the server listens on 127.0.0.1 only, but any web page open in
any browser on this PC can still send requests to 127.0.0.1. This API can
connect/disconnect and exposes the server list, so every request is checked:
  * Host header must be 127.0.0.1:<port> or localhost:<port>
    (blocks DNS-rebinding attacks);
  * API calls need the random per-run token in the X-Token header; the token
    is only embedded in the page that is opened with ?t=<token>;
  * Origin, when present, must be our own origin (blocks cross-site fetch).
"""
from __future__ import annotations

import hmac
import json
import logging
import secrets
import sys
import time
import traceback
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from .controller import ApiError, Controller

log = logging.getLogger("umbra.http")
# In a PyInstaller build the bundled files are unpacked under sys._MEIPASS.
WEB_DIR = (Path(getattr(sys, "_MEIPASS")) / "umbra" / "web"
           if hasattr(sys, "_MEIPASS") else Path(__file__).parent / "web")
STATIC = {
    "/app.css": ("app.css", "text/css; charset=utf-8"),
    "/app.js": ("app.js", "application/javascript; charset=utf-8"),
}
CSP = ("default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; "
       "img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
MAX_BODY = 1024 * 1024


class UiServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, controller: Controller, port: int = 0):
        super().__init__(("127.0.0.1", port), Handler)
        self.controller = controller
        self.token = secrets.token_urlsafe(24)

    @property
    def port(self) -> int:
        return self.server_address[1]

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.port}/?t={self.token}"


class Handler(BaseHTTPRequestHandler):
    server: UiServer  # type: ignore[assignment]
    server_version = "UmbraUI"

    def log_message(self, fmt, *args):  # silence default stderr logging
        log.debug(fmt, *args)

    # ---- helpers ------------------------------------------------------
    def _host_ok(self) -> bool:
        host = self.headers.get("Host", "")
        port = self.server.port
        return host in (f"127.0.0.1:{port}", f"localhost:{port}")

    def _send(self, code: int, body: bytes, ctype: str, extra: dict | None = None) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Security-Policy", CSP)
        self.send_header("Referrer-Policy", "no-referrer")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj: dict) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=False).encode("utf-8"),
                   "application/json; charset=utf-8")

    # ---- GET: page + static files -------------------------------------
    def do_GET(self):  # noqa: N802
        if not self._host_ok():
            return self._send(403, b"forbidden", "text/plain")
        url = urlsplit(self.path)
        if url.path == "/":
            token = parse_qs(url.query).get("t", [""])[0]
            if not hmac.compare_digest(token, self.server.token):
                return self._send(403, b"forbidden", "text/plain")
            html = (WEB_DIR / "index.html").read_text(encoding="utf-8")
            html = html.replace("__TOKEN__", self.server.token)
            return self._send(200, html.encode("utf-8"), "text/html; charset=utf-8")
        entry = STATIC.get(url.path)
        if entry:
            return self._send(200, (WEB_DIR / entry[0]).read_bytes(), entry[1])
        self._send(404, b"not found", "text/plain")

    # ---- POST: API ----------------------------------------------------
    def do_POST(self):  # noqa: N802
        if not self._host_ok():
            return self._json(403, {"error": "forbidden"})
        origin = self.headers.get("Origin")
        if origin and origin not in (f"http://127.0.0.1:{self.server.port}",
                                     f"http://localhost:{self.server.port}"):
            return self._json(403, {"error": "forbidden origin"})
        token = self.headers.get("X-Token", "")
        if not hmac.compare_digest(token, self.server.token):
            return self._json(403, {"error": "bad token"})
        url = urlsplit(self.path)
        if not url.path.startswith("/api/"):
            return self._json(404, {"error": "not found"})

        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return self._json(400, {"error": "bad length"})
        if length > MAX_BODY:
            return self._json(413, {"error": "слишком большой запрос"})
        raw = self.rfile.read(length) if length else b"{}"
        try:
            args = json.loads(raw or b"{}")
            if not isinstance(args, dict):
                raise ValueError
        except ValueError:
            return self._json(400, {"error": "bad json"})

        ctrl = self.server.controller
        ctrl.last_seen = time.time()
        name = url.path[len("/api/"):]
        try:
            self._json(200, ctrl.call(name, args))
        except ApiError as exc:
            self._json(400, {"error": str(exc)})
        except Exception as exc:  # noqa: BLE001
            log.error("API %s failed:\n%s", name, traceback.format_exc())
            self._json(500, {"error": f"внутренняя ошибка: {exc}"})
