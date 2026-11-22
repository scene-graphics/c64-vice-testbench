"""Serve just the latest WASM frame from each local benchmark worker."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import sys
import threading
import webbrowser


def start_preview(output, workers):
    frames = output / "preview"
    frames.mkdir()
    page = Path(__file__).with_name("live-vice-preview.html").read_bytes()
    routes = {f"/frames/{i}": frames / f"{i}.frame" for i in range(workers)}

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/":
                body, media = page, "text/html; charset=utf-8"
            elif self.path == "/workers":
                body, media = json.dumps(list(routes)).encode(), "application/json"
            elif self.path in routes:
                try:
                    body = routes[self.path].read_bytes()
                except FileNotFoundError:
                    self.send_response(204)
                    self.end_headers()
                    return
                media = "application/octet-stream"
            else:
                self.send_error(404)
                return
            self.send_response(200)
            self.send_header("Content-Type", media)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    url = f"http://127.0.0.1:{server.server_port}/"
    print(f"Live C64 screen: {url}", file=sys.stderr, flush=True)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    if not os.environ.get("C64_PREVIEW_NO_OPEN"):
        threading.Thread(target=webbrowser.open, args=(url,), daemon=True).start()
    return server
