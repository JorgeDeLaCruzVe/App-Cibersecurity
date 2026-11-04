import os
import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

HTML = (Path(__file__).parent / "index.html").read_bytes()
class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(HTML)
        elif self.path == "/api/health":
            raw = json.dumps({"status":"ok","mode":"public-read-only-demo","modules":["endpoint","server","web"]}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(raw)
        else:
            self.send_error(404)
    def do_POST(self):
        self.send_error(405, "Read-only demo")
if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", "10000"))), Handler).serve_forever()
