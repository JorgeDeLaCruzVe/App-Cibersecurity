"""Security AI public demo: fixed-domain, lightweight NEXDC HTTPS check only."""
import os
import json
import ssl
import socket
import time
import threading
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit

HTML = (Path(__file__).parent / "index.html").read_bytes()
DOMAIN = "nexdcglobal.pages.dev"  # Hardcoded allowlist: user-supplied NEXDC site
CHECK_URL = "https://" + DOMAIN + "/"
_CACHE = {"until": 0, "value": None}
_LOCK = threading.Lock()
HEADERS = ("strict-transport-security", "content-security-policy", "x-content-type-options", "x-frame-options", "referrer-policy")

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def check_nexdc():
    output = {"domain": DOMAIN, "checked_at": datetime.now(timezone.utc).isoformat(),
              "availability": "unavailable", "http_status": None, "tls": "unverified",
              "certificate_expires": None, "headers": {}}
    # Fixed public site only, without scanning arbitrary user-provided URLs.
    try:
        with socket.create_connection((DOMAIN, 443), timeout=6) as conn:
            with ssl.create_default_context().wrap_socket(conn, server_hostname=DOMAIN) as tls:
                cert = tls.getpeercert()
                expiry = cert.get("notAfter")
                if expiry:
                    output["certificate_expires"] = datetime.strptime(expiry, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc).date().isoformat()
                output["tls"] = "valid"
    except (OSError, ssl.SSLError, ValueError):
        pass
    try:
        req = urllib.request.Request(CHECK_URL, method="HEAD", headers={"User-Agent":"SecurityAI-Demo-Healthcheck/0.2"})
        with NoRedirect().build_opener().open(req, timeout=7) as resp:
            output["http_status"] = resp.status
            output["availability"] = "online" if 200 <= resp.status < 400 else "error"
            for h in HEADERS:
                output["headers"][h] = bool(resp.headers.get(h))
    except urllib.error.HTTPError as e:
        output["http_status"] = e.code
        output["availability"] = "redirect_or_error"
        for h in HEADERS:
            output["headers"][h] = bool(e.headers.get(h))
    except (OSError, ValueError):
        output["availability"] = "check_failed"
    return output

def cached_check():
    now = time.monotonic()
    if now < _CACHE["until"] and _CACHE["value"] is not None:
        return _CACHE["value"]
    with _LOCK:
        if time.monotonic() >= _CACHE["until"] or _CACHE["value"] is None:
            _CACHE["value"] = check_nexdc()
            _CACHE["until"] = time.monotonic() + 300
    return _CACHE["value"]

class Handler(BaseHTTPRequestHandler):
    def send_json(self, payload):
        raw = json.dumps(payload).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(raw)
    def do_HEAD(self):
        path = urlsplit(self.path).path
        if path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
        elif path == "/api/health" or path == "/api/web/nexdc/status":
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
        elif path == "/favicon.ico":
            self.send_response(204)
        else:
            self.send_response(404)
        self.end_headers()
    def do_GET(self):
        path = urlsplit(self.path).path
        if path in ("/", "/index.html"):
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'")
            self.end_headers()
            self.wfile.write(HTML)
        elif path == "/api/health":
            self.send_json({"status":"ok","mode":"limited-real-web-check-and-simulated-endpoints","modules":["endpoint","server","web"]})
        elif path == "/api/web/nexdc/status":
            self.send_json(cached_check())
        elif path == "/favicon.ico":
            self.send_response(204)
            self.send_header("Cache-Control", "public, max-age=86400")
            self.end_headers()
        else:
            self.send_error(404)
    def do_POST(self):
        self.send_error(405, "Read-only demo")

if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", "10000"))), Handler).serve_forever()
