"""Security AI public demo: fixed-domain, lightweight NEXDC HTTPS check only."""
import os
import json
import ssl
import socket
import time
import threading
import urllib.request
import urllib.error
import ipaddress
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit
from telegram_bot import authorized as telegram_authorized, process_message as telegram_process, verify_token as telegram_verify_token, send_message as telegram_send_message, setup_webhook

HTML = (Path(__file__).parent / "index.html").read_bytes()
DOMAIN = "nexdcglobal.pages.dev"  # Hardcoded allowlist: user-supplied NEXDC site
CHECK_URL = "https://" + DOMAIN + "/"
_CACHE = {"until": 0, "value": None}
_LOCK = threading.Lock()
HEADERS = ("strict-transport-security", "content-security-policy", "x-content-type-options", "x-frame-options", "referrer-policy", "permissions-policy", "cross-origin-opener-policy", "cross-origin-resource-policy")

class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None

def check_nexdc():
    output = {"domain": DOMAIN, "checked_at": datetime.now(timezone.utc).isoformat(), "source": "real", "check_type": "non_intrusive",
              "availability": "unavailable", "http_status": None, "tls": "unverified",
              "certificate_expires": None, "headers": {}, "tls_protocol": None, "tls_cipher": None, "certificate_issuer": None, "http_port_80": "not_checked", "https_port_443": "not_checked", "http_redirect": None}
    # Read-only checks against one fixed authorized domain, no arbitrary URLs.
    try:
        with socket.create_connection((DOMAIN, 443), timeout=6) as conn:
            output["https_port_443"] = "tcp_reachable"
            with ssl.create_default_context().wrap_socket(conn, server_hostname=DOMAIN) as tls:
                output["tls_protocol"] = tls.version()
                output["tls_cipher"] = tls.cipher()[0] if tls.cipher() else None
                cert = tls.getpeercert()
                issuer = cert.get("issuer", ())
                output["certificate_issuer"] = ", ".join(str(part[1]) for group in issuer for part in group if len(part) >= 2 and part[0] in ("organizationName", "commonName"))[:160] or None
                expiry = cert.get("notAfter")
                if expiry:
                    output["certificate_expires"] = datetime.strptime(expiry, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc).date().isoformat()
                output["tls"] = "valid"
    except (OSError, ssl.SSLError, ValueError):
        pass
    # One benign TCP connectivity check and one HEAD request, not a port sweep.
    try:
        with socket.create_connection((DOMAIN, 80), timeout=3):
            output["http_port_80"] = "tcp_reachable"
    except OSError:
        output["http_port_80"] = "unreachable_or_filtered"
    try:
        req_http = urllib.request.Request("http://" + DOMAIN + "/", method="HEAD",
                                          headers={"User-Agent":"SecurityAI-Demo-Healthcheck/0.4"})
        with urllib.request.build_opener(NoRedirect()).open(req_http, timeout=5) as res_http:
            output["http_redirect"] = {"status": res_http.status, "location_https": str(res_http.headers.get("Location", "")).startswith("https://")}
    except urllib.error.HTTPError as exc:
        output["http_redirect"] = {"status": exc.code, "location_https": str(exc.headers.get("Location", "")).startswith("https://")}
    except (OSError, ValueError):
        pass
    # One benign TCP connectivity check and one HEAD request, not a port sweep.
    try:
        with socket.create_connection((DOMAIN, 80), timeout=3):
            output["http_port_80"] = "tcp_reachable"
    except OSError:
        output["http_port_80"] = "unreachable_or_filtered"
    try:
        req_http = urllib.request.Request("http://" + DOMAIN + "/", method="HEAD",
                                          headers={"User-Agent":"SecurityAI-Demo-Healthcheck/0.4"})
        with urllib.request.build_opener(NoRedirect()).open(req_http, timeout=5) as res_http:
            output["http_redirect"] = {"status": res_http.status, "location_https": str(res_http.headers.get("Location", "")).startswith("https://")}
    except urllib.error.HTTPError as exc:
        output["http_redirect"] = {"status": exc.code, "location_https": str(exc.headers.get("Location", "")).startswith("https://")}
    except (OSError, ValueError):
        pass
    try:
        req = urllib.request.Request(CHECK_URL, method="HEAD", headers={"User-Agent":"SecurityAI-Demo-Healthcheck/0.3"})
        with urllib.request.build_opener(NoRedirect()).open(req, timeout=7) as resp:
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
    # DNS information is observational only; it does not establish origin-server exposure.
    try:
        addresses = sorted({item[4][0] for item in socket.getaddrinfo(DOMAIN, None, type=socket.SOCK_STREAM)})
        output["dns_addresses"] = [address for address in addresses if ipaddress.ip_address(address).is_global][:8]
    except OSError:
        output["dns_addresses"] = []
    return output

def web_summary():
    s = cached_check()
    observed = s.get("headers", {})
    missing = [key for key in HEADERS if observed and not observed.get(key)]
    return {"domain": DOMAIN, "mode": "real_live", "check": s, "missing_security_headers": missing,
            "notes": "Las cabeceras ausentes no demuestran por sí solas una vulnerabilidad; revisar contexto. DNS refleja la CDN si aplica."}

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
        elif path in ("/api/health", "/api/web/nexdc/status", "/api/web/sites", "/api/assets", "/api/telegram/status"):
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
            self.send_json({"status":"ok","mode":"real_web_monitoring_and_pending_private_agents","modules":["endpoint","server","web"]})
        elif path == "/api/web/nexdc/status":
            self.send_json(cached_check())
        elif path == "/api/web/sites":
            self.send_json({"sites": [web_summary()], "total": 1, "source": "real"})
        elif path == "/api/telegram/status":
            bot_ready = bool(os.getenv("TELEGRAM_BOT_TOKEN"))
            secret_ready = bool(os.getenv("TELEGRAM_WEBHOOK_SECRET"))
            chat_ready = bool(os.getenv("TELEGRAM_CHAT_ID"))
            self.send_json({"bot_token_configured": bot_ready, "webhook_secret_configured": secret_ready, "chat_authorized": chat_ready, "bot_can_receive_commands": bot_ready and secret_ready, "notification_target_ready": bot_ready and chat_ready})
        elif path == "/api/assets":
            self.send_json({"computers": [], "servers": [], "total": 0, "mode": "awaiting_authenticated_agent_gateway"})
        elif path == "/favicon.ico":
            self.send_response(204)
            self.send_header("Cache-Control", "public, max-age=86400")
            self.end_headers()
        else:
            self.send_error(404)
    def do_POST(self):
        path = urlsplit(self.path).path
        if path != "/api/telegram/webhook":
            self.send_error(405, "Endpoint not available")
            return
        if not telegram_authorized(self.headers.get("X-Telegram-Bot-Api-Secret-Token", "")):
            self.send_error(403, "Forbidden")
            return
        try:
            length = int(self.headers.get("Content-Length", "-1"))
            if length < 2 or length > 16384:
                self.send_error(413, "Invalid update")
                return
            payload = json.loads(self.rfile.read(length))
            if not isinstance(payload, dict):
                raise ValueError("Telegram update must be an object")
        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            self.send_error(400, "Invalid update")
            return
        telegram_process(payload, check_nexdc)
        self.send_json({"ok": True})

if __name__ == "__main__":
    if os.getenv("TELEGRAM_BOT_TOKEN") and os.getenv("TELEGRAM_WEBHOOK_SECRET"):
        # Registration is retried at next deploy. Logs never expose tokens.
        def startup_telegram():
            print("Telegram token validation: " + telegram_verify_token(), flush=True)
            print("Telegram webhook configured" if setup_webhook() else "Telegram webhook registration failed", flush=True)
            recipient = os.getenv("TELEGRAM_CHAT_ID", "").strip()
            if recipient:
                delivered = telegram_send_message(recipient, "🛡 Security AI · Prueba de conexión\\nTu chat está configurado. Escribe /estado para consultar NEXDC.")
                print("Telegram startup message accepted" if delivered else "Telegram startup message failed", flush=True)
        threading.Thread(target=startup_telegram, daemon=True).start()
    ThreadingHTTPServer(("0.0.0.0", int(os.environ.get("PORT", "10000"))), Handler).serve_forever()
