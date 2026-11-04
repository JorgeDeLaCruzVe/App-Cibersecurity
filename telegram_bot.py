"""Telegram command handlers with strict webhook authentication and chat allowlist."""
import hmac
import json
import os
import urllib.request
import urllib.error

BOT_API = "https://api.telegram.org/bot"

def configured():
    return bool(os.getenv("TELEGRAM_BOT_TOKEN") and os.getenv("TELEGRAM_WEBHOOK_SECRET"))

def send_message(chat_id, message):
    token = os.getenv("TELEGRAM_BOT_TOKEN", "")
    if not token or not str(chat_id).lstrip("-").isdigit():
        return False
    payload = json.dumps({"chat_id": int(chat_id), "text": message[:3500],
                          "disable_web_page_preview": True}).encode()
    request = urllib.request.Request(BOT_API + token + "/sendMessage", data=payload,
                                     headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            return response.status == 200
    except urllib.error.HTTPError as exc:
        # Only predefined error categories: do not log untrusted API text or credentials.
        try:
            description = str(json.load(exc).get("description", "")).lower()
        except (ValueError, OSError):
            description = ""
        if "chat not found" in description:
            category = "chat_not_found"
        elif "bot was blocked" in description:
            category = "bot_blocked"
        elif "user is deactivated" in description:
            category = "user_deactivated"
        elif "not enough rights" in description:
            category = "insufficient_rights"
        elif "chat_id is empty" in description:
            category = "empty_chat_id"
        else:
            category = "other"
        print("Telegram sendMessage HTTP " + str(exc.code) + " category=" + category, flush=True)
        return False
    except (OSError, ValueError):
        print("Telegram sendMessage transport error", flush=True)
        return False

def authorized(secret_header):
    configured_secret = os.getenv("TELEGRAM_WEBHOOK_SECRET", "")
    return bool(configured_secret and hmac.compare_digest(secret_header or "", configured_secret))

def process_message(update, checker):
    msg = update.get("message") or update.get("edited_message") or {}
    chat = msg.get("chat", {})
    chat_id = chat.get("id")
    if not isinstance(chat_id, int):
        print("Telegram update skipped: no chat ID", flush=True)
        return
    cmd = str(msg.get("text", "")).strip().split(maxsplit=1)[0].lower().split("@")[0]
    allowed_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()
    if cmd in ("/id", "/chatid"):
        print("Telegram /id requested; attempting reply", flush=True)
        send_message(chat_id, "ID de este chat: " + str(chat_id) + "\nAgrégalo como TELEGRAM_CHAT_ID en Render y como secreto en GitHub Actions.")
        return
    if not allowed_id or str(chat_id) != allowed_id:
        print("Telegram update skipped: chat not authorized", flush=True)
        return
    print("Telegram authorized command: " + (cmd if cmd in ("/start", "/ayuda", "/help", "/estado", "/status", "/web", "/servicios", "/seguridad", "/puertos") else "other"), flush=True)
    if cmd in ("/start", "/ayuda", "/help"):
        send_message(chat_id, "Security AI · Comandos:\n/estado — resumen de los 3 módulos\n/web — estado HTTPS de NEXDC\n/seguridad — informe técnico TLS, HTTP, DNS y cabeceras\n/puertos — puertos web observados en Cloudflare\n/servicios — activos conectados\n/id — identificador de este chat\n\nLas verificaciones web son reales y no intrusivas. Los agentes de PC/servidor aún no están instalados.")
    elif cmd in ("/estado", "/status", "/web", "/servicios", "/seguridad", "/puertos"):
        if cmd == "/servicios":
            send_message(chat_id, "Security AI · Servicios\n🌐 Web: 1 sitio (NEXDC)\n🖥 Computadores: 0 agentes conectados\n🗄 Servidores: 0 gateways conectados\n\nNo se ha habilitado todavía la respuesta automática.")
            return
        result = checker()
        if cmd == "/puertos":
            port80 = result.get("http_port_80", "no verificado")
            port443 = result.get("https_port_443", "no verificado")
            redirect = result.get("http_redirect")
            redirect_text = ("HTTP " + str(redirect.get("status")) + (" → HTTPS" if redirect.get("location_https") else " (sin redirección HTTPS confirmada)")) if isinstance(redirect, dict) else "no verificada"
            send_message(chat_id, "🛡 Security AI · Puertos web del borde Cloudflare\\n"
                         + "80/TCP (HTTP): " + str(port80) + "\\n"
                         + "443/TCP (HTTPS): " + str(port443) + "\\n"
                         + "Redirección HTTP: " + redirect_text + "\\n"
                         + "Otros puertos: no examinados\\n\\n"
                         + "Estos resultados corresponden al dominio público y a su CDN; no identifican puertos de un servidor de origen.")
            return
        if cmd == "/seguridad":
            headers = result.get("headers", {})
            labels = [("HSTS", "strict-transport-security"), ("CSP", "content-security-policy"),
                      ("X-Content-Type-Options", "x-content-type-options"), ("X-Frame-Options", "x-frame-options"),
                      ("Referrer-Policy", "referrer-policy"), ("Permissions-Policy", "permissions-policy"),
                      ("COOP", "cross-origin-opener-policy"), ("CORP", "cross-origin-resource-policy")]
            header_lines = [label + ": " + ("presente" if headers.get(k) else "no detectada") for label, k in labels] if headers else ["No disponibles"]
            dns = ", ".join(result.get("dns_addresses", [])) or "sin resultado"
            send_message(chat_id, "🛡 Security AI · Informe web\\n"
                         + "Dominio: " + str(result.get("domain")) + "\\n"
                         + "HTTP: " + str(result.get("http_status")) + "\\n"
                         + "TLS: " + str(result.get("tls")) + " / " + str(result.get("tls_protocol") or "desconocido") + "\\n"
                         + "Cifrado: " + str(result.get("tls_cipher") or "desconocido") + "\\n"
                         + "Emisor: " + str(result.get("certificate_issuer") or "no verificado") + "\\n"
                         + "Caduca: " + str(result.get("certificate_expires") or "no verificado") + "\\n"
                         + "DNS públicos CDN: " + dns + "\\n\\nCabeceras HTTP:\\n" + "\\n".join(header_lines)
                         + "\\n\\nPuertos: /puertos\\nNo es un pentest; los encabezados ausentes no prueban vulnerabilidades.")
            return
        availability = result.get("availability", "unknown")
        tls = result.get("tls", "unknown")
        code = result.get("http_status")
        expiration = result.get("certificate_expires") or "Sin verificar"
        status = "🟢 Online" if availability == "online" else "🟠 Sin confirmar (" + availability + ")"
        lines = ["🛡 Security AI · Estado real",
                 "🌐 NEXDC: " + status,
                 "HTTP: " + str(code or "sin respuesta"),
                 "TLS: " + ("válido" if tls == "valid" else "sin verificar"),
                 "Certificado hasta: " + expiration,
                 "Comprobación: " + result.get("checked_at", "sin fecha")]
        if cmd != "/web":
            lines += ["", "🖥 Computadores: 0 conectados", "🗄 Servidores: 0 conectados"]
        send_message(chat_id, "\n".join(lines))

def verify_token():
    """Check Bot API authorization without logging token or username."""
    token = os.getenv("TELEGRAM_BOT_TOKEN", "")
    if not token:
        return "not_configured"
    request = urllib.request.Request(BOT_API + token + "/getMe", method="GET")
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            result = json.load(response)
            return "valid" if result.get("ok") else "api_rejected"
    except urllib.error.HTTPError as exc:
        return "api_http_" + str(exc.code)
    except (OSError, ValueError):
        return "network_or_invalid_response"

def setup_webhook():
    token = os.getenv("TELEGRAM_BOT_TOKEN", "")
    secret = os.getenv("TELEGRAM_WEBHOOK_SECRET", "")
    base = os.getenv("PUBLIC_BASE_URL", "https://security-ai-demo-online.onrender.com").rstrip("/")
    if not token or not secret:
        return False
    # HTTPS-only, fixed Telegram API and callback domain.
    if base != "https://security-ai-demo-online.onrender.com":
        return False
    payload = json.dumps({"url": base + "/api/telegram/webhook",
                          "secret_token": secret,
                          "allowed_updates": ["message"]}).encode()
    request = urllib.request.Request(BOT_API + token + "/setWebhook", data=payload,
                                     headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=12) as response:
            return bool(json.load(response).get("ok"))
    except urllib.error.HTTPError as exc:
        print("Telegram setWebhook returned HTTP " + str(exc.code), flush=True)
        return False
    except (OSError, ValueError):
        print("Telegram setWebhook network or response error", flush=True)
        return False
