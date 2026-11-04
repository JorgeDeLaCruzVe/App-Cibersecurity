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
    except (OSError, urllib.error.HTTPError, ValueError):
        return False

def authorized(secret_header):
    configured_secret = os.getenv("TELEGRAM_WEBHOOK_SECRET", "")
    return bool(configured_secret and hmac.compare_digest(secret_header or "", configured_secret))

def process_message(update, checker):
    msg = update.get("message") or update.get("edited_message") or {}
    chat = msg.get("chat", {})
    chat_id = chat.get("id")
    if not isinstance(chat_id, int):
        return
    cmd = str(msg.get("text", "")).strip().split(maxsplit=1)[0].lower().split("@")[0]
    allowed_id = os.getenv("TELEGRAM_CHAT_ID", "").strip()
    if cmd in ("/id", "/chatid"):
        send_message(chat_id, "ID de este chat: " + str(chat_id) + "\nAgrégalo como TELEGRAM_CHAT_ID en Render y como secreto en GitHub Actions.")
        return
    if not allowed_id or str(chat_id) != allowed_id:
        return
    if cmd in ("/start", "/ayuda", "/help"):
        send_message(chat_id, "Security AI · Comandos:\n/estado — resumen de los 3 módulos\n/web — estado HTTPS de NEXDC\n/servicios — activos conectados\n/id — identificador de este chat\n\nLas verificaciones web son reales y no intrusivas. Los agentes de PC/servidor aún no están instalados.")
    elif cmd in ("/estado", "/status", "/web", "/servicios"):
        if cmd == "/servicios":
            send_message(chat_id, "Security AI · Servicios\n🌐 Web: 1 sitio (NEXDC)\n🖥 Computadores: 0 agentes conectados\n🗄 Servidores: 0 gateways conectados\n\nNo se ha habilitado todavía la respuesta automática.")
            return
        result = checker()
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
        with urllib.request.urlopen(request, timeout=8) as response:
            return bool(json.load(response).get("ok"))
    except (OSError, urllib.error.HTTPError, ValueError):
        return False
