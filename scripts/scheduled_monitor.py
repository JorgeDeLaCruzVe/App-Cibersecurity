"""Hourly NEXDC monitoring job. Runs in GitHub Actions, not in Render's sleeping web worker."""
import datetime
import json
import os
import socket
import ssl
import urllib.error
import urllib.request

DOMAIN = "nexdcglobal.pages.dev"
URL = "https://" + DOMAIN + "/"
USER_AGENT = "SecurityAI-Monitor/0.3 (authorized NEXDC monitoring)"

def probe():
    result = {"availability": "unknown", "http": None, "tls": "unverified",
              "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat()}
    try:
        with socket.create_connection((DOMAIN, 443), timeout=10) as sock:
            with ssl.create_default_context().wrap_socket(sock, server_hostname=DOMAIN):
                result["tls"] = "valid"
    except (OSError, ssl.SSLError):
        pass
    try:
        request = urllib.request.Request(URL, method="HEAD", headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(request, timeout=12) as response:
            result["http"] = response.status
            result["availability"] = "online" if 200 <= response.status < 400 else "error"
    except urllib.error.HTTPError as exc:
        result["http"] = exc.code
        result["availability"] = "error"
    except (OSError, ValueError):
        result["availability"] = "unavailable"
    return result

def telegram_send(text):
    token = os.getenv("TELEGRAM_BOT_TOKEN", "")
    chat_id = os.getenv("TELEGRAM_CHAT_ID", "")
    if not token or not chat_id.lstrip("-").isdigit():
        print("Telegram secrets are not configured. No message sent.")
        return False
    payload = json.dumps({"chat_id": chat_id, "text": text[:3500]}).encode()
    request = urllib.request.Request("https://api.telegram.org/bot" + token + "/sendMessage",
                                     data=payload, headers={"Content-Type":"application/json"}, method="POST")
    try:
        with urllib.request.urlopen(request, timeout=12) as response:
            return response.status == 200
    except (OSError, urllib.error.HTTPError):
        print("Telegram API delivery failed.")
        return False

def main():
    result = probe()
    print(json.dumps(result))
    now = datetime.datetime.now(datetime.timezone.utc)
    site_ok = result["availability"] == "online" and result["tls"] == "valid"
    # Scheduled cron is best-effort; at 09:00 UTC send daily status.
    report = now.hour == 9 and now.minute <= 29
    if not site_ok:
        message = ("🚨 Security AI · NEXDC requiere atención\n"
                   "Disponibilidad: " + result["availability"] + "\n"
                   "HTTP: " + str(result["http"]) + "\n"
                   "TLS: " + result["tls"] + "\n"
                   "Hora UTC: " + result["checked_at"] + "\n"
                   "Confirmar desde otra red antes de declarar caída.")
        telegram_send(message)
    elif report:
        telegram_send("✅ Security AI · Resumen diario\n"
                      "NEXDC: Online\nHTTP: " + str(result["http"]) +
                      "\nTLS: válido\n"
                      "Computadores conectados: 0\nServidores conectados: 0\n"
                      "Hora UTC: " + result["checked_at"])
    if not site_ok:
        print("Monitoring check flagged a problem; Telegram alert attempted.")
        # Don't fail the workflow just because a site is unavailable. Logs retain evidence.

if __name__ == "__main__":
    main()
