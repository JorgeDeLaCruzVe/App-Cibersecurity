import json
import os
import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from unittest.mock import patch
import telegram_bot
import server

class DemoRoutes(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.Handler)
        cls.base = "http://127.0.0.1:" + str(cls.httpd.server_address[1])
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def get(self, path, method="GET"):
        with urlopen(Request(self.base + path, method=method), timeout=3) as result:
            return result.status, result.read().decode("utf-8")

    def test_home_with_query(self):
        status, body = self.get("/?utm_source=chatgpt.com")
        self.assertEqual(status, 200)
        self.assertIn("Security AI", body)

    def test_health_with_query(self):
        status, body = self.get("/api/health?check=1")
        self.assertEqual(status, 200)
        self.assertIn('"status": "ok"', body)

    def test_head_root(self):
        self.assertEqual(self.get("/", "HEAD")[0], 200)

    def test_favicon(self):
        self.assertEqual(self.get("/favicon.ico")[0], 204)

    def test_missing_route(self):
        with self.assertRaises(HTTPError) as ctx:
            self.get("/unknown-route")
        self.assertEqual(ctx.exception.code, 404)

    def test_telegram_webhook_rejects_missing_secret(self):
        payload = json.dumps({"update_id": 1, "message": {"text": "/estado", "chat": {"id": 123}}}).encode()
        req = Request(self.base + "/api/telegram/webhook", data=payload, method="POST",
                      headers={"Content-Type":"application/json"})
        with patch.dict(os.environ, {"TELEGRAM_WEBHOOK_SECRET":"abc123_secure_value_456"}):
            with self.assertRaises(HTTPError) as ctx:
                urlopen(req, timeout=3)
        self.assertEqual(ctx.exception.code, 403)

    def test_telegram_webhook_valid_secret(self):
        payload = json.dumps({"update_id": 1, "message": {"text": "/servicios", "chat": {"id": 123}}}).encode()
        req = Request(self.base + "/api/telegram/webhook", data=payload, method="POST",
                      headers={"Content-Type":"application/json", "X-Telegram-Bot-Api-Secret-Token":"abc123_secure_value_456"})
        with patch.dict(os.environ, {"TELEGRAM_WEBHOOK_SECRET":"abc123_secure_value_456", "TELEGRAM_CHAT_ID":"123"}):
            with patch.object(telegram_bot, "send_message", return_value=True) as mocked:
                with urlopen(req, timeout=3) as resp:
                    self.assertEqual(resp.status, 200)
                mocked.assert_called_once()
                self.assertIn("Computadores", mocked.call_args.args[1])

    def test_telegram_rejects_other_chats(self):
        with patch.dict(os.environ, {"TELEGRAM_CHAT_ID":"123"}):
            with patch.object(telegram_bot, "send_message") as mocked:
                telegram_bot.process_message({"message":{"chat":{"id":456},"text":"/estado"}}, lambda: {})
                mocked.assert_not_called()

    def test_nexdc_endpoint(self):
        stub={"domain":"nexdcglobal.pages.dev", "availability":"test", "tls":"test"}
        with patch.object(server, "cached_check", return_value=stub):
            status, body = self.get("/api/web/nexdc/status?utm_source=chatgpt.com")
        self.assertEqual(status, 200)
        self.assertIn("nexdcglobal.pages.dev", body)

if __name__ == "__main__":
    unittest.main()
