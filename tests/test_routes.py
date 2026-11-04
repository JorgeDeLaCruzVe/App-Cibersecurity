import threading
import unittest
from http.server import ThreadingHTTPServer
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from unittest.mock import patch
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

    def test_nexdc_endpoint(self):
        stub={"domain":"nexdcglobal.pages.dev", "availability":"test", "tls":"test"}
        with patch.object(server, "cached_check", return_value=stub):
            status, body = self.get("/api/web/nexdc/status?utm_source=chatgpt.com")
        self.assertEqual(status, 200)
        self.assertIn("nexdcglobal.pages.dev", body)

if __name__ == "__main__":
    unittest.main()
