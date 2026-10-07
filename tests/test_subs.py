import base64
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer

from umbra.subs import decode_subscription, fetch_subscription, parse_title, parse_userinfo

LINES = ["vless://a@h:1#one", "vless://b@h:2#two", "trojan://x@h:3#t"]
PLAIN = "\n".join(LINES).encode()


class Decode(unittest.TestCase):
    def test_plain(self):
        self.assertEqual(decode_subscription(PLAIN + b"\n\n"), LINES)

    def test_base64_variants(self):
        std = base64.b64encode(PLAIN)
        self.assertEqual(decode_subscription(std), LINES)
        self.assertEqual(decode_subscription(std.rstrip(b"=")), LINES)           # no padding
        self.assertEqual(decode_subscription(base64.urlsafe_b64encode(PLAIN)), LINES)
        wrapped = b"\n".join(std[i:i + 20] for i in range(0, len(std), 20))        # line-wrapped
        self.assertEqual(decode_subscription(wrapped), LINES)

    def test_garbage(self):
        with self.assertRaises(ValueError):
            decode_subscription(b"%%% not base64 and no links %%%")


class Fetch(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        body = {"/plain": PLAIN, "/b64": base64.b64encode(PLAIN),
                "/happ": b"happ://crypt3/AAAA"}

        class H(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                data = body.get(self.path)
                self.send_response(200 if data else 404)
                if self.path == "/b64":
                    self.send_header("profile-title", "base64:" + base64.b64encode("Мой VPN".encode()).decode())
                    self.send_header("subscription-userinfo", "upload=10; download=20; total=1000; expire=1790000000")
                self.end_headers()
                self.wfile.write(data or b"")

            def log_message(self, *a):
                pass

        cls.srv = HTTPServer(("127.0.0.1", 0), H)
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()

    def test_fetch(self):
        plain = fetch_subscription(self.base + "/plain")
        self.assertEqual((plain.lines, plain.title, plain.info), (LINES, "", {}))
        rich = fetch_subscription(self.base + "/b64")
        self.assertEqual(rich.lines, LINES)
        self.assertEqual(rich.title, "Мой VPN")
        self.assertEqual(rich.info, {"upload": 10, "download": 20, "total": 1000, "expire": 1790000000})

    def test_header_parsers(self):
        self.assertEqual(parse_userinfo("upload=1;download=2; total=x; junk"), {"upload": 1, "download": 2})
        self.assertEqual(parse_title("My%20VPN"), "My VPN")
        self.assertEqual(parse_title("base64:!!!"), "")

    def test_encrypted_is_rejected_clearly(self):
        with self.assertRaises(ValueError) as ctx:
            fetch_subscription(self.base + "/happ")
        self.assertIn("зашифрована", str(ctx.exception))

    def test_bad_scheme(self):
        with self.assertRaises(ValueError):
            fetch_subscription("file:///etc/passwd")
        with self.assertRaises(ValueError):
            fetch_subscription("ftp://example.com/x")


if __name__ == "__main__":
    unittest.main()
