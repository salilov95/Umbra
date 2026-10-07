"""Controller + HTTP server behaviour (no Xray needed)."""
import json
import os
import tempfile
import unittest
import urllib.error
import urllib.request
from pathlib import Path

os.environ.setdefault("UMBRA_HOME", tempfile.mkdtemp(prefix="vc-test-"))

from umbra.controller import ApiError, Controller  # noqa: E402
from umbra.server import UiServer  # noqa: E402

UUID = "11111111-2222-3333-4444-555555555555"
L1 = f"vless://{UUID}@a.example.com:443?security=reality&pbk=K&sni=x.com&type=tcp#One"
L2 = f"vless://{UUID}@b.example.com:443?security=tls&type=ws&path=%2F#Two"


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.home = Path(tempfile.mkdtemp(prefix="vc-ctrl-"))
        self.c = Controller(self.home)

    def tearDown(self):
        self.c.quit_event.set()

    def test_add_dedupe_select_delete(self):
        r = self.c.add_links(f"{L1}\n{L2}\n{L1}\nnonsense\nvless://bad")
        self.assertEqual(r["added"], 2)
        self.assertEqual(len(r["skipped"]), 3)
        st = self.c.state()
        self.assertEqual([s["name"] for s in st["servers"]], ["One", "Two"])
        self.assertEqual(st["selected"], st["servers"][0]["id"])   # first one auto-selected
        second = st["servers"][1]["id"]
        self.c.select(second)
        self.assertEqual(self.c.state()["selected"], second)
        self.c.delete(second)
        st = self.c.state()
        self.assertEqual(len(st["servers"]), 1)
        self.assertEqual(st["selected"], st["servers"][0]["id"])

    def test_state_does_not_leak_secrets(self):
        self.c.add_links(L1)
        dumped = json.dumps(self.c.state())
        self.assertNotIn(UUID, dumped)
        self.assertNotIn("pbk=K", dumped)

    def test_persistence(self):
        self.c.add_links(L1)
        c2 = Controller(self.home)
        self.assertEqual(len(c2.state()["servers"]), 1)
        c2.quit_event.set()

    def test_settings_validation(self):
        for kwargs in ({"socks_port": 80}, {"socks_port": 2000, "http_port": 2000},
                       {"loglevel": "loud"}, {"http_port": 70000}):
            with self.subTest(kwargs=kwargs):
                with self.assertRaises(ApiError):
                    self.c.set_settings(**kwargs)
        self.c.set_settings(socks_port=11080, http_port=11081, direct_domains=["a.com", " ", "b.com"])
        s = self.c.state()["settings"]
        self.assertEqual((s["socks_port"], s["http_port"], s["direct_domains"]), (11080, 11081, ["a.com", "b.com"]))

    def test_flags_rename_and_copy(self):
        self.c.add_links(f"vless://{UUID}@a.example.com:443?security=none#%F0%9F%87%B3%F0%9F%87%B1%20Amsterdam")
        srv = self.c.state()["servers"][0]
        self.assertEqual((srv["country"], srv["name"]), ("NL", "Amsterdam"))
        self.c.rename(srv["id"], "  Мой   сервер ")
        srv = self.c.state()["servers"][0]
        self.assertEqual((srv["country"], srv["name"]), ("NL", "Мой сервер"))   # flag survives
        with self.assertRaises(ApiError):
            self.c.rename(srv["id"], "   ")
        self.assertIn(UUID, self.c.get_link(srv["id"])["link"])                # only on explicit copy

    def test_more_settings(self):
        self.c.set_settings(auto_connect=True, failover=True, proxy_domains=["x.ru"], show_connections=True)
        s = self.c.state()["settings"]
        self.assertEqual((s["auto_connect"], s["failover"], s["proxy_domains"], s["show_connections"]),
                         (True, True, ["x.ru"], True))
        with self.assertRaises(ApiError):
            self.c.set_settings(nonsense=1)
        with self.assertRaises(ApiError):
            self.c.set_settings(autostart=True)     # only offered in the .exe build
        with self.assertRaises(ApiError):
            self.c.set_settings(direct_domains="not a list")

    def test_select_best_picks_lowest_ping(self):
        import umbra.controller as mod
        self.c.add_links(f"{L1}\n{L2}")
        ids = [s["id"] for s in self.c.state()["servers"]]
        fake = {"a.example.com": 250, "b.example.com": 40}
        orig = mod.tcp_ping
        mod.tcp_ping = lambda host, port, timeout=3.0: fake[host]
        try:
            res = self.c.select_best()
        finally:
            mod.tcp_ping = orig
        self.assertEqual((res["id"], res["ms"]), (ids[1], 40))
        self.assertEqual(self.c.state()["selected"], ids[1])

    def test_error_wording_and_probe(self):
        import socket
        from urllib.error import URLError
        from umbra.controller import explain_error, probe_url
        self.assertIn("DNS", explain_error(URLError(socket.gaierror(-2, "x"))))
        self.assertIn("сброшено", explain_error(ConnectionResetError()))
        self.assertIn("время вышло", explain_error(URLError(TimeoutError("timed out"))))
        r = probe_url("http://127.0.0.1:9/", None, timeout=2)
        self.assertEqual((r["ok"], r["status"]), (False, None))
        self.assertTrue(r["error"])

    def test_tray_setting_and_struct_layout(self):
        import ctypes
        from umbra import tray
        self.assertTrue(self.c.state()["settings"]["close_to_tray"])
        self.assertFalse(self.c.state()["tray"])                  # no tray outside Windows
        self.c.set_settings(close_to_tray=False)
        self.assertFalse(self.c.state()["settings"]["close_to_tray"])
        # the sizes Windows expects on 64-bit (wchar is 2 bytes there)
        self.assertEqual(ctypes.sizeof(tray.make_notify_struct(ctypes.c_uint16)), 976)
        self.assertEqual(ctypes.sizeof(tray.MSG), 48)
        if not tray.IS_WINDOWS:
            self.assertFalse(tray.Tray(dict, print, print, print).start())

    def test_presets_notifications_and_quiet_log_default(self):
        s = self.c.state()
        self.assertEqual(s["settings"]["loglevel"], "error")
        self.assertEqual(set(s["presets"]), {"ads_block", "ru_direct", "torrents_direct"})
        self.c.set_settings(presets=["torrents_direct", "ads_block"])
        self.assertEqual(self.c.state()["settings"]["presets"], ["ads_block", "torrents_direct"])
        with self.assertRaises(ApiError):
            self.c.set_settings(presets=["bogus"])

        seen = []
        self.c.notify_hook = lambda title, text: seen.append(title)
        self.c.notify("A", "b")
        self.c.set_settings(notifications=False)
        self.c.notify("C", "d")                                   # switched off: journal only
        self.assertEqual(seen, ["A"])
        self.c.notify_hook = lambda *a: 1 / 0                     # a broken hook must not break anything
        self.c.set_settings(notifications=True)
        self.c.notify("E", "f")
        self.assertIn("E: f", " ".join(l["text"] for l in self.c.logs.since(0)))

    def test_old_warning_loglevel_is_migrated_once(self):
        import json as _json
        home = Path(tempfile.mkdtemp(prefix="vc-log-"))
        (home / "state.json").write_text(_json.dumps({"loglevel": "warning"}), encoding="utf-8")
        c = Controller(home)
        self.assertEqual(c.data["loglevel"], "error")
        c.set_settings(loglevel="warning")                        # the user's own later choice is kept
        c.quit_event.set()
        c2 = Controller(home)
        self.assertEqual(c2.data["loglevel"], "warning")
        c2.quit_event.set()

    def test_subscription_expiry_warning(self):
        import time as _time
        seen = []
        self.c.notify_hook = lambda title, text: seen.append((title, text))
        now = _time.time()
        self.c.data["subscriptions"] = [
            {"id": "a", "url": "https://p.example/1", "name": "Soon", "info": {"expire": now + 2.5 * 86400}},
            {"id": "b", "url": "https://p.example/2", "name": "Later", "info": {"expire": now + 40 * 86400}},
            {"id": "c", "url": "https://p.example/3", "name": "Gone", "info": {"expire": now - 86400}},
            {"id": "d", "url": "https://p.example/4", "name": "NoDate", "info": {}},
        ]
        self.c.warn_expiring()
        self.c.warn_expiring()                                    # only once per run
        self.assertEqual([t for t, _ in seen], ["Подписка скоро закончится", "Подписка закончилась"])
        self.assertIn("Soon", seen[0][1])
        self.assertIn("через 2 дн.", seen[0][1])

    def test_update_check(self):
        import threading
        from http.server import BaseHTTPRequestHandler, HTTPServer
        import umbra.controller as mod

        class H(BaseHTTPRequestHandler):
            tag = "v9.9.9"

            def do_GET(self):  # noqa: N802
                if self.path.endswith("/releases/latest"):
                    self.send_response(302)
                    self.send_header("Location", f"/me/app/releases/tag/{H.tag}")
                    self.end_headers()
                else:
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"release page")

            def log_message(self, *a):
                pass

        srv = HTTPServer(("127.0.0.1", 0), H)
        threading.Thread(target=srv.serve_forever, daemon=True).start()
        old = (mod.UPDATE_REPO, mod.UPDATE_URL)
        try:
            mod.UPDATE_REPO = ""
            self.assertEqual(self.c.check_update(), {"configured": False, "update": None})   # no repo: no requests
            mod.UPDATE_REPO = "me/app"
            mod.UPDATE_URL = f"http://127.0.0.1:{srv.server_address[1]}/{{repo}}/releases/latest"
            self.assertEqual(self.c.check_update()["update"]["version"], "9.9.9")
            self.assertEqual(self.c.state()["update"]["version"], "9.9.9")
            H.tag = "v0.0.1"                                      # older than what we run
            self.assertIsNone(self.c.check_update()["update"])
            self.assertIsNone(self.c.state()["update"])
            with self.assertRaises(ApiError):
                self.c.open_update()
        finally:
            mod.UPDATE_REPO, mod.UPDATE_URL = old
            srv.shutdown()

    def test_qr(self):
        from umbra.qr import make_qr
        self.c.add_links(L1)
        sid = self.c.state()["servers"][0]["id"]
        res = self.c.qr(sid)
        rows = res["rows"]
        self.assertEqual(res["name"], "One")
        self.assertTrue(all(len(r) == len(rows) for r in rows))   # square
        self.assertEqual((len(rows) - 17) % 4, 0)                 # a legal QR size
        self.assertEqual(rows[0][:7], "1111111")                  # top-left finder pattern
        self.assertEqual(rows[3][:7], "1011101")
        with self.assertRaises(ValueError):
            make_qr("x" * 5000)
        try:
            import cv2
            import numpy as np
        except ImportError:
            return                                                # no decoder here: structure checks only
        scale, quiet, n = 8, 4, len(rows)
        img = np.full(((n + 2 * quiet) * scale,) * 2, 255, np.uint8)
        for y, row in enumerate(rows):
            for x, cell in enumerate(row):
                if cell == "1":
                    img[(y + quiet) * scale:(y + quiet + 1) * scale, (x + quiet) * scale:(x + quiet + 1) * scale] = 0
        self.assertEqual(cv2.QRCodeDetector().detectAndDecode(img)[0], L1)

    def test_data_of_the_old_name_is_adopted_once(self):
        from umbra.store import LEGACY_DIR, adopt_legacy_data
        root = Path(tempfile.mkdtemp(prefix="vc-rename-"))
        old, new = root / LEGACY_DIR, root / "Umbra"
        (old / "core").mkdir(parents=True)
        (old / "ui-profile").mkdir()
        (old / "state.json").write_text('{"mode": "global"}', encoding="utf-8")
        (old / "core" / "geoip.dat").write_bytes(b"geo")
        (old / "app.log").write_text("log", encoding="utf-8")
        self.assertTrue(adopt_legacy_data(new, old))
        self.assertEqual((new / "core" / "geoip.dat").read_bytes(), b"geo")
        self.assertFalse((new / "ui-profile").exists() or (new / "app.log").exists())
        self.assertTrue((old / "state.json").exists())            # the old folder is not touched
        (new / "state.json").write_text('{"mode": "bypass_ru"}', encoding="utf-8")
        self.assertFalse(adopt_legacy_data(new, old))             # never overwrites newer data
        self.assertIn("bypass_ru", (new / "state.json").read_text(encoding="utf-8"))
        self.assertFalse(adopt_legacy_data(root / "Other", root / "nothing-here"))
        c = Controller(new)
        self.assertEqual(c.data["mode"], "bypass_ru")
        c.quit_event.set()

    def test_traffic_math(self):
        from umbra.controller import Traffic
        t = Traffic()
        t.update({"inbound": {"http-in": {"downlink": 1000, "uplink": 100}}}, 10.0)
        self.assertEqual((t.down_bps, t.down_total), (0, 1000))                 # first sample: no speed yet
        t.update({"inbound": {"http-in": {"downlink": 5000, "uplink": 300}, "socks-in": {"downlink": 1000, "uplink": 0}},
                  "outbound": {"proxy": {"downlink": 4000, "uplink": 0}, "direct": {"downlink": 2000, "uplink": 0}}}, 12.0)
        self.assertEqual((t.down_bps, t.up_bps), (2500, 100))
        self.assertEqual((t.proxy_total, t.direct_total), (4000, 2000))
        self.assertEqual(len(t.public()["history"]), 60)
        t.update({"inbound": {}}, 13.0)                                         # counters reset -> never negative
        self.assertEqual(t.down_bps, 0)

    def test_old_state_is_migrated(self):
        import json as _json
        home = Path(tempfile.mkdtemp(prefix="vc-mig-"))
        url = "https://panel.example/sub/TOKEN"
        (home / "state.json").write_text(_json.dumps({
            "servers": [{"id": "aa", "name": "One", "link": L1, "sub": url},
                        {"id": "bb", "name": "Two", "link": L2, "sub": None}],
            "subscriptions": [url], "selected": "aa"}), encoding="utf-8")
        c = Controller(home)
        st = c.state()
        self.assertEqual(len(st["subs"]), 1)
        self.assertEqual(st["subs"][0]["count"], 1)
        self.assertEqual(st["subs"][0]["host"], "panel.example")
        self.assertNotIn("TOKEN", _json.dumps(st))          # the subscription URL is a secret too
        self.assertEqual(st["servers"][0]["sub"], st["subs"][0]["id"])
        c.delete_sub(st["subs"][0]["id"])
        self.assertEqual([s["name"] for s in c.state()["servers"]], ["Two"])
        c.quit_event.set()

    def test_call_dispatch(self):
        with self.assertRaises(ApiError):
            self.c.call("nope", {})
        with self.assertRaises(ApiError):
            self.c.call("select", {"wrong": 1})
        with self.assertRaises(ApiError):
            self.c.call("connect", {})        # nothing selected

    def test_connect_installs_core_automatically_and_reports_failure(self):
        from umbra.core import CoreError
        calls = []

        def failing_install():
            calls.append(1)
            raise CoreError("не удалось скачать: boom")

        self.c.core.install = failing_install       # no network in unit tests
        self.c.add_links(L1)
        with self.assertRaises(ApiError) as ctx:
            self.c.connect()
        msg = str(ctx.exception)
        self.assertEqual(len(calls), 1)             # it tried to install by itself
        self.assertIn("boom", msg)
        self.assertIn("вручную", msg)               # and tells how to do it by hand
        self.assertIn(str(self.c.core.dir), msg)
        self.assertEqual(self.c.core.install_state["running"], False)
        self.assertIn("boom", self.c.core.install_state["error"])
        self.assertFalse(self.c.connecting)
        self.assertFalse(self.c.connected)
        logged = " ".join(l["text"] for l in self.c.logs.since(0))
        self.assertIn("не удалось подключиться", logged)   # reason survives in the log


class ServerSecurity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ctrl = Controller(Path(tempfile.mkdtemp(prefix="vc-srv-")))
        cls.srv = UiServer(cls.ctrl, 0)
        import threading
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.srv.port}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown()
        cls.ctrl.quit_event.set()

    def req(self, path, data=None, headers=None):
        r = urllib.request.Request(self.base + path, data=data, headers=headers or {})
        try:
            with urllib.request.urlopen(r, timeout=5) as resp:
                return resp.status, resp.read(), resp.headers
        except urllib.error.HTTPError as e:
            return e.code, e.read(), e.headers

    def test_page_needs_token(self):
        self.assertEqual(self.req("/")[0], 403)
        self.assertEqual(self.req("/?t=wrong")[0], 403)
        code, body, hdrs = self.req("/?t=" + self.srv.token)
        self.assertEqual(code, 200)
        self.assertIn(self.srv.token.encode(), body)
        self.assertIn("script-src 'self'", hdrs["Content-Security-Policy"])

    def test_static(self):
        self.assertEqual(self.req("/app.js")[0], 200)
        self.assertEqual(self.req("/app.css")[0], 200)
        self.assertEqual(self.req("/../server.py")[0], 404)

    def test_api_needs_token_host_origin(self):
        body = json.dumps({"since": 0}).encode()
        ok = {"X-Token": self.srv.token, "Content-Type": "application/json"}
        self.assertEqual(self.req("/api/poll", body, {})[0], 403)                       # no token
        self.assertEqual(self.req("/api/poll", body, {"X-Token": "bad"})[0], 403)       # wrong token
        self.assertEqual(self.req("/api/poll", body, {**ok, "Origin": "http://evil.example"})[0], 403)
        self.assertEqual(self.req("/api/poll", body, {**ok, "Host": "evil.example"})[0], 403)  # rebinding
        code, raw, _ = self.req("/api/poll", body, ok)
        self.assertEqual(code, 200)
        self.assertIn("servers", json.loads(raw)["state"])

    def test_api_errors_are_json(self):
        ok = {"X-Token": self.srv.token}
        code, raw, _ = self.req("/api/connect", b"{}", ok)
        self.assertEqual(code, 400)
        self.assertIn("error", json.loads(raw))
        self.assertEqual(self.req("/api/poll", b"[1,2]", ok)[0], 400)
        self.assertEqual(self.req("/api/poll", b"{not json", ok)[0], 400)


if __name__ == "__main__":
    unittest.main()
