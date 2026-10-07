"""End-to-end: our Controller drives a real Xray against a local VLESS server.

Needs XRAY_DIR (folder with xray + geoip.dat + geosite.dat) and permission to
edit /etc/hosts (the test maps two fake host names to 127.0.0.1). Meant for a
Linux sandbox, not for the Windows machine.
"""
import json
import os
import shutil
import subprocess
import tempfile
import threading
import time
import unittest
import urllib.request
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

XRAY_DIR = os.environ.get("XRAY_DIR")
HOSTS = Path("/etc/hosts")
MARK = "# umbra-e2e"
UUID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


def can_run():
    return bool(XRAY_DIR) and os.name == "posix" and os.access(HOSTS, os.W_OK)


@unittest.skipUnless(can_run(), "needs XRAY_DIR and writable /etc/hosts")
class EndToEnd(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ["UMBRA_HOME"] = tempfile.mkdtemp(prefix="vc-e2e-")
        import umbra.controller as mod
        from umbra.controller import Controller
        # probe our own local "internet" instead of gstatic / cloudflare
        mod.HEALTH_URL = "http://testsite.example:18080/"
        mod.TRACE_URL = "http://testsite.example:18080/trace"
        mod.RECONNECT_DELAYS = (0.5, 1, 1)
        # the first host is dead on purpose: the test must fall through to the next one
        mod.SPEED_URLS = ["http://127.0.0.1:9/nothing", "http://testsite.example:18080/big"]
        mod.SITE_TIMEOUT = 4
        mod.PROBE_TIMEOUT = 3
        cls.tmp = Path(tempfile.mkdtemp(prefix="vc-e2e-"))
        cls.hosts_backup = "\n".join(l for l in HOSTS.read_text().splitlines() if MARK not in l) + "\n"
        cls.addClassCleanup(lambda: HOSTS.write_text(cls.hosts_backup))   # even if setup fails halfway
        HOSTS.write_text(cls.hosts_backup + f"\n127.0.0.1 testsite.example {MARK}\n127.0.0.1 testsite.ru {MARK}\n")

        class H(BaseHTTPRequestHandler):
            def do_GET(self):  # noqa: N802
                self.send_response(200)
                self.end_headers()
                if self.path == "/trace":
                    self.wfile.write(b"fl=1\nip=203.0.113.7\nloc=NL\n")
                elif self.path == "/big":
                    self.wfile.write(b"x" * 300_000)
                else:
                    self.wfile.write(b"hello-from-origin")

            def log_message(self, *a):
                pass

        cls.origin = HTTPServer(("127.0.0.1", 18080), H)
        threading.Thread(target=cls.origin.serve_forever, daemon=True).start()

        # the "remote" VLESS server
        server_cfg = {
            "log": {"loglevel": "info"},
            "inbounds": [
                {"listen": "127.0.0.1", "port": 20443, "protocol": "vless",
                 "settings": {"clients": [{"id": UUID}], "decryption": "none"}},
                {"listen": "127.0.0.1", "port": 20444, "protocol": "vmess",
                 "settings": {"clients": [{"id": UUID}]}},
                {"listen": "127.0.0.1", "port": 20445, "protocol": "trojan",
                 "settings": {"clients": [{"password": "tr-pass"}]}},
                {"listen": "127.0.0.1", "port": 20446, "protocol": "shadowsocks",
                 "settings": {"method": "aes-256-gcm", "password": "ss-pass", "network": "tcp,udp"}},
            ],
            "outbounds": [{"protocol": "freedom"}],
        }
        (cls.tmp / "server.json").write_text(json.dumps(server_cfg))
        env = dict(os.environ, XRAY_LOCATION_ASSET=XRAY_DIR)
        cls.server_log = cls.tmp / "server.log"
        cls.server = subprocess.Popen([f"{XRAY_DIR}/xray", "run", "-c", str(cls.tmp / "server.json")],
                                      stdout=open(cls.server_log, "w"), stderr=subprocess.STDOUT, env=env)
        time.sleep(1)

        cls.ctrl = Controller(Path(os.environ["UMBRA_HOME"]))
        for name in ("xray", "geoip.dat", "geosite.dat"):
            shutil.copy(f"{XRAY_DIR}/{name}", cls.ctrl.core.dir / name)
        cls.ctrl.add_links(f"vless://{UUID}@127.0.0.1:20443?security=none&type=tcp#local")
        cls.ctrl.set_settings(socks_port=21808, http_port=21809)

    @classmethod
    def tearDownClass(cls):
        cls.ctrl.shutdown()
        cls.server.terminate()
        cls.origin.shutdown()
        HOSTS.write_text(cls.hosts_backup)

    def fetch(self, url):
        proxy = "http://127.0.0.1:21809"
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({"http": proxy}))
        with opener.open(url, timeout=10) as r:
            return r.read().decode()

    def server_log_text(self):
        return self.server_log.read_text()

    def test_1_global_goes_through_vless(self):
        self.ctrl.set_mode("global")
        self.ctrl.connect()
        self.assertTrue(self.ctrl.connected)
        self.assertEqual(self.fetch("http://testsite.example:18080/"), "hello-from-origin")
        time.sleep(0.3)
        self.assertIn("testsite.example:18080", self.server_log_text())

    def wait_for(self, cond, seconds=8):
        end = time.time() + seconds
        while time.time() < end:
            if cond():
                return True
            time.sleep(0.1)
        return False

    def test_1b_tunnel_probe_exit_ip_and_traffic(self):
        self.assertTrue(self.wait_for(lambda: self.ctrl.health["ms"] is not None), "no health probe")
        self.assertEqual(self.ctrl.health["fails"], 0)
        self.assertTrue(self.wait_for(lambda: self.ctrl.exit is not None), "no exit ip")
        self.assertEqual((self.ctrl.exit["ip"], self.ctrl.exit["loc"]), ("203.0.113.7", "NL"))
        self.fetch("http://testsite.example:18080/big")
        self.assertTrue(self.wait_for(lambda: self.ctrl.traffic.down_total > 300_000), "counters did not move")
        st = self.ctrl.state()["traffic"]
        self.assertGreater(st["proxy_total"], 300_000)       # it went through the tunnel
        self.assertTrue(any(d > 0 for d, _ in st["history"]))

    def test_2_bypass_ru_goes_direct(self):
        self.ctrl.set_mode("bypass_ru")          # reconnects with new routing
        self.assertTrue(self.ctrl.connected)
        before = self.server_log_text().count("testsite.ru")
        self.assertEqual(self.fetch("http://testsite.ru:18080/"), "hello-from-origin")
        time.sleep(0.3)
        self.assertEqual(self.server_log_text().count("testsite.ru"), before)  # never reached the VLESS server

    def test_3_core_death_triggers_auto_reconnect(self):
        old = self.ctrl.core.proc
        old.kill()
        self.assertTrue(self.wait_for(lambda: self.ctrl.connected and self.ctrl.core.proc is not None
                                      and self.ctrl.core.proc is not old), "did not reconnect")
        self.assertEqual(self.fetch("http://testsite.ru:18080/"), "hello-from-origin")

    def test_3b_no_auto_reconnect_when_switched_off(self):
        self.ctrl.set_settings(auto_reconnect=False)
        self.ctrl.core.proc.kill()
        self.assertTrue(self.wait_for(lambda: not self.ctrl.connected))
        time.sleep(2.5)
        self.assertFalse(self.ctrl.connected)
        self.assertFalse(self.ctrl.reconnecting)
        self.ctrl.set_settings(auto_reconnect=True)

    def test_4_disconnect_closes_ports(self):
        self.ctrl.connect()
        self.assertTrue(self.ctrl.connected)
        self.ctrl.disconnect()
        self.assertFalse(self.ctrl.connected)
        from umbra.core import port_is_open
        self.assertFalse(port_is_open(21809))
        self.assertFalse(port_is_open(21808))

    def other_links(self):
        import base64
        vmess = "vmess://" + base64.b64encode(json.dumps({
            "v": "2", "ps": "vm-local", "add": "127.0.0.1", "port": "20444", "id": UUID, "aid": "0", "net": "tcp"}).encode()).decode()
        ss = "ss://" + base64.b64encode(b"aes-256-gcm:ss-pass").decode() + "@127.0.0.1:20446#ss-local"
        return {"vm-local": vmess, "tr-local": "trojan://tr-pass@127.0.0.1:20445?security=none#tr-local", "ss-local": ss}

    def test_5_vmess_trojan_shadowsocks_carry_traffic(self):
        self.ctrl.set_mode("global")
        res = self.ctrl.add_links("\n".join(self.other_links().values()))
        self.assertEqual((res["added"], res["skipped"]), (3, []))
        by_name = {s["name"]: s for s in self.ctrl.state()["servers"]}
        self.assertEqual({by_name[n]["protocol"] for n in self.other_links()}, {"vmess", "trojan", "shadowsocks"})
        for name in self.other_links():
            with self.subTest(protocol=name):
                marker = f"/via-{name}"
                self.ctrl.connect(by_name[name]["id"])
                self.assertTrue(self.ctrl.connected)
                self.assertEqual(self.fetch("http://testsite.example:18080" + marker), "hello-from-origin")
        self.ctrl.disconnect()
        log = self.server_log_text()
        for tag in ("vmess", "trojan", "shadowsocks"):
            self.assertRegex(log, rf"accepted tcp:testsite\.example:18080 \[.*\]|{tag}")

    def test_6_real_delay_through_each_tunnel(self):
        # a dead port and a link Xray itself rejects must not spoil the batch
        self.ctrl.add_links(f"vless://{UUID}@127.0.0.1:29999?security=none#dead\n"
                            f"vless://{UUID}@127.0.0.1:20443?security=reality&pbk=NOT-A-KEY&sni=a.com#badkey")
        self.ctrl.real_ping("all")
        delays = {s["name"]: s["delay"] for s in self.ctrl.state()["servers"]}
        for name in ("local", "vm-local", "tr-local", "ss-local"):
            self.assertGreater(delays[name], 0, name)
        self.assertEqual((delays["dead"], delays["badkey"]), (-1, -1))
        best = self.ctrl.select_best()
        self.assertIn(best["id"], [s["id"] for s in self.ctrl.state()["servers"] if s["delay"] and s["delay"] > 0])

    def test_7_speedtest(self):
        with self.assertRaises(Exception):
            self.ctrl.speedtest()                      # not connected
        self.ctrl.connect()
        res = self.ctrl.speedtest()
        self.assertGreater(res["mbps"], 0)
        self.assertEqual(res["bytes"], 300_000)
        self.assertEqual(self.ctrl.state()["speed"]["mbps"], res["mbps"])
        self.assertEqual(res["source"], "testsite.example")       # fell back past the dead host

    def test_8_site_check_both_paths_and_rules(self):
        self.ctrl.disconnect()                                     # works without a live connection
        ok = self.ctrl.check_site("http://testsite.example:18080/page")
        self.assertEqual(ok["verdict"], "both")
        self.assertEqual((ok["direct"]["status"], ok["server"]["status"]), (200, 200))
        self.assertIn(ok["server_name"], ("local", "vm-local", "tr-local", "ss-local"))
        self.assertIn("testsite.example:18080", self.server_log_text())   # really went through the server

        dead = self.ctrl.check_site("http://no-such-host.invalid/")
        self.assertEqual(dead["verdict"], "none")
        self.assertIn("DNS", dead["direct"]["error"])

        refused = self.ctrl.check_site("http://127.0.0.1:9/")
        self.assertFalse(refused["direct"]["ok"])

        for bad in ("", "ftp://x.com", "http://"):
            with self.subTest(bad=bad), self.assertRaises(Exception):
                self.ctrl.check_site(bad)

        self.ctrl.add_rule("Example.ORG", "proxy")
        self.ctrl.add_rule("example.org", "direct")               # moving a host between lists
        s = self.ctrl.state()["settings"]
        self.assertEqual((s["proxy_domains"], s["direct_domains"]), ([], ["example.org"]))
        with self.assertRaises(Exception):
            self.ctrl.add_rule("example.org", "sideways")


if __name__ == "__main__":
    unittest.main()
