import json
import os
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

import base64

from umbra.links import parse_link, parse_vless
from umbra.xrayconf import build_config, build_probe_config, build_routing, split_user_rules

UUID = "11111111-2222-3333-4444-555555555555"
REALITY = (f"vless://{UUID}@example.com:443?flow=xtls-rprx-vision&security=reality&sni=www.microsoft.com"
           "&fp=chrome&pbk=PUBKEY&sid=ab12&spx=%2F&type=tcp#r")
LINKS = {
    "reality": REALITY,
    "tls-ws": f"vless://{UUID}@example.com:443?security=tls&type=ws&path=%2Fws&host=cdn.example.com&sni=cdn.example.com#w",
    "tls-grpc": f"vless://{UUID}@example.com:443?security=tls&type=grpc&serviceName=svc&mode=multi#g",
    "tls-xhttp": f"vless://{UUID}@example.com:443?security=tls&type=xhttp&path=%2Fx&mode=auto#x",
    "tls-httpupgrade": f"vless://{UUID}@example.com:443?security=tls&type=httpupgrade&path=%2Fu#h",
    "tls-xhttp-extra": (f"vless://{UUID}@example.com:443?security=tls&type=xhttp&path=%2Fx&mode=packet-up"
                        "&extra=%7B%22xPaddingBytes%22%3A%22100-1000%22%2C%22xmux%22%3A%7B%22maxConcurrency%22%3A%2216-32%22%7D%7D#e"),
    "reality-grpc": f"vless://{UUID}@example.com:443?security=reality&sni=www.microsoft.com&pbk=PUBKEY&sid=ab&type=grpc&serviceName=svc#rg",
    "reality-xhttp": f"vless://{UUID}@example.com:2053?security=reality&sni=www.microsoft.com&pbk=PUBKEY&sid=ab&type=xhttp&path=%2F&mode=auto#rx",
    "trojan-tls": "trojan://pw@example.com:443?sni=example.com&type=tcp#t",
    "trojan-ws": "trojan://pw@example.com:443?sni=example.com&type=ws&path=%2Ft#tw",
    "ss-aead": "ss://" + base64.b64encode(b"aes-256-gcm:secret").decode() + "@example.com:8388#s",
    "ss-2022": "ss://2022-blake3-aes-128-gcm:" + base64.b64encode(b"0123456789abcdef").decode() + "@example.com:8388#s22",
    "vmess-ws-tls": "vmess://" + base64.b64encode(json.dumps({
        "v": "2", "ps": "vm", "add": "example.com", "port": "443", "id": UUID, "aid": "0",
        "net": "ws", "path": "/w", "host": "c.example.com", "tls": "tls", "sni": "c.example.com"}).encode()).decode(),
    "vmess-tcp": "vmess://" + base64.b64encode(json.dumps({
        "v": "2", "ps": "vm2", "add": "example.com", "port": 10086, "id": UUID, "aid": 0, "net": "tcp", "scy": "aes-128-gcm"}).encode()).decode(),
    "plain": f"vless://{UUID}@127.0.0.1:20443?security=none#p",
}


class Config(unittest.TestCase):
    def test_reality_outbound(self):
        cfg = build_config(parse_vless(REALITY))
        out = cfg["outbounds"][0]
        self.assertEqual(out["tag"], "proxy")  # first outbound = default route
        user = out["settings"]["vnext"][0]["users"][0]
        self.assertEqual((user["id"], user["flow"], user["encryption"]), (UUID, "xtls-rprx-vision", "none"))
        rs = out["streamSettings"]["realitySettings"]
        self.assertEqual((rs["serverName"], rs["publicKey"], rs["shortId"], rs["spiderX"]),
                         ("www.microsoft.com", "PUBKEY", "ab12", "/"))
        self.assertEqual([i["listen"] for i in cfg["inbounds"]], ["127.0.0.1", "127.0.0.1"])

    def test_no_flow_key_when_empty(self):
        cfg = build_config(parse_vless(LINKS["tls-ws"]))
        self.assertNotIn("flow", cfg["outbounds"][0]["settings"]["vnext"][0]["users"][0])

    def test_routing_modes(self):
        g = build_routing("global", [])
        self.assertEqual(g["domainStrategy"], "AsIs")
        self.assertEqual(len(g["rules"]), 1)  # only the private ranges
        r = build_routing("bypass_ru", ["example.org", "10.1.0.0/16"])
        self.assertEqual(r["domainStrategy"], "IPIfNonMatch")
        flat = json.dumps(r)
        for needle in ("domain:example.org", "10.1.0.0/16", "geoip:ru", "geoip:private", "domain:ru"):
            self.assertIn(needle, flat)
        self.assertIn("geoip:private", json.dumps(r["rules"][-3]))  # LAN rule precedes RU rules
        with self.assertRaises(ValueError):
            build_routing("nope", [])

    def test_forced_proxy_wins_and_extras(self):
        r = build_routing("bypass_ru", ["a.com"], ["gosuslugi.ru"])
        self.assertEqual(r["rules"][0], {"type": "field", "domain": ["domain:gosuslugi.ru"], "outboundTag": "proxy"})
        cfg = build_config(parse_vless(LINKS["plain"]), "global", metrics_port=12345)
        self.assertEqual(cfg["log"]["access"], "none")
        self.assertEqual(cfg["metrics"]["listen"], "127.0.0.1:12345")
        self.assertNotIn("access", build_config(parse_vless(LINKS["plain"]), show_connections=True)["log"])
        self.assertNotIn("metrics", build_config(parse_vless(LINKS["plain"])))

    def test_other_protocol_outbounds(self):
        t = build_config(parse_link(LINKS["trojan-tls"]))["outbounds"][0]
        self.assertEqual((t["protocol"], t["settings"]["servers"][0]["password"], t["streamSettings"]["security"]),
                         ("trojan", "pw", "tls"))
        s = build_config(parse_link(LINKS["ss-aead"]))["outbounds"][0]
        self.assertEqual((s["protocol"], s["settings"]["servers"][0]["method"]), ("shadowsocks", "aes-256-gcm"))
        v = build_config(parse_link(LINKS["vmess-tcp"]))["outbounds"][0]
        self.assertEqual((v["protocol"], v["settings"]["vnext"][0]["users"][0]["security"]), ("vmess", "aes-128-gcm"))

    def test_presets(self):
        from umbra.xrayconf import PRESETS
        cfg = build_config(parse_vless(LINKS["plain"]), "global", direct_entries=["mine.com"],
                           presets=["ads_block", "torrents_direct"])
        rules = cfg["routing"]["rules"]
        self.assertEqual(rules[0]["domain"], ["domain:mine.com"])            # the user's rule stays first
        self.assertEqual(rules[1], {"type": "field", "domain": ["geosite:category-ads-all"], "outboundTag": "block"})
        self.assertEqual(rules[2], {"type": "field", "protocol": ["bittorrent"], "outboundTag": "direct"})
        self.assertIn("block", [o["tag"] for o in cfg["outbounds"]])
        self.assertEqual(cfg["outbounds"][0]["tag"], "proxy")                # default route unchanged
        self.assertEqual(set(PRESETS), {"ads_block", "ru_direct", "torrents_direct"})
        with self.assertRaises(ValueError):
            build_routing("global", [], [], ["nope"])

    def test_user_rules(self):
        d, i = split_user_rules(["Example.COM", "full:a.b.com", "geoip:cn", "192.168.0.0/16", "# c", ""])
        self.assertEqual(d, ["domain:example.com", "full:a.b.com"])
        self.assertEqual(i, ["geoip:cn", "192.168.0.0/16"])


@unittest.skipUnless(os.environ.get("XRAY_DIR"), "set XRAY_DIR to a folder with xray + geo files")
class WithRealXray(unittest.TestCase):
    """Ask the real Xray binary to validate every generated config."""

    def test_xray_accepts_all_variants(self):
        xdir = Path(os.environ["XRAY_DIR"])
        env = dict(os.environ, XRAY_LOCATION_ASSET=str(xdir))
        for name, link in LINKS.items():
            for mode in ("global", "bypass_ru"):
                with self.subTest(link=name, mode=mode):
                    cfg = build_config(parse_link(link), mode, direct_entries=["example.org", "10.0.0.0/8"],
                                       proxy_entries=["forced.ru", "geoip:cn"], metrics_port=23991,
                                       presets=["ads_block", "ru_direct", "torrents_direct"])
                    if name.startswith("reality"):
                        # a syntactically valid x25519 key (base64url, 32 bytes)
                        cfg["outbounds"][0]["streamSettings"]["realitySettings"]["publicKey"] = \
                            "5Y2C5nQ3oVQdZ0lD3tJ7wq7r5oG0Zr8YyXz7oN0JXmA"
                    with tempfile.TemporaryDirectory() as tmp:
                        p = Path(tmp) / "c.json"
                        p.write_text(json.dumps(cfg))
                        res = subprocess.run([str(xdir / "xray"), "run", "-test", "-c", str(p)],
                                             capture_output=True, text=True, env=env, timeout=30)
                    self.assertEqual(res.returncode, 0, res.stdout + res.stderr)

    def test_xray_accepts_probe_config(self):
        xdir = Path(os.environ["XRAY_DIR"])
        env = dict(os.environ, XRAY_LOCATION_ASSET=str(xdir))
        servers = [(name.replace("-", ""), parse_link(link), 24000 + i)
                   for i, (name, link) in enumerate(LINKS.items()) if not name.startswith("reality")]
        cfg = build_probe_config(servers)
        self.assertEqual(len(cfg["inbounds"]), len(servers))
        self.assertEqual(len(cfg["routing"]["rules"]), len(servers))
        with tempfile.TemporaryDirectory() as tmp:
            p = Path(tmp) / "c.json"
            p.write_text(json.dumps(cfg))
            res = subprocess.run([str(xdir / "xray"), "run", "-test", "-c", str(p)],
                                 capture_output=True, text=True, env=env, timeout=30)
        self.assertEqual(res.returncode, 0, res.stdout + res.stderr)


if __name__ == "__main__":
    unittest.main()
