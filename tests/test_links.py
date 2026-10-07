import unittest

import base64
import json

from umbra.links import is_supported, parse_link, parse_vless

UUID = "11111111-2222-3333-4444-555555555555"
REALITY = (
    f"vless://{UUID}@example.com:443?encryption=none&flow=xtls-rprx-vision&security=reality"
    "&sni=www.microsoft.com&fp=chrome&pbk=PUBKEY123&sid=ab12&spx=%2F&type=tcp&headerType=none"
    "#%F0%9F%87%A9%F0%9F%87%AA%20Berlin%20%231"
)


class ParseVless(unittest.TestCase):
    def test_reality(self):
        v = parse_vless(REALITY)
        self.assertEqual((v.uuid, v.host, v.port), (UUID, "example.com", 443))
        self.assertEqual((v.security, v.network, v.flow), ("reality", "tcp", "xtls-rprx-vision"))
        self.assertEqual((v.sni, v.fp, v.pbk, v.sid, v.spx), ("www.microsoft.com", "chrome", "PUBKEY123", "ab12", "/"))
        self.assertEqual(v.name, "🇩🇪 Berlin #1")

    def test_ws_tls(self):
        v = parse_vless(f"vless://{UUID}@1.2.3.4:8443?security=tls&type=ws&path=%2Fws%3Fed%3D2048"
                        "&host=cdn.example.com&sni=cdn.example.com&alpn=h2,http/1.1&fp=firefox#ws")
        self.assertEqual((v.network, v.security), ("ws", "tls"))
        self.assertEqual(v.path, "/ws?ed=2048")
        self.assertEqual(v.host_header, "cdn.example.com")
        self.assertEqual(v.alpn, ["h2", "http/1.1"])

    def test_grpc_and_aliases(self):
        v = parse_vless(f"vless://{UUID}@h.example:443?type=grpc&serviceName=svc&mode=multi&security=tls")
        self.assertEqual((v.network, v.service_name, v.mode), ("grpc", "svc", "multi"))
        self.assertEqual(parse_vless(f"vless://{UUID}@h.example:443?type=splithttp").network, "xhttp")
        self.assertEqual(parse_vless(f"vless://{UUID}@h.example:443?type=raw").network, "tcp")

    def test_default_name_and_ipv6(self):
        v = parse_vless(f"vless://{UUID}@[2001:db8::1]:443?security=none")
        self.assertEqual((v.host, v.port, v.name), ("2001:db8::1", 443, "2001:db8::1:443"))

    def test_xhttp_extra(self):
        extra = '{"xPaddingBytes":"100-1000","xmux":{"maxConcurrency":"16-32"}}'
        from urllib.parse import quote
        v = parse_vless(f"vless://{UUID}@h.example:443?type=xhttp&security=tls&mode=packet-up&extra={quote(extra)}")
        self.assertEqual(v.extra["xmux"]["maxConcurrency"], "16-32")
        for bad in ("{oops", "[1,2]"):
            with self.assertRaises(ValueError):
                parse_vless(f"vless://{UUID}@h.example:443?type=xhttp&extra={quote(bad)}")

    def test_errors(self):
        bad = {
            "http://x": "не vless",
            "vless://@h:443": "нет UUID",
            f"vless://{UUID}@:443": "нет адреса",
            f"vless://{UUID}@h": "порта",
            f"vless://{UUID}@h:99999": "адрес",
            f"vless://{UUID}@h:443?security=reality": "pbk",
            f"vless://{UUID}@h:443?type=kcp": "не поддерживается",
            f"vless://{UUID}@h:443?security=xtls": "не поддерживается",
        }
        for link, fragment in bad.items():
            with self.subTest(link=link):
                with self.assertRaises(ValueError) as ctx:
                    parse_vless(link)
                self.assertIn(fragment, str(ctx.exception))

    def test_trojan(self):
        v = parse_link("trojan://p%40ss@h.example:443?sni=a.com&type=ws&path=%2Ft#Tro")
        self.assertEqual((v.protocol, v.password, v.security, v.network, v.path, v.name),
                         ("trojan", "p@ss", "tls", "ws", "/t", "Tro"))        # TLS is the default
        self.assertEqual(parse_link("trojan://pw@h.example:443?security=none").security, "none")
        with self.assertRaises(ValueError):
            parse_link("trojan://@h.example:443")

    def test_shadowsocks_forms(self):
        b64 = lambda s: base64.urlsafe_b64encode(s.encode()).decode().rstrip("=")
        sip = parse_link(f"ss://{b64('aes-256-gcm:se:cret')}@h.example:8388#SS%201")
        self.assertEqual((sip.protocol, sip.method, sip.password, sip.port, sip.name),
                         ("shadowsocks", "aes-256-gcm", "se:cret", 8388, "SS 1"))
        legacy = parse_link(f"ss://{b64('chacha20-ietf-poly1305:pw@h.example:8388')}#old")
        self.assertEqual((legacy.method, legacy.password, legacy.host), ("chacha20-ietf-poly1305", "pw", "h.example"))
        plain = parse_link("ss://2022-blake3-aes-128-gcm:a2V5a2V5a2V5a2V5a2V5a2V5@h.example:8388")
        self.assertEqual(plain.method, "2022-blake3-aes-128-gcm")
        for bad in (f"ss://{b64('rc4-md5:pw')}@h.example:1", f"ss://{b64('aes-256-gcm:pw')}@h.example:1?plugin=obfs",
                    "ss://!!!@h.example:1"):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                parse_link(bad)

    def test_vmess(self):
        def link(**kw):
            data = {"v": "2", "ps": "VM", "add": "h.example", "port": "443", "id": UUID, "aid": "0",
                    "net": "ws", "path": "/w", "host": "c.com", "tls": "tls", "sni": "c.com"}
            data.update(kw)
            return "vmess://" + base64.b64encode(json.dumps(data).encode()).decode()
        v = parse_link(link())
        self.assertEqual((v.protocol, v.uuid, v.network, v.security, v.path, v.host_header, v.method, v.name),
                         ("vmess", UUID, "ws", "tls", "/w", "c.com", "auto", "VM"))
        g = parse_link(link(net="grpc", path="svc", tls=""))
        self.assertEqual((g.network, g.service_name, g.security), ("grpc", "svc", "none"))
        self.assertEqual(parse_link(link(port=8443)).port, 8443)           # number instead of string
        for bad in (link(aid="64"), link(id="nope"), link(net="kcp"), link(port=""), "vmess://not-base64!"):
            with self.subTest(bad=bad[:30]), self.assertRaises(ValueError):
                parse_link(bad)

    def test_dispatch(self):
        self.assertTrue(is_supported("VLESS://x") and is_supported("ss://x") and is_supported("vmess://x"))
        self.assertFalse(is_supported("hysteria2://x") or is_supported("nonsense"))
        with self.assertRaises(ValueError):
            parse_link("hysteria2://pw@h:1")
        info = parse_link("trojan://topsecret@h.example:443").public_info()
        self.assertNotIn("topsecret", str(info))
        self.assertEqual(info["protocol"], "trojan")

    def test_public_info_has_no_secrets(self):
        info = parse_vless(REALITY).public_info()
        self.assertNotIn(UUID, str(info))
        self.assertNotIn("PUBKEY123", str(info))


if __name__ == "__main__":
    unittest.main()
