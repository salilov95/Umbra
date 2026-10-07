"""Parsing of share links: vless://, trojan://, ss://, vmess://.

Every scheme is turned into the same ProxyLink dataclass; building the Xray
config from it is the job of xrayconf.py. Anything we do not understand is
rejected with a clear error instead of being silently ignored - a wrong guess
here would give a config that "connects" but does not do what the user expects.
"""
from __future__ import annotations

import base64
import binascii
import json
import uuid as _uuid
from dataclasses import dataclass, field
from urllib.parse import parse_qs, unquote, urlsplit

SCHEMES = ("vless", "trojan", "ss", "vmess")
SUPPORTED_NETWORKS = ("tcp", "ws", "grpc", "xhttp", "httpupgrade")
# Names that some panels / clients use for the same transport.
NETWORK_ALIASES = {"raw": "tcp", "splithttp": "xhttp"}
SUPPORTED_SECURITY = ("none", "tls", "reality")
SS_METHODS = (
    "aes-128-gcm", "aes-256-gcm", "chacha20-poly1305", "chacha20-ietf-poly1305",
    "xchacha20-poly1305", "xchacha20-ietf-poly1305",
    "2022-blake3-aes-128-gcm", "2022-blake3-aes-256-gcm", "2022-blake3-chacha20-poly1305",
)


@dataclass
class ProxyLink:
    protocol: str            # vless | trojan | shadowsocks | vmess
    host: str
    port: int
    name: str = ""
    uuid: str = ""           # vless / vmess user id
    password: str = ""       # trojan / shadowsocks
    method: str = ""         # shadowsocks cipher, vmess "scy"
    encryption: str = "none"
    flow: str = ""
    network: str = "tcp"
    security: str = "none"
    sni: str = ""
    fp: str = ""
    alpn: list[str] = field(default_factory=list)
    pbk: str = ""      # reality public key
    sid: str = ""      # reality short id
    spx: str = ""      # reality spider X
    path: str = ""
    host_header: str = ""
    service_name: str = ""
    mode: str = ""
    extra: dict = field(default_factory=dict)   # xhttp 'extra' options (xmux, padding, ...)

    def public_info(self) -> dict:
        """Fields that are safe to show in the UI (no ids, no keys, no passwords)."""
        return {
            "protocol": self.protocol,
            "host": self.host,
            "port": self.port,
            "security": self.security,
            "network": self.network,
            "flow": self.flow,
        }


VlessLink = ProxyLink   # old name, kept for callers and tests


def _first(query: dict[str, list[str]], key: str, default: str = "") -> str:
    values = query.get(key)
    return values[0].strip() if values else default


def _b64(text: str) -> str:
    """Decode standard or url-safe base64 with or without padding."""
    compact = "".join(text.split()).replace("-", "+").replace("_", "/")
    try:
        return base64.b64decode(compact + "=" * (-len(compact) % 4), validate=True).decode("utf-8")
    except (binascii.Error, ValueError, UnicodeDecodeError) as exc:
        raise ValueError("не получилось раскодировать base64 в ссылке") from exc


def _network(value: str) -> str:
    network = (value or "tcp").lower()
    network = NETWORK_ALIASES.get(network, network)
    if network not in SUPPORTED_NETWORKS:
        raise ValueError(f"транспорт type={network} пока не поддерживается")
    return network


def _endpoint(parts) -> tuple[str, int]:
    try:
        host = parts.hostname or ""
        port = parts.port
    except ValueError as exc:  # bad port / bad IPv6 brackets
        raise ValueError(f"некорректный адрес в ссылке ({exc})") from exc
    if not host:
        raise ValueError("в ссылке нет адреса сервера")
    if port is None or not (1 <= port <= 65535):
        raise ValueError("в ссылке нет корректного порта")
    return host, port


def _stream_from_query(link: ProxyLink, q: dict[str, list[str]], default_security: str = "none") -> None:
    """Transport + TLS parameters shared by vless:// and trojan://."""
    link.network = _network(_first(q, "type", "tcp"))
    security = _first(q, "security", default_security).lower() or default_security
    if security not in SUPPORTED_SECURITY:
        raise ValueError(f"security={security} не поддерживается")
    link.security = security
    link.sni = _first(q, "sni") or _first(q, "peer")
    link.fp = _first(q, "fp")
    link.alpn = [a for a in _first(q, "alpn").split(",") if a]
    link.pbk = _first(q, "pbk")
    link.sid = _first(q, "sid")
    link.spx = _first(q, "spx")
    link.path = _first(q, "path")
    link.host_header = _first(q, "host")
    link.service_name = _first(q, "serviceName")
    link.mode = _first(q, "mode")

    extra_raw = _first(q, "extra")
    if extra_raw:
        try:
            extra = json.loads(extra_raw)
        except ValueError as exc:
            raise ValueError("параметр extra= не является JSON") from exc
        if not isinstance(extra, dict):
            raise ValueError("параметр extra= должен быть JSON-объектом")
        link.extra = extra

    if security == "reality" and not link.pbk:
        raise ValueError("security=reality, но нет pbk (public key)")


def parse_vless(link: str) -> ProxyLink:
    link = link.strip()
    if not link.lower().startswith("vless://"):
        raise ValueError("это не vless:// ссылка")
    try:
        parts = urlsplit(link)
    except ValueError as exc:
        raise ValueError(f"некорректный адрес в ссылке ({exc})") from exc
    user = unquote(parts.username or "")
    if not user:
        raise ValueError("в ссылке нет UUID (часть до @)")
    host, port = _endpoint(parts)
    try:
        user = str(_uuid.UUID(user))
    except ValueError:
        # Xray also accepts arbitrary id strings; keep them, but sanity-check.
        if len(user) > 64 or any(c.isspace() for c in user):
            raise ValueError("некорректный UUID") from None

    q = parse_qs(parts.query, keep_blank_values=True)
    result = ProxyLink(
        protocol="vless", host=host, port=port, uuid=user,
        name=unquote(parts.fragment).strip() or f"{host}:{port}",
        encryption=_first(q, "encryption", "none") or "none",
        flow=_first(q, "flow"),
    )
    _stream_from_query(result, q)
    return result


def parse_trojan(link: str) -> ProxyLink:
    try:
        parts = urlsplit(link.strip())
    except ValueError as exc:
        raise ValueError(f"некорректный адрес в ссылке ({exc})") from exc
    password = unquote(parts.username or "")
    if not password:
        raise ValueError("в ссылке нет пароля (часть до @)")
    host, port = _endpoint(parts)
    q = parse_qs(parts.query, keep_blank_values=True)
    result = ProxyLink(
        protocol="trojan", host=host, port=port, password=password,
        name=unquote(parts.fragment).strip() or f"{host}:{port}",
        flow=_first(q, "flow"),
    )
    _stream_from_query(result, q, default_security="tls")   # trojan means TLS unless said otherwise
    return result


def parse_ss(link: str) -> ProxyLink:
    """SIP002 (ss://base64(method:password)@host:port) and the legacy all-base64 form."""
    body = link.strip()[len("ss://"):]
    body, _, fragment = body.partition("#")
    name = unquote(fragment).strip()
    if "@" not in body:                       # legacy: everything is base64
        body = _b64(body.split("?")[0])
    try:
        parts = urlsplit("ss://" + body)
    except ValueError as exc:
        raise ValueError(f"некорректный адрес в ссылке ({exc})") from exc
    host, port = _endpoint(parts)
    if _first(parse_qs(parts.query), "plugin"):
        raise ValueError("Shadowsocks с plugin= не поддерживается")

    userinfo = unquote(body.rsplit("@", 1)[0])
    if ":" not in userinfo:                   # SIP002: base64(method:password)
        userinfo = _b64(userinfo)
    method, sep, password = userinfo.partition(":")
    method = method.lower()
    if not sep or not password:
        raise ValueError("в ссылке нет метода шифрования или пароля")
    if method not in SS_METHODS:
        raise ValueError(f"шифр {method} не поддерживается")
    return ProxyLink(protocol="shadowsocks", host=host, port=port, method=method,
                     password=password, name=name or f"{host}:{port}")


def parse_vmess(link: str) -> ProxyLink:
    """vmess://base64(json) - the v2rayN share format."""
    try:
        data = json.loads(_b64(link.strip()[len("vmess://"):]))
    except ValueError as exc:
        raise ValueError("vmess:// ссылка должна содержать base64 с JSON внутри") from exc
    if not isinstance(data, dict):
        raise ValueError("vmess:// ссылка должна содержать JSON-объект")

    def get(key: str) -> str:
        return str(data.get(key) or "").strip()

    host = get("add")
    try:
        port = int(get("port"))
    except ValueError:
        port = 0
    if not host:
        raise ValueError("в ссылке нет адреса сервера")
    if not (1 <= port <= 65535):
        raise ValueError("в ссылке нет корректного порта")
    try:
        user = str(_uuid.UUID(get("id")))
    except ValueError:
        raise ValueError("некорректный UUID") from None
    if get("aid") not in ("", "0"):
        raise ValueError("VMess с alterId больше 0 устарел и не поддерживается ядром")

    tls = get("tls").lower()
    if tls not in ("", "none", "tls"):
        raise ValueError(f"tls={tls} не поддерживается")
    network = _network(get("net"))
    return ProxyLink(
        protocol="vmess", host=host, port=port, uuid=user,
        name=get("ps") or f"{host}:{port}",
        method=get("scy") or "auto",
        network=network,
        security="tls" if tls == "tls" else "none",
        sni=get("sni"), fp=get("fp"),
        alpn=[a for a in get("alpn").split(",") if a],
        host_header=get("host"),
        path="" if network == "grpc" else get("path"),
        service_name=get("path") if network == "grpc" else "",
        mode=get("type") if network == "grpc" else "",
    )


_PARSERS = {"vless": parse_vless, "trojan": parse_trojan, "ss": parse_ss, "vmess": parse_vmess}


def is_supported(link: str) -> bool:
    return link.strip().lower().split("://", 1)[0] in _PARSERS and "://" in link


def parse_link(link: str) -> ProxyLink:
    """Parse any supported share link. Raises ValueError with a human-readable text."""
    scheme = link.strip().lower().split("://", 1)[0]
    parser = _PARSERS.get(scheme)
    if parser is None or "://" not in link:
        raise ValueError("ссылка должна начинаться с vless://, trojan://, ss:// или vmess://")
    return parser(link)
